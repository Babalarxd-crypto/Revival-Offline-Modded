// Observe synchronous and IOCP/event-completed WSA buffers without changing them.
const pending = new Map();
const wsaError = new NativeFunction(ws.getExportByName('WSAGetLastError'),'int',[]);
function finishCapture(overlapped,count,success) {
    const key=overlapped.toString(), op=pending.get(key);
    if (!op) return;
    pending.delete(key);
    if (!success) return; // Failed operations transfer no replayable bytes.
    let remaining=count;
    const capacity=op.buffers.reduce((sum,b)=>sum+b.size,0);
    if (count>capacity) { send({kind:'gap',reason:'WSA completion exceeds buffer capacity'}); return; }
    for (const b of op.buffers) {
        const n=Math.min(remaining,b.size);
        if(n) dump(op.t,op.direction,b.ptr,n,op.api);
        remaining-=n;
    }
}
for (const [api,direction] of [['WSASend','C>S'],['WSARecv','S>C']]) {
    Interceptor.attach(ws.getExportByName(api),{
        onEnter(a) {
            this.t=target(a[0]);
            if(!this.t) return;
            this.overlapped=a[5];this.got=a[3];
            const count=a[2].toUInt32();
            if(count>64 || !a[6].isNull()) {
                send({kind:'gap',reason:'WSA completion routine or buffer count unsupported'});
                this.t=null;return;
            }
            const buffers=[],stride=Process.pointerSize===8?16:8,offset=Process.pointerSize===8?8:4;
            for(let i=0;i<count;i++) {
                const b=a[1].add(i*stride);
                buffers.push({size:b.readU32(),ptr:b.add(offset).readPointer()});
            }
            this.op={t:this.t,direction,buffers,api};
            if(!this.overlapped.isNull()) {
                const key=this.overlapped.toString();
                if(pending.has(key)) send({kind:'gap',reason:'Overlapped operation reused before observed completion'});
                pending.set(key,this.op);
            }
        },
        onLeave(ret) {
            if(!this.t) return;
            if(ret.toInt32()!==0) {
                if(wsaError()!==997 && !this.overlapped.isNull()) pending.delete(this.overlapped.toString());
                return;
            }
            if(!this.overlapped.isNull()) {
                // Immediate success may deliberately skip IOCP notification.
                // finishCapture removes pending, so later notifications cannot duplicate it.
                if(!this.got.isNull()) finishCapture(this.overlapped,this.got.readU32(),true);
                return;
            }
            if(this.got.isNull()) { send({kind:'gap',reason:'Missing synchronous byte count'});return; }
            const key='sync:'+Process.getCurrentThreadId();
            pending.set(key,this.op);
            finishCapture({toString:()=>key},this.got.readU32(),true);
        }
    });
}
const kernel=Process.getModuleByName('kernel32.dll');
Interceptor.attach(kernel.getExportByName('GetQueuedCompletionStatus'),{
    onEnter(a){this.bytes=a[1];this.overlapped=a[3];},
    onLeave(ret){
        const ov=this.overlapped.readPointer();
        if(!ov.isNull()) finishCapture(ov,this.bytes.readU32(),!ret.isNull());
    }
});
Interceptor.attach(kernel.getExportByName('GetQueuedCompletionStatusEx'),{
    onEnter(a){this.entries=a[1];this.count=a[3];},
    onLeave(ret){
        if(ret.isNull()) return;
        const count=this.count.readU32(),stride=Process.pointerSize===8?32:16;
        for(let i=0;i<count;i++) {
            const entry=this.entries.add(i*stride);
            finishCapture(entry.add(Process.pointerSize).readPointer(),
                entry.add(Process.pointerSize*3).readU32(),entry.add(Process.pointerSize*2).readPointer().isNull());
        }
    }
});
for(const [module,api] of [[ws,'WSAGetOverlappedResult'],[kernel,'GetOverlappedResult']]) {
    Interceptor.attach(module.getExportByName(api),{
        onEnter(a){this.overlapped=a[1];this.bytes=a[2];},
        onLeave(ret){if(!ret.isNull()) finishCapture(this.overlapped,this.bytes.readU32(),true);}
    });
}
send({kind:'async_observer_ready',coverage:'sync, IOCP, IOCPEx, overlapped-result; callback completion unsupported'});
