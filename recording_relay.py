"""Byte-preserving, process-directed TCP recording; no packet or key mutation."""
import socket
import threading
import ipaddress

PORTS=(8000,8001,18030,*range(18020,18030))


def pump(source,target,emit):
    try:
        while True:
            data=source.recv(65536)
            if not data:
                break
            # Log before forwarding so connection shutdown cannot hide delivered bytes.
            emit(data)
            target.sendall(data)
    finally:
        try:
            target.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class RecordingRelay:
    def __init__(self,emit,gap,auth_extra=None):
        self.emit,self.gap=emit,gap
        self.auth_extra=auth_extra
        self.routes={}
        self.ready={port:threading.Event() for port in PORTS}
        self.listeners=[]
        self.connections=[]
        self.writers={}
        self.conflicts=set()
        self.lock=threading.Lock()
        self.stopped=False

    def route(self,port,host):
        if port not in PORTS:
            raise ValueError('Unexpected game port')
        ipaddress.IPv4Address(host)
        with self.lock:
            if port in self.routes and self.routes[port]!=host:
                raise ValueError('Destination changed during recording')
            self.routes[port]=host
            self.ready[port].set()

    def start(self):
        try:
            for port in PORTS:
                listener=socket.socket()
                listener.bind(('127.0.0.1',port))
                listener.listen(2)
                listener.settimeout(.5)
                self.listeners.append(listener)
            for listener,port in zip(self.listeners,PORTS):
                threading.Thread(target=self.accept,args=(listener,port),daemon=True).start()
        except Exception:
            self.stop()
            raise

    def accept(self,listener,port):
        while not self.stopped:
            try:
                connection,_=listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                self.connections.append(connection)
            threading.Thread(target=self.handle,args=(connection,port),daemon=True).start()

    def handle(self,connection,port):
        try:
            if not self.ready[port].wait(10):
                raise ValueError('Original destination was not observed')
            upstream=socket.create_connection((self.routes[port],port),timeout=10)
            upstream.settimeout(None)
            with self.lock:
                self.connections.append(upstream)
            def transfer(source,target,side):
                def capture(data):
                    self.capture(connection,port,side,data)
                try:
                    pump(source,target,capture)
                except (OSError,ValueError) as exc:
                    if not self.stopped:
                        self.gap('TCP recording interrupted: '+str(exc))
            sender=threading.Thread(target=transfer,args=(connection,upstream,'C>S'),daemon=True)
            sender.start()
            transfer(upstream,connection,'S>C')
            sender.join()
        except (OSError,ValueError) as exc:
            if not self.stopped:
                self.gap(str(exc))
        finally:
            connection.close()

    def capture(self,connection,port,side,data):
        with self.lock:
            owner=self.writers.setdefault(port,connection)
            conflict=owner is not connection
            report=conflict and port not in self.conflicts
            if report:
                self.conflicts.add(port)
        if conflict and port==8000 and self.auth_extra is not None:
            self.auth_extra(id(connection),side,data)
            return
        if report:
            self.gap(f'{port}: multiple data-bearing connections; capture cannot be merged')
        if not conflict:
            self.emit(port,side,data)

    def stop(self):
        self.stopped=True
        for sock in self.listeners+self.connections:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()


def hook_script():
    return r'''
const ws=Process.getModuleByName('ws2_32.dll');
for(const api of ['connect','WSAConnect']) {
    Interceptor.attach(ws.getExportByName(api),{
        onEnter(args) {
            const addr=args[1];
            if(args[2].toInt32()<16 || addr.readU16()!==2) return;
            const port=(addr.add(2).readU8()<<8)|addr.add(3).readU8();
            if(port!==8000 && port!==8001 && port!==18030 && !(port>=18020 && port<=18029)) return;
            const bytes=[4,5,6,7].map(i=>addr.add(i).readU8());
            if(bytes[0]===127) return;
            send({kind:'relay_route',port,host:bytes.join('.')});
            // Replace only this call's sockaddr; caller-owned memory stays intact.
            this.address=Memory.alloc(16);
            this.address.writeByteArray(new Uint8Array(addr.readByteArray(16)));
            [127,0,0,1].forEach((value,i)=>this.address.add(4+i).writeU8(value));
            args[1]=this.address;
        }
    });
}
send({kind:'relay_observer_ready',coverage:'byte-preserving TCP relay; no async-buffer reads'});
'''
