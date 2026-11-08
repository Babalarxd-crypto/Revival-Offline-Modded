// Read-only observation: no key writes and no redirects in the normal game.
const keyGame = Process.getModuleByName('BinaryTrU.exe');
const keySite = keyGame.base.add(0x4e4531);
const keySignature = [0x8d,0x8d,0x68,0xff,0xff,0xff,0x8d,0x83,0x34,0x10,0,0];
let keyValid = true;
for (let i=0;i<keySignature.length;i++)
    if (keySite.add(i).readU8()!==keySignature[i]) keyValid=false;
if (!keyValid) send({kind:'gap',reason:'Session observer signature mismatch'});
else {
    Interceptor.attach(keySite, {
        onEnter() {
            try {
                const bytes=new Uint8Array(this.context.ebp.sub(0x98).readByteArray(16));
                send({kind:'session_key_candidate',
                    key:Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('')});
            } catch(error) { send({kind:'gap',reason:'Session key observation failed'}); }
        }
    });
    send({kind:'session_observer_ready',read_only:true});
}
const aesSite=keyGame.base.add(0x169190);
if(aesSite.readU8()===0x83 && aesSite.add(1).readU8()===0xec && aesSite.add(2).readU8()===0x34) {
    Interceptor.attach(aesSite,{
        onEnter(args){
            if(args[2].toUInt32()!==16) return;
            const bytes=new Uint8Array(args[1].readByteArray(16));
            send({kind:'session_key_candidate',key:Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('')});
        }
    });
} else send({kind:'gap',reason:'AES observer signature mismatch'});
