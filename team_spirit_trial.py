"""Experimental level-five team-set calculation in an owned localhost replay only."""
import hashlib
import sys
import json
from pathlib import Path

EXE_SHA256 = '199c410ad9ced1f7ec8838e7f243366f96f63cde576f392c7de2965e9c3fad1f'
FUNCTION_RVA = 0x748fc0
PROLOGUE = bytes.fromhex('558bec83ec18538b5d0c5633f63bde')

JS = r'''
if (!__REDIRECT_ALL__) throw new Error('Team spirit requires redirect-all');
const spiritModule = Process.mainModule;
const spiritFunction = spiritModule.base.add(0x748fc0);
const spiritOwner = __OWN_NAME__;
const spiritXI = __OWN_XI__;
const spiritExpected = [0x55,0x8b,0xec,0x83,0xec,0x18,0x53,0x8b,0x5d,0x0c,0x56,0x33,0xf6,0x3b,0xde];
for (let i=0; i<spiritExpected.length; i++)
    if (spiritFunction.add(i).readU8() !== spiritExpected[i])
        throw new Error('Team spirit signature mismatch; no hook installed');
let spiritReports = 0;
Interceptor.attach(spiritFunction, {
    onEnter(args) {
        this.output = this.context.edi;
        // Match actual roster identities, not one UI call site (other panels use others).
        this.apply = false;
        try {
            const bytes=new Uint8Array(args[1].add(0xed).readByteArray(88));
            const xi=Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
            this.apply = xi===spiritXI && args[3].toInt32()>=0 && args[3].toInt32()<=5;
        } catch(error) {}
        if (this.apply) args[3] = ptr(5);
    },
    onLeave() {
        if (this.apply) {
            this.output.add(0x1c).writeS32(11);
            this.output.add(0x20).writeS32(11);
        }
        if (this.apply && spiritReports++ < 20) {
            try {
                send({event:'offline_team_spirit_result', experimental:true,
                    level:this.output.add(0x18).readS32(),
                    current:this.output.add(0x1c).readS32()+this.output.add(0x20).readS32(),
                    bonuses:[0,4,8,12,16,20].map(n=>this.output.add(n).readS32())});
            } catch (error) { send({event:'offline_team_spirit_read_error'}); }
        }
    }
});
// The match map is also consumed by the match-stat setup, not just Flash.
const matchFind = spiritModule.base.add(0x5fc80);
const matchExpected = [0x55,0x8b,0xec,0x51,0x53,0x8b,0x5d,0x08,0x56,0x8b,0xf1];
for (let i=0;i<matchExpected.length;i++)
    if (matchFind.add(i).readU8()!==matchExpected[i]) throw new Error('Match map signature mismatch');
let matchReports=0;
Interceptor.attach(matchFind, {
    onEnter(args) {
        this.matchMap=false;
        try {
            const global=spiritModule.base.add(0xebaa04).readPointer();
            const map=global.add(0x2c).readPointer().add(0x35c0);
            if (!this.context.ecx.equals(map)) return;
            this.head=map.add(4).readPointer();
            this.iterator=this.context.eax;
            this.matchMap=true;
        } catch(error) {}
    },
    onLeave() {
        if (!this.matchMap) return;
        try {
            const node=this.iterator.readPointer();
            if (node.equals(this.head)) return;
            const team=node.add(0x10);
            const owner=team.add(4).readUtf16String(40).split('\x00')[0];
            if (owner!==spiritOwner) return;
            const field=team.add(0x32f), before=field.readU8();
            if (before>5) throw new Error('Match level outside expected range');
            field.writeU8(5);
            if (matchReports++<12) send({event:'offline_match_team_spirit',
                before,level:field.readU8(),own_team:true,experimental:true});
        } catch(error) { send({event:'offline_match_team_spirit_error',reason:String(error)}); }
    }
});
send({event:'offline_team_spirit_ready', level:5, experimental:true});
'''


def validate(path, args):
    if '--local-candidate' not in args or '--redirect-all' not in args:
        raise ValueError('Takım ruhu testi yalnızca local-candidate + redirect-all ile çalışır.')
    if hashlib.sha256(Path(path).read_bytes()).hexdigest() != EXE_SHA256:
        raise ValueError('Takım ruhu testi bu EXE sürümünü desteklemiyor; dosya değiştirilmedi.')


def main():
    import run_halftime_diagnostic as runner
    validate(runner.GAME, sys.argv[1:])
    if '--capture' not in sys.argv:
        raise ValueError('Takım ruhu testi için açık bir --capture dosyası gerekli.')
    capture=Path(sys.argv[sys.argv.index('--capture')+1])
    owner=capture_owner(capture) if '--lobby-card' not in sys.argv else ''
    from roster_menu import inspect
    _,_,ids=inspect(capture)
    xi=b''.join(ids).hex()
    runner.JS += '\n' + JS.replace('__OWN_NAME__',json.dumps(owner)).replace('__OWN_XI__',json.dumps(xi))
    return runner.main()


def capture_owner(capture):
    from inspect_shop_capture import capture_replies, decode_reply
    names=[]
    for frame in capture_replies(capture):
        plain=decode_reply(frame)
        if len(plain)==3911:
            name=plain[16:96].decode('utf-16-le').split('\0')[0]
            if not name or not all(ch.isprintable() for ch in name):
                raise ValueError('Kayıtta oyuncu kimliği okunamadı; maç alanı değiştirilmedi.')
            names.append(name)
    if len(names)!=1:
        raise ValueError('Tek bir desteklenen oda kaydı gerekli.')
    return names[0]


if __name__ == '__main__':
    raise SystemExit(main())
