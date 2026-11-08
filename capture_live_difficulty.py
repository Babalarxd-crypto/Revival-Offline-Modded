"""Passive lobby-socket observation in an already-running normal game."""
import json
import threading
import time
from datetime import datetime
from pathlib import Path

import frida

HERE = Path(__file__).resolve().parent
JS = r'''
const ws = Process.getModuleByName('ws2_32.dll');
const peer = new NativeFunction(ws.getExportByName('getpeername'), 'int',
                                ['pointer', 'pointer', 'pointer']);
function target(sock) {
    try {
        const addr = Memory.alloc(128), size = Memory.alloc(4);
        size.writeS32(128);
        if (peer(sock, addr, size) !== 0 || addr.readU16() !== 2) return null;
        const port = (addr.add(2).readU8() << 8) | addr.add(3).readU8();
        const ip = [4,5,6,7].map(i => addr.add(i).readU8()).join('.');
        if (port !== 8001 || ip.startsWith('127.') || ip === '0.0.0.0') return null;
        return {port, ip, socket: sock.toString()};
    } catch(e) { return null; }
}
function dump(t, direction, data, count, api) {
    if (!t || count <= 0) return;
    if (count > 1048576) {
        send({kind:'gap', api, reason:'buffer exceeds 1MiB'}); return;
    }
    try {
        const bytes = new Uint8Array(data.readByteArray(count));
        const hex = Array.from(bytes, b => b.toString(16).padStart(2,'0')).join('');
        send({kind:'data', ...t, direction, size:count, hex, api});
    } catch(e) { send({kind:'gap', api, reason:String(e)}); }
}
for (const [api, direction] of [['send','C>S'], ['recv','S>C']]) {
    Interceptor.attach(ws.getExportByName(api), {
        onEnter(a) { this.t=target(a[0]); this.buf=a[1]; },
        onLeave(ret) { dump(this.t, direction, this.buf, ret.toInt32(), api); }
    });
}
for (const [api, direction] of [['WSASend','C>S'], ['WSARecv','S>C']]) {
    Interceptor.attach(ws.getExportByName(api), {
        onEnter(a) {
            this.t=target(a[0]); this.buffers=[];
            this.count=a[2].toUInt32(); this.got=a[3]; this.overlapped=a[5];
            if (!this.t) return;
            if (this.count > 64) {
                send({kind:'gap', api, reason:'more than 64 WSABUFs'}); return;
            }
            const stride=Process.pointerSize===8 ? 16 : 8;
            const ptrOffset=Process.pointerSize===8 ? 8 : 4;
            for(let i=0;i<this.count;i++) {
                const p=a[1].add(i*stride);
                this.buffers.push({size:p.readU32(), ptr:p.add(ptrOffset).readPointer()});
            }
        },
        onLeave(ret) {
            if (!this.t) return;
            if (ret.toInt32() !== 0 || this.got.isNull()) {
                send({kind:'gap', api, reason:'failed or asynchronous operation; completion not observed'});
                return;
            }
            let remaining=this.got.readU32();
            for(const b of this.buffers) {
                const n=Math.min(remaining,b.size);
                dump(this.t,direction,b.ptr,n,api); remaining-=n;
            }
        }
    });
}
send({kind:'ready', path:Process.mainModule.path,
      coverage:'IPv4 remote TCP8001 send/recv and synchronous WSA only; async completions not captured'});
'''


def level_marker(value):
    level = int(value)
    if level not in range(1, 11):
        raise ValueError('Zorluk 1..10 olmali')
    return level


def recording_panel(write):
    import tkinter as tk
    from tkinter import ttk
    root = tk.Tk()
    root.title('Revival - Zorluk kaydi')
    root.geometry('700x270')
    root.minsize(640, 250)
    body = ttk.Frame(root, padding=16)
    body.pack(fill='both', expand=True)
    ttk.Label(body, text='Once buradan seviyeye bas, SONRA oyunda ayni seviyeyi sec.').pack(anchor='w')
    ttk.Label(body, text='Bu dugmeler oyunun zorlugunu degistirmez; loga isaret koyar.').pack(anchor='w')
    levels = ttk.Frame(body)
    levels.pack(fill='x', pady=14)
    status = tk.StringVar(value='Kayit acik. Henuz seviye isareti konmadi.')

    def mark(n):
        write(f'MARK difficulty={level_marker(str(n))}')
        status.set(f'Seviye {n} kaydedildi. Simdi oyunda {n} sec. Tekrar basabilirsin.')

    for n in range(1, 11):
        ttk.Button(levels, text=str(n), width=4, command=lambda n=n: mark(n)).pack(side='left', padx=3)
    ttk.Label(body, text='Rakip adi / not:').pack(anchor='w')
    row = ttk.Frame(body)
    row.pack(fill='x', pady=5)
    note = ttk.Entry(row)
    note.pack(side='left', fill='x', expand=True)

    def save_note():
        text = note.get().strip()
        if not text:
            status.set('Once rakip adi veya not yaz.'); return
        write('NOTE ' + text)
        status.set('Not kaydedildi: ' + text)
        note.delete(0, 'end')

    ttk.Button(row, text='NOTU KAYDET', command=save_note).pack(side='right', padx=5)
    ttk.Label(body, textvariable=status, wraplength=650).pack(anchor='w', pady=8)
    ttk.Button(body, text='KAYDI BITIR (oyun acik kalir)', command=root.destroy).pack(anchor='e')
    return root


def main():
    print('NORMAL OYUN ZORLUK KAYDI - OFFLINE LAUNCHER DEGIL')
    print('Normal oyunu kendin ac, giris yap ve antrenman ekranina gel.')
    print('Bu arac oyun acmaz/kapatmaz, paketleri veya hesabi degistirmez.')
    print('Sadece uzak TCP8001 oda trafigi kaydedilir. Loglari herkese acik paylasma.')
    input('Hazir olunca Enter (offline oturumlar kapali olmali): ')
    device = frida.get_local_device()
    games = [p for p in device.enumerate_processes() if p.name.lower() == 'binarytru.exe']
    if len(games) != 1:
        raise RuntimeError('Tam olarak bir normal oyun acik olmali')
    folder = HERE / 'Zorluk-Loglari' / datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    folder.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    lock = threading.Lock()
    session = device.attach(games[0].pid)
    try:
        with (folder / 'capture.log').open('x', encoding='utf-8') as out:
            def write(text):
                with lock:
                    out.write(f'{time.monotonic()-started:.6f} {text}\n')
                    out.flush()

            def message(msg, data):
                if msg['type'] != 'send':
                    write('HOOK_ERROR ' + json.dumps(msg)); return
                payload = msg['payload']
                if payload.get('kind') == 'data':
                    write(f"[8001 {payload['direction']}] {payload['size']}B {payload['hex']}")
                    write('SOCKET ' + json.dumps({k:v for k,v in payload.items() if k != 'hex'}))
                else:
                    write('EVENT ' + json.dumps(payload))
                    if payload.get('kind') in ('ready', 'gap'):
                        print(payload, flush=True)

            script = session.create_script(JS)
            script.on('message', message)
            script.load()
            print('Kayit klasoru:', folder)
            print('Acilan pencerede 1..10 dugmelerini kullan; CMDye sayi yazma.')
            print('Seviyeye bastiktan SONRA oyunda ayni seviyeyi sec. Tekrar isaretleyebilirsin.')
            print('Rakip degismiyorsa baska seviyeye gecip geri don. Sureyi 3 dk sabit tut.')
            print('Satin alma/odul/kadro onayi yapma; bu kayit icin MAC BASLATMA gerekmiyor.')
            print('Bitirmek icin penceredeki KAYDI BITIR dugmesine bas.')
            try:
                recording_panel(write).mainloop()
            except (KeyboardInterrupt, EOFError):
                pass
            finally:
                script.unload()
            write('DONE capture stopped; game untouched')
    finally:
        session.detach()
    print('Kayit bitti. Oyun kapatilmadi. Log:', folder)


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'Kayit durdu: {exc}')
        raise SystemExit(1)
