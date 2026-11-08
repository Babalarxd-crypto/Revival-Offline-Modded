"""Observe normal game's lobby from before login; never redirect or write packets."""
import json
import threading
import time
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk
import frida
from capture_live_difficulty import JS

HERE = Path(__file__).resolve().parent


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--setup-game-root', type=Path)
    args = parser.parse_args()
    setup = args.setup_game_root is not None
    if setup:
        from local_setup import validate_game
        validate_game(args.setup_game_root)
    print('KADRO KAYDI: Offline oyunu kapat. Normal oyunu henuz acma.', flush=True)
    device = frida.get_local_device()
    if any(p.name.lower() == 'binarytru.exe' for p in device.enumerate_processes()):
        raise RuntimeError('Oyun zaten acik. Kapatip kaydi yeniden baslat; kadro giriste gelir.')
    parent_session=None
    gated=[]
    def child_added(child):
        if parent_session is None:
            return
        if child.parent_pid != launcher_pid:
            return
        if Path(child.path or '').name.lower()=='binarytru.exe':
            gated.append(child)
        else:
            device.resume(child.pid)
    if setup:
        launchers=[p for p in device.enumerate_processes() if p.name.lower()=='revival_launcher.exe']
        if len(launchers)!=1:
            raise RuntimeError('Önce NORMAL launcherı açın ama OYNA düğmesine basmayın. Sonra hazırlığı yeniden açın.')
        launcher_pid=launchers[0].pid
        parent_session=device.attach(launcher_pid)
        device.on('child-added',child_added)
        try:
            parent_session.enable_child_gating()
        except Exception:
            device.off('child-added',child_added)
            parent_session.detach()
            raise
        print('Gözlemci hazır. Normal launcherda OYNA düğmesine basın. Oyun gözlemci kurulunca devam edecek.',flush=True)
    else:
        print('Simdi NORMAL launcher ile oyunu ac. Kayit hazir mesaji gelmeden giris yapma.', flush=True)
    deadline = time.monotonic() + 600
    game = None
    while time.monotonic() < deadline:
        games = [p for p in device.enumerate_processes() if p.name.lower() == 'binarytru.exe']
        if len(games) > 1:
            raise RuntimeError('Birden fazla oyun acik')
        if setup and gated:
            game=gated[0];break
        if games and not setup:
            game = games[0]; break
        time.sleep(.15)
    if game is None:
        if parent_session:
            parent_session.disable_child_gating()
            device.off('child-added',child_added)
            parent_session.detach()
        raise RuntimeError('10 dakika icinde oyun acilmadi; oyun baslatilmadi/kapatilmadi.')
    path = HERE / f'capture-roster-{datetime.now():%Y%m%d-%H%M%S-%f}.log'
    raw_path=path
    lock = threading.Lock()
    auth_rows = []
    gaps = []
    auth_socket = [None]
    observed_keys = {}
    relay=None
    key_candidates = set()
    channel_counts = {}
    try:
        session = device.attach(game.pid)
    except Exception:
        if parent_session:
            try:
                for child in gated:
                    device.resume(child.pid)
                parent_session.disable_child_gating()
            finally:
                device.off('child-added',child_added)
                parent_session.detach()
        raise
    try:
        with path.open('x', encoding='utf-8') as out:
            started = time.monotonic()
            def write(text):
                with lock:
                    out.write(f'{time.monotonic()-started:.6f} {text}\n')
                    out.flush()
            def message(msg, data):
                if msg['type'] != 'send':
                    gaps.append(msg)
                    write('HOOK_ERROR ' + json.dumps(msg)); return
                p = msg['payload']
                if p.get('kind')=='relay_route':
                    try:
                        relay.route(p['port'],p['host'])
                    except ValueError as exc:
                        gaps.append(str(exc))
                    return
                if p.get('kind') == 'session_key_candidate':
                    with lock:
                        if len(key_candidates)>=128:
                            gaps.append('Too many key candidates; recording rejected')
                        else:
                            key_candidates.add(p['key'])
                    return
                if p.get('kind') == 'observed_session_key':
                    port=p['port']
                    key=p['key']
                    if port in observed_keys and observed_keys[port]!=key:
                        gaps.append('Session key changed within recording')
                    observed_keys[port]=key
                    write(f'[sessionkey] port={port} key={key} observed=1')
                    return
                if p.get('kind') == 'data':
                    with lock:
                        channel_counts[p['port']]=channel_counts.get(p['port'],0)+1
                    if p['port'] != 8000:
                        write(f"[{p['port']} {p['direction']}] {p['size']}B {p['hex']}")
                    elif setup and p['port'] == 8000:
                        with lock:
                            if auth_socket[0] is None:
                                auth_socket[0] = p['socket']
                            if auth_socket[0] != p['socket']:
                                gaps.append('multiple auth sockets')
                            auth_rows.append(('OUT' if p['direction']=='C>S' else 'IN',
                                              2756, bytes.fromhex(p['hex'])))
                            with path.with_suffix('.auth.log').open('a',encoding='utf-8') as auth:
                                direction='OUT' if p['direction']=='C>S' else 'IN'
                                auth.write(f'{direction} {"send" if direction=="OUT" else "recv"} sock=2756 {p["hex"]}\n')
                else:
                    if p.get('kind') == 'gap' or msg['type'] != 'send':
                        gaps.append(p)
                    write('EVENT ' + json.dumps(p))
                    print(p, flush=True)
            code = JS.replace('port !== 8001',
                '(port !== 8001 && port !== 8000 && port !== 18030 && !(port >= 18020 && port <= 18029))') if setup else JS
            if setup:
                from recording_relay import RecordingRelay,hook_script
                def relay_gap(reason):
                    gaps.append(reason)
                    write('EVENT '+json.dumps({'kind':'gap','reason':reason}))
                def relay_data(port,side,data):
                    message({'type':'send','payload':{'kind':'data','port':port,
                        'socket':str(port),'direction':side,'size':len(data),'hex':data.hex()}},None)
                def extra_auth(stream,side,data):
                    direction='OUT' if side=='C>S' else 'IN'
                    with lock:
                        extra_path=path.with_suffix(f'.auth-{stream}.log')
                        with extra_path.open('a',encoding='utf-8') as auth:
                            auth.write(f'{direction} {"send" if direction=="OUT" else "recv"} sock=2756 {data.hex()}\n')
                relay=RecordingRelay(relay_data,relay_gap,auth_extra=extra_auth)
                relay.start()
                code=hook_script()
                # Replay parsers use canonical unprefixed channel records.
                def write(text):
                    with lock:
                        out.write(text+'\n')
                        out.flush()
                code += '\n'+(HERE/'session_observer.js').read_text(encoding='utf-8')
            script = session.create_script(code)
            script.on('message', message)
            script.load()
            if setup:
                device.resume(game.pid)
                gated.clear()
            try:
                root = tk.Tk()
                root.title('Normal oyundan kadro kaydi')
                body = ttk.Frame(root, padding=20)
                body.pack(fill='both', expand=True)
                ttk.Label(body, text='Kayit acik. Normal oyunda giris yap, kadronun yuklenmesini bekle.\n'
                          'Satin alma, odul veya kadro onayi yapma.\n'
                          'Offline maç kaydı için kendi antrenman maçını başlat, devre arasını da kaydet.\n'
                          'Kaydı bitirmek kayıt bağlantılarını kapatır; normal oyun sunucudan ayrılabilir.\n'
                          'Oyun işlemi kapatılmaz. Maç sürerken kaydı bitirmeyin.', wraplength=550).pack()
                health_timer=[None]
                def close_panel():
                    if health_timer[0] is not None:
                        root.after_cancel(health_timer[0])
                        health_timer[0]=None
                    root.destroy()
                root.protocol('WM_DELETE_WINDOW',close_panel)
                ttk.Button(body, text='KAYDI BITIR VE KONTROL ET', command=close_panel).pack(pady=15)
                if setup:
                    health=ttk.Label(body,wraplength=550)
                    health.pack()
                    def refresh_health():
                        with lock:
                            keys=len(key_candidates)
                            match_packets=sum(n for port,n in channel_counts.items() if 18020<=port<=18029)
                            errors=len(gaps)
                        health.configure(text=f'Anahtar adayı: {keys} | Maç paketi: {match_packets} | Kayıt hatası: {errors}\n'
                            + ('Kayıt hatası var. Daha uzun oynamak düzeltmez; kaydı bitirin.' if errors else
                               'Bu sayaçlar başarı kanıtı değildir; anahtar ve kayıt bitişte doğrulanır.'))
                        health_timer[0]=root.after(500,refresh_health)
                    refresh_health()
                root.mainloop()
            finally:
                if relay:
                    relay.stop()
                script.unload()
    finally:
        if relay:
            relay.stop()
        session.detach()
        if parent_session:
            try:
                for child in gated:
                    device.resume(child.pid)
                parent_session.disable_child_gating()
            finally:
                device.off('child-added',child_added)
                parent_session.detach()
    if setup:
        # Preserve private evidence if later metadata preparation fails; do not print keys.
        path.with_suffix('.keys.json').write_text(json.dumps(sorted(key_candidates)),encoding='utf-8')
        try:
            from prepare_recording import prepare_recording
            path=prepare_recording(path)
            # Only a successful on-disk validation may downgrade recorded warnings.
            if path!=raw_path:
                gaps.clear()
            print('Anahtarlar şifreli mesajlarla doğrulandı.',flush=True)
        except (ValueError,OSError) as exc:
            gaps.append(str(exc))
    from roster_menu import inspect
    try:
        inspect(path)
    except (ValueError, OSError, AssertionError) as exc:
        print(f'Kayit saklandi ama kadro dogrulanamadi: {exc}\n{path}', flush=True)
    else:
        print(f'Kadro kaydi hazir: {path}\nLauncher > Kadro kaydi ac ile sec.', flush=True)
        print('Bu lobi kaydidir; tek basina mac kaydi degildir.', flush=True)
        if setup:
            if gaps:
                raise ValueError('Kayıtta boşluk var; yerel veri oluşturulmadı. '+str(gaps[:1]))
            from local_setup import save_setup, installed_release,auth_recording_rows
            if all((HERE/name).is_file() for name in ('game.log','offline_launch_candidate.json')):
                print('Mevcut yerel giriş dosyaları korundu; yeni kayıt ayrı saklandı.',flush=True)
            else:
                save_setup(HERE, args.setup_game_root, auth_recording_rows(raw_path,auth_rows), installed_release(args.setup_game_root))
            print('Yerel offline giriş verisi hazır. Bu dosyaları başkalarına göndermeyin. '
                  'Bu kayıt lobi içindir; tam maç kaydı değildir.', flush=True)
            try:
                from offline_replay import forced_session_key, channel_plan, match_port, room_phases, match_replay
                if forced_session_key(path) is None:
                    raise ValueError('Oturum anahtarı gözlemlenmedi; maç oynatma hazır değil.')
                channel_plan(path)
                port=match_port(path)
                room_phases(path)
                match_replay(path,port)
            except (ValueError,OSError,AssertionError) as exc:
                print(f'Kayıt korundu, offline maç doğrulaması geçmedi: {exc}',flush=True)
            else:
                print('Oda/maç kayıt yapısı ve oturum anahtarı doğrulandı. '
                      'Gerçek offline oynatım ayrıca denenmelidir.',flush=True)
    input('Kapatmak icin Enter: ')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(f'Kayit durdu: {exc}', flush=True)
        input('Kapatmak icin Enter: ')
        raise SystemExit(1)
