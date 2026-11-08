"""Interactive, bounded offline attempt. Never changes network settings."""
import json
import argparse
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

import frida

HERE = Path(__file__).resolve().parent
INSTALL = Path(os.environ.get('REVIVAL_GAME_ROOT', str(HERE)))
GAME = INSTALL / "Game" / "BinaryTr" / "BinaryTrU.exe"
FIREWALL_RULE = "RevivalOfflineTestBlock"


def wait_for_game(device, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        games = [p for p in device.enumerate_processes() if p.name.lower() == "binarytru.exe"]
        if games:
            if len(games) != 1:
                raise RuntimeError("Multiple game processes found; refusing to select one")
            return games[0].pid
        time.sleep(0.01)
    raise RuntimeError("Launcher did not start the game within 30 seconds")

JS = r"""
const FORCE_KEY = __SESSION_KEY__;
const REDIRECT_ALL = __REDIRECT_ALL__;
const KEY_BYTES = FORCE_KEY ? FORCE_KEY.match(/../g).map(h => parseInt(h, 16)) : null;
function ipOf(sa) {
    try {
        if (sa.readU16() === 2) {
            const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
            const ip = [4,5,6,7].map(o => sa.add(o).readU8()).join('.');
            return [ip, port];
        }
    } catch (_) {}
    return ['?', 0];
}
function socketPort(sock) {
    try {
        const module = Process.getModuleByName('ws2_32.dll');
        const getpeername = new NativeFunction(module.getExportByName('getpeername'),
                                              'int', ['pointer', 'pointer', 'pointer']);
        const sa = Memory.alloc(16), len = Memory.alloc(4);
        len.writeS32(16);
        if (getpeername(sock, sa, len) === 0) return ipOf(sa);
    } catch (_) {}
    return ['?', 0];
}
function ptrHex(ptr, len) {
    try {
        const bytes = new Uint8Array(ptr.readByteArray(len));
        let text = '';
        for (let i = 0; i < bytes.length; i++) text += ('0' + bytes[i].toString(16)).slice(-2);
        return text;
    } catch (_) { return ''; }
}
let keyHooked = false;
function installKeyHook() {
    if (keyHooked) return;
    let module;
    try { module = Process.getModuleByName('BinaryTrU.exe'); } catch (_) { return; }
    const target = module.base.add(0x4e4531);
    try {
        const sig = new Uint8Array(target.readByteArray(12));
        if (sig[0] !== 0x8d || sig[1] !== 0x8d || sig[2] !== 0x68
            || sig[3] !== 0xff || sig[4] !== 0xff || sig[5] !== 0xff) {
            send({event:'sessionkey_signature_mismatch', target: String(target)});
            keyHooked = true;
            return;
        }
    } catch (_) { return; }
    Interceptor.attach(target, {
        onEnter() {
            try {
                const keyPtr = this.context.ebp.sub(0x98);
                const oldKey = ptrHex(keyPtr, 16);
                if (KEY_BYTES) keyPtr.writeByteArray(KEY_BYTES);
                let ip = '?', port = 0;
                try {
                    const sock = this.context.ebx.readPointer();
                    const pair = socketPort(sock);
                    ip = pair[0]; port = pair[1];
                } catch (_) {}
                send({event:'sessionkey', port:port, ip:ip,
                      old:oldKey, forced:FORCE_KEY});
            } catch (e) { send({event:'sessionkey_error', error:String(e)}); }
        }
    });
    keyHooked = true;
    send({event:'sessionkey_hook_ready', forced:FORCE_KEY});
}
let installed = false;
function install() {
    if (installed) return;
    let module;
    try { module = Process.getModuleByName('ws2_32.dll'); } catch (_) { return; }
    installed = true;
    for (const name of ['connect', 'WSAConnect']) {
        Interceptor.attach(module.getExportByName(name), {
            onEnter(args) {
                const sa = args[1];
                if (sa.readU16() !== 2) { send({event:'other_address_family'}); return; }
                const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                const ip = [4,5,6,7].map(i => sa.add(i).readU8()).join('.');
                if (port === 8000 || port === 8001 || (port >= 18020 && port <= 18030)) {
                    sa.add(4).writeByteArray([127,0,0,1]);
                    send({event:'redirect', port:port});
                } else if (REDIRECT_ALL) {
                    sa.add(4).writeByteArray([127,0,0,1]);
                    send({event:'redirect_other', port:port, ip:ip});
                } else {
                    send({event:'non_replayed_destination', port:port, ip:ip});
                }
            }
        });
    }
    send({event:'hooks_ready'});
}
Process.attachModuleObserver({onAdded(m) {
    if (m.name.toLowerCase() === 'ws2_32.dll') install();
}});
install();

const CHEAT = __CHEAT_CONSOLE__;
if (CHEAT) {
    let gateHits = 0;
    function patchCheatGate() {
        try {
            const module = Process.getModuleByName('BinaryTrU.exe');
            const mgr = module.base.add(0xebaa04).readPointer();
            if (mgr.isNull()) return;
            const paneMgr = mgr.add(0x60).readPointer();
            if (paneMgr.isNull()) return;
            const gate = paneMgr.add(0x1ff);
            const old = gate.readU8();
            if (old !== 1) {
                gate.writeU8(1);
                if (gateHits < 5) {
                    gateHits++;
                    send({event:'cheat_gate', addr:gate.toString(), old:old});
                }
            }
        } catch (e) {
            if (gateHits < 5) {
                gateHits++;
                send({event:'cheat_gate_error', error:String(e)});
            }
        }
    }
    setInterval(patchCheatGate, 250);
    try {
        const module = Process.getModuleByName('BinaryTrU.exe');
        for (const [name, off] of [['load', 0x974c80], ['setvisible', 0x9750e0]]) {
            try {
                Interceptor.attach(module.base.add(off), {
                    onEnter(args) {
                        send({event:'cheat_' + name,
                              self:this.context.ecx.toString(),
                              arg0:args.length ? args[0].toInt32() : 0});
                    }
                });
            } catch (e) {
                send({event:'cheat_hook_error', name:name, error:String(e)});
            }
        }
    } catch (e) {
        send({event:'cheat_module_error', error:String(e)});
    }
}
"""


def require_disconnected():
    # Ignore stale routes on disconnected interfaces, but include connected VPNs.
    command = (
        "$ErrorActionPreference='Stop'; "
        "$a=@(Get-NetIPInterface | Where-Object { "
        "$_.ConnectionState -eq 'Connected' -and $_.InterfaceIndex -ne 1 }); "
        "ConvertTo-Json -Compress -InputObject @($a | "
        "Select-Object InterfaceAlias,InterfaceIndex,AddressFamily)"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        text=True, encoding="utf-8", errors="replace", timeout=15,
        capture_output=True,
    )
    if result.returncode:
        raise RuntimeError("Network check failed: " + result.stderr.strip())
    active = json.loads(result.stdout)
    if active:
        raise RuntimeError(f"Active network adapters remain; test refused: {active}")


def require_firewall_block():
    """Accept active adapters only when a block rule covers the game executable."""
    command = (
        "$ErrorActionPreference='Stop'; "
        f"Get-NetFirewallRule -DisplayName '{FIREWALL_RULE}' | ForEach-Object {{ "
        "$app = $_ | Get-NetFirewallApplicationFilter; "
        "[pscustomobject]@{ Direction = [string]$_.Direction; Action = [string]$_.Action; "
        "Enabled = [string]$_.Enabled; Program = [string]$app.Program } } | ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", command],
        text=True, encoding="utf-8", errors="replace", timeout=20,
        capture_output=True,
    )
    if result.returncode:
        raise RuntimeError("Firewall rule check failed: " + result.stderr.strip())
    data = json.loads(result.stdout or "[]")
    if isinstance(data, dict):
        data = [data]
    expected = os.path.normcase(str(GAME))
    valid = [row for row in data
             if row["Direction"] == "Outbound" and row["Action"] == "Block"
             and row["Enabled"] == "True"
             and os.path.normcase(row["Program"]) == expected]
    if not valid:
        raise RuntimeError(
            f"Firewall block rule '{FIREWALL_RULE}' covering {GAME} is missing; test refused")


def find_game_window(pid):
    import ctypes
    from ctypes import wintypes
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    found = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def callback(hwnd, _):
        owner = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
        if owner.value == pid and user32.IsWindowVisible(hwnd):
            found.append(hwnd)
        return True

    user32.EnumWindows(callback, 0)
    return found[0] if found else None


def tap(vk, up=False):
    import ctypes
    ctypes.WinDLL("user32", use_last_error=True).keybd_event(
        vk, 0, 2 if up else 0, 0)
    time.sleep(0.05)


def type_ascii(text):
    for ch in text:
        vk = ord(ch.upper())
        tap(vk)
        tap(vk, up=True)


def snapshot(tag, record):
    source = HERE / "game-screen.png"
    if source.exists():
        source.unlink()
    subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
         str(HERE / "capture_game_window.ps1")],
        cwd=HERE, capture_output=True, timeout=30)
    if source.exists():
        target = HERE / f"cheat-{tag}.png"
        target.write_bytes(source.read_bytes())
        record(f"cheat screenshot: {target.name}")
    else:
        record(f"cheat screenshot failed: {tag}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manual-room',action='store_true')
    parser.add_argument("--local-candidate", action="store_true")
    parser.add_argument("--firewall-blocked", action="store_true")
    parser.add_argument("--diagnose-auth", action="store_true")
    parser.add_argument("--cheat-console", action="store_true")
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--capture", default=None,
                        help="capture file; defaults to latest_capture.txt")
    parser.add_argument("--lobby-card", action="store_true",
                        help="replay only the 8001 lobby stream; no match UI or port")
    parser.add_argument("--redirect-all", action="store_true",
                        help="force every game TCP connect to 127.0.0.1; no live traffic")
    parser.add_argument("--seconds", type=int, default=None)
    parser.add_argument("--session-key", default=None,
                        help="32 hex chars; force the client's 16-byte session key")
    args = parser.parse_args()
    session_key = None
    if args.session_key:
        session_key = args.session_key.strip().lower()
        if len(session_key) != 32 or any(c not in "0123456789abcdef" for c in session_key):
            parser.error("--session-key must be exactly 32 hex characters")
    candidate_env = None
    if args.local_candidate:
        candidate = json.loads((HERE / "offline_launch_candidate.json").read_text(encoding="utf-8"))
        candidate_env = candidate["environment"]
        if (set(candidate_env) != {"NMRunEnv_ENUM", "NMRP_DATA", "REVIVAL_SERVER_IP"}
                or candidate_env["REVIVAL_SERVER_IP"] != "127.0.0.1"
                or candidate_env["NMRunEnv_ENUM"] != "NMRP_DATA"):
            raise RuntimeError("Invalid local launch candidate")
    logpath = HERE / f"offline-attempt-{time.time_ns()}.txt"
    server = session = None
    pid = None
    device = frida.get_local_device()
    if any(p.name.lower() == "binarytru.exe" for p in device.enumerate_processes()):
        raise RuntimeError("Close the existing game first; it will not be modified.")
    if not args.local_candidate and not any(p.name.lower() == "revival_launcher.exe" for p in device.enumerate_processes()):
        raise RuntimeError("Open Revival launcher and wait for Play to be ready first.")
    if args.local_candidate:
        print("LOCAL CANDIDATE TEST: launcher is not needed; game acceptance is unverified.")
    else:
        print("1. Open Revival launcher normally and wait until Play is ready.")
        print("   Do NOT click Play. Leave the launcher open.")
    if args.firewall_blocked:
        print("3. Firewall block rule covers the game; adapters may stay connected.")
        print("   Firewall block is applied by this script; starting immediately.")
        require_firewall_block()
        checked = "Firewall block rule verified"
    elif args.redirect_all:
        print("2. Redirect-all mode: every game TCP connect is rewritten to 127.0.0.1.")
        checked = "Redirect-all hook active; no live TCP destination"
    else:
        print("2. Disconnect Wi-Fi and unplug Ethernet; disconnect VPNs too.")
        input("3. Once disconnected, press Enter here to start the ten-minute test: ")
        require_disconnected()
        checked = "Adapter check passed"
    print(f"Results: {logpath}")
    if session_key:
        print(f"Forced session key: {session_key}")
    else:
        print("No forced session key: captured ciphertext will not decrypt offline.")
    with logpath.open("x", encoding="utf-8") as log:
        def record(message):
            log.write(str(message) + "\n")
            log.flush()

        try:
            record(f"{checked}; this is a bounded replay test, not a complete emulator.")
            replay_command = [
                sys.executable, "-u", str(HERE / "offline_replay.py"),
                "--seconds", "0" if args.seconds == 0 else "600", "--experimental-channel",
            ]
            if session_key:
                replay_command += ["--session-key", session_key]
            if args.capture:
                replay_command += ["--capture", args.capture]
            if args.lobby_card:
                replay_command += ["--lobby-card"]
            if args.manual_room:
                replay_command += ['--manual-room']
            if args.diagnose_auth:
                replay_command += ["--diagnose-auth"]
                record("AUTH DIAGNOSIS ONLY: old encrypted world data is not usable")
            server = subprocess.Popen(
                replay_command,
                cwd=HERE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
            )
            # Child reports readiness only after all three sockets bind.
            first = server.stdout.readline()
            record(first.strip())
            if not first.startswith("Local-only replay ready"):
                raise RuntimeError("Replay server did not start; game not launched")

            def pump_server():
                for line in server.stdout:
                    record("SERVER: " + line.rstrip())

            threading.Thread(target=pump_server, daemon=True).start()
            if args.firewall_blocked:
                require_firewall_block()
            elif not args.redirect_all:
                require_disconnected()
            if args.local_candidate:
                env = dict(os.environ)
                env.update(candidate_env)
                pid = device.spawn([str(GAME), "TRAuth", "GoleyTest1234567890ABCD"],
                                   cwd=str(GAME.parent), env=env)
                record("Local candidate spawned suspended; no live identity supplied")
            else:
                print("Starting through the launcher Play button...")
                click = subprocess.Popen(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
                 str(HERE / "click2.ps1")], cwd=HERE,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
                try:
                    pid = wait_for_game(device)
                finally:
                    try:
                        click.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        click.terminate()
                        click.wait(timeout=5)
            record(f"Test game PID: {pid}")
            if not args.local_candidate:
                record("Late attach: first connection may precede hooks; network remains disconnected.")
            session = device.attach(pid)
            script = session.create_script(
                JS.replace("__SESSION_KEY__", json.dumps(session_key))
                .replace("__REDIRECT_ALL__", "true" if args.redirect_all else "false")
                .replace("__CHEAT_CONSOLE__", "true" if args.cheat_console else "false")
                + "\n" + (HERE / "key_probe.js").read_text(encoding="utf-8"))
            hook_state = {"ready": False, "error": None}

            def on_script_message(message, data):
                record(json.dumps(message))
                payload = message.get("payload", {})
                if payload.get("event") == "proud_key_hook_ready":
                    hook_state["ready"] = True
                elif payload.get("event") == "proud_key_signature_mismatch":
                    hook_state["error"] = payload

            script.on("message", on_script_message)
            script.load()
            deadline = time.monotonic() + 2
            while (not hook_state["ready"] and hook_state["error"] is None
                   and time.monotonic() < deadline):
                time.sleep(0.01)
            if hook_state["error"]:
                raise RuntimeError("Session-key hook mismatch: "
                                   + json.dumps(hook_state["error"]))
            if not hook_state["ready"]:
                raise RuntimeError("Session-key hook did not install; replay would not decrypt")
            if args.local_candidate:
                device.resume(pid)
            if args.cheat_console:
                time.sleep(30)
                hwnd = find_game_window(pid)
                record(f"game window: {hwnd}")
                snapshot("lobby", record)
                if hwnd:
                    import ctypes
                    user32 = ctypes.WinDLL("user32", use_last_error=True)
                    user32.ShowWindow(hwnd, 9)
                    user32.SetForegroundWindow(hwnd)
                    time.sleep(0.5)
                    tap(0x11)
                    tap(0xC0)
                    tap(0xC0, up=True)
                    tap(0x11, up=True)
                    record("cheat toggle sent (Ctrl+backtick)")
                    time.sleep(3)
                    snapshot("after-toggle", record)
                    type_ascii("help")
                    tap(0x0D)
                    time.sleep(3)
                    snapshot("after-help", record)
                    type_ascii("card")
                    tap(0x0D)
                    time.sleep(8)
                    snapshot("after-card", record)
            if args.lobby_card:
                print("Test started. Lobby-only mode: do NOT enter Training or start a match.")
            else:
                print("Test started. If lobby opens, try ONLY Training -> Match -> Start.")
            print("Do not buy/open packs. Keep isolation until this console says DONE.")
            seconds = args.seconds if args.seconds is not None else (40 if args.diagnose_auth else 570)
            print("No time limit. Close the game to end the offline session." if seconds == 0
                  else "The test will close its game automatically when the timer ends.")
            deadline = time.monotonic() + seconds if seconds else float('inf')
            next_shot = time.monotonic()
            shot_index = 0
            while time.monotonic() < deadline:
                if not args.firewall_blocked and not args.redirect_all:
                    require_disconnected()
                if server.poll() is not None:
                    raise RuntimeError("Replay server stopped")
                if not any(p.pid == pid for p in device.enumerate_processes()):
                    record("Game exited before deadline")
                    break
                if args.watch and time.monotonic() >= next_shot:
                    snapshot(f"watch-{shot_index:02d}", record)
                    shot_index += 1
                    next_shot = time.monotonic() + 15
                time.sleep(2)
        except Exception as exc:
            record(f"STOP: {type(exc).__name__}: {exc}")
            print(f"Test stopped: {exc}")
        finally:
            if pid is not None:
                try:
                    device.kill(pid)
                    record("Owned game closed")
                except frida.ProcessNotFoundError:
                    pass
            if session is not None:
                try:
                    session.detach()
                except frida.InvalidOperationError:
                    pass
            if server is not None:
                if server.poll() is None:
                    server.terminate()
                server.wait(timeout=10)
            record("DONE; no certificate, proxy, firewall, or adapter settings changed.")
    print("DONE. You can reconnect internet now. The game is no longer needed.")
    try:
        if sys.stdin.isatty():
            input("Press Enter to close this console. ")
    except EOFError:
        pass


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Not started: {type(exc).__name__}: {exc}")
        try:
            if sys.stdin.isatty():
                input("Press Enter to close. ")
        except EOFError:
            pass
