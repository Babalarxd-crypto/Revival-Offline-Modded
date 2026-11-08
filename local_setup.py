"""Prepare localhost identity and validated own-user bootstrap; no network writes."""
import hashlib
import json
import os
import re
from urllib.request import urlopen, Request
from pathlib import Path
from offline_launch_data import build_environment
from offline_launch_data import RELEASE_KEYS
from launch_codec import normalize_key
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes
from offline_replay import exchanges, pop_frames

HERE = Path(__file__).resolve().parent


def release_from_manifest(text, raw):
    """Use only public version metadata, never account fields from the log."""
    manifest = json.loads(raw)
    launcher = re.findall(r'launcher manifest ok, build launcher-([^\s]+)', text)
    versions = re.findall(r'game manifest ok, build ([^\s]+)', text)
    identities = re.findall(r'(?:ticket|restore) request \(patchline=([a-zA-Z0-9_-]+), build=(\d+)\)', text)
    if not launcher or not versions or not identities or versions[-1] != manifest['version']:
        raise ValueError('Normal launcher sürüm kaydı manifestle eşleşmiyor. Normal launcherı açıp güncellemeyi tamamlayın.')
    patchline, build = identities[-1]
    if patchline != 'live':
        raise ValueError('Yalnızca live sürüm metadata hazırlığı destekleniyor.')
    files = {row['path']: row for row in manifest['files']}
    release = dict(zip(RELEASE_KEYS, (launcher[-1],patchline,build,manifest['version'],
        hashlib.sha256(raw).hexdigest(),files['BinaryTr/BinaryTrU.exe']['sha256'],
        files['BinaryTr/revival_client.dll']['sha256'])))
    build_environment(b'GoleyTest1234567890ABCD', release)
    return release


def installed_release(game_root):
    log = Path(os.environ['APPDATA'])/'Revival'/'logs'/'launcher.log'
    text = log.read_text(encoding='utf-8', errors='replace')
    if not re.search(r'launcher manifest ok, build launcher-([^\s]+)', text):
        request = Request('https://api.playrevival.co/api/v1/patch/launcher',
                          headers={'User-Agent':'Mozilla/5.0','Accept':'application/json'})
        with urlopen(request,timeout=20) as response:
            launcher_raw=response.read(2*1024*1024+1)
        if len(launcher_raw)>2*1024*1024:
            raise ValueError('Launcher manifesti çok büyük.')
        launcher_manifest=json.loads(launcher_raw)
        entry=next(row for row in launcher_manifest['files'] if row['path']=='revival_launcher.exe')
        launcher_path=Path(game_root)/'revival_launcher.exe'
        if hashlib.sha256(launcher_path.read_bytes()).hexdigest()!=entry['sha256']:
            raise ValueError('Kurulu normal launcher resmi manifestle eşleşmiyor.')
        version=launcher_manifest['version']
        if not re.fullmatch(r'launcher-[0-9.]+',version):
            raise ValueError('Launcher sürüm biçimi desteklenmiyor.')
        text+='\nlauncher manifest ok, build '+version+'\n'
    # Public metadata only; no login, ticket request, game download or account operation.
    request = Request('https://api.playrevival.co/api/v1/patch/live',
                      headers={'User-Agent':'Mozilla/5.0', 'Accept':'application/json'})
    with urlopen(request, timeout=20) as response:
        raw = response.read(2*1024*1024+1)
    if len(raw) > 2*1024*1024:
        raise ValueError('Manifest beklenen boyutu aşıyor.')
    release = release_from_manifest(text, raw)
    candidate(game_root, release)
    return release


def validate_game(game_root):
    for name in ('BinaryTrU.exe', 'revival_client.dll'):
        if not (Path(game_root)/'Game'/'BinaryTr'/name).is_file():
            raise ValueError('Oyun dosyası bulunamadı: '+name)


def runtime_release(encoded):
    key = normalize_key(b'GoleyTest1234567890ABCD')
    wire = bytes.fromhex(encoded)
    if not wire or len(wire) % 8 or len(wire) > 65536:
        raise ValueError('Geçersiz başlatma verisi')
    decryptor = Cipher(TripleDES(key), modes.CBC(key[:8])).decryptor()
    data = decryptor.update(wire)+decryptor.finalize()
    padding = data[-1]
    if not 1 <= padding <= 8 or data[-padding:] != bytes([padding])*padding:
        raise ValueError('Başlatma verisi biçimi desteklenmiyor')
    fields = {}
    for part in data[:-padding].decode('utf-8').split(';'):
        if not part:
            continue
        name, separator, value = part.partition('=')
        if not separator or name in fields:
            raise ValueError('Geçersiz başlatma alanı')
        fields[name] = value
    release = {name: fields[name] for name in RELEASE_KEYS}
    # Discard account/ticket fields; only release metadata leaves this function.
    build_environment(b'GoleyTest1234567890ABCD', release)
    return release


def candidate(game_root, release):
    validate_game(game_root)
    for name, key in [('BinaryTrU.exe', 'REVIVAL_HOST_SHA256'),
                      ('revival_client.dll', 'REVIVAL_DLL_SHA256')]:
        path = Path(game_root)/'Game'/'BinaryTr'/name
        if hashlib.sha256(path.read_bytes()).hexdigest() != release[key]:
            raise ValueError('Desteklenmeyen oyun sürümü: '+name+'. Yerel veri oluşturulmadı.')
    return {'environment': build_environment(b'GoleyTest1234567890ABCD', release),
            'release_fields': release, 'status': 'local-synthetic-offline'}


def auth_log(rows):
    groups = exchanges(rows, 2756)
    if (len(groups) != 2 or
            sum(len(a)+len(b) for a,b in groups) != sum(len(data) for _,sock,data in rows if sock==2756)):
        raise ValueError('Giriş kaydı eksik: iki tam giriş alışverişi gerekli. Kaydı girişten önce başlatın.')
    for request, response in groups:
        for data in (request, response):
            buffer = bytearray(data)
            if not pop_frames(buffer) or buffer:
                raise ValueError('Giriş kaydı eksik paket içeriyor; mevcut veriler korunuyor.')
    return ''.join(f'{direction} {"send" if direction=="OUT" else "recv"} sock=2756 {data.hex()}\n'
                   for request, response in groups
                   for direction, data in [('OUT', request), ('IN', response)])


def save_setup(folder, game_root, rows, release):
    folder = Path(folder)
    report = candidate(game_root, release)
    text = auth_log(rows)
    # Never replace an existing working setup or a user's original log.
    if any((folder/name).exists() for name in ('game.log', 'offline_launch_candidate.json')):
        raise ValueError('Yerel veri zaten var; üzerine yazılmadı.')
    with (folder/'game.log').open('x', encoding='utf-8') as out:
        out.write(text)
    try:
        with (folder/'offline_launch_candidate.json').open('x', encoding='utf-8') as out:
            json.dump(report, out, indent=2)
    except Exception:
        (folder/'game.log').unlink()
        raise


def auth_recording_rows(capture, primary):
    """Select one complete auth connection; never concatenate reconnects."""
    from offline_replay import records
    try:
        auth_log(primary)
        return primary
    except ValueError:
        pass
    for path in sorted(capture.parent.glob(capture.stem+'.auth-*.log')):
        rows=records(path)
        try:
            auth_log(rows)
        except ValueError:
            continue
        return rows
    raise ValueError('Hiçbir giriş bağlantısı tek başına tam değil; bağlantılar birleştirilmedi.')
