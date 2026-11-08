"""Automatic local recording repair; preserve originals and reject real gaps."""
import json
import re
from pathlib import Path
from offline_replay import forced_session_key, records, channel_plan
from inspect_shop_capture import capture_replies
from local_setup import auth_log, auth_recording_rows
from verify_session_keys import normalize_capture, verified_keys
from offline_replay import match_rows, pop_channel_frames, match_port, room_phases, match_replay
from roster_menu import inspect

AUTH_RECONNECT='8000: multiple data-bearing connections; capture cannot be merged'


def reset_warning(reason):
    return isinstance(reason,str) and reason.startswith('TCP recording interrupted: [WinError 10054]')


def validate_reset_capture(path):
    """A reset is tolerable only with complete recorded match/bootstrap structures."""
    inspect(path)
    primary=path.with_suffix('.auth.log')
    auth_log(auth_recording_rows(path,records(primary) if primary.exists() else []))
    channel_plan(path)
    # Validate stream integrity independently of the replay's supported room schema.
    # A readable recording is not a claim of a replay-compatible match.
    ports={int(port) for port in re.findall(r'^\[(18\d{3}) (?:C>S|S>C)\]',path.read_text(encoding='utf-8'),re.M)}
    for channel in ports:
        for side in ('OUT','IN'):
            buffer=bytearray(b''.join(data for direction,_,data in match_rows(path,channel) if direction==side))
            if not pop_channel_frames(buffer) or buffer:
                raise ValueError('Bağlantı kapanışında eksik kanal verisi var; kayıt korunuyor.')


def prepare_recording(path):
    path=Path(path)
    key_file=path.with_suffix('.keys.json')
    text=path.read_text(encoding='utf-8')
    benign=False
    reset=False
    for line in text.splitlines():
        if not line.startswith('EVENT '):
            continue
        event=json.loads(line[6:])
        if event.get('kind')!='gap':
            continue
        if reset_warning(event.get('reason')):
            reset=True
        elif event.get('reason')!=AUTH_RECONNECT:
            raise ValueError('Kaydedici gerçek paket kaybı bildirmiş; kaynak korunuyor: '+str(event.get('reason')))
        benign=True
    if reset:
        validate_reset_capture(path)
    if benign:
        primary=path.with_suffix('.auth.log')
        auth_log(auth_recording_rows(path,records(primary) if primary.exists() else []))
    known=forced_session_key(path)
    if known is not None and not benign:
        return path
    if not key_file.exists() and known is None:
        return path
    candidates=json.loads(key_file.read_text(encoding='utf-8')) if key_file.exists() else [known]
    target=path.with_suffix('.offline.log')
    if target.exists():
        verified_keys(target,candidates)
        if capture_replies(path)!=capture_replies(target):
            raise ValueError('Var olan offline kopyanın kadrosu farklı; üzerine yazılmadı.')
        channel_plan(target)
        return target
    normalize_capture(path,target,candidates)
    try:
        if benign:
            lines=[]
            for line in target.read_text(encoding='utf-8').splitlines():
                if line.startswith('EVENT '):
                    event=json.loads(line[6:])
                    if event.get('kind')=='gap' and (event.get('reason')==AUTH_RECONNECT or reset_warning(event.get('reason'))):
                        line='EVENT '+json.dumps({'kind':'note','reason':'Recorded stream boundaries validated; match replay compatibility not implied. Original warning: '+event['reason']})
                lines.append(line)
            target.write_text('\n'.join(lines)+'\n',encoding='utf-8')
        channel_plan(target)
    except Exception:
        target.unlink()
        raise
    return target
