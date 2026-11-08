"""Build isolated offline room-duration fixtures; no network or process access."""
import re
from pathlib import Path
from card_patch import encode_reply
from inspect_shop_capture import decode_reply
from offline_replay import pop_frames

HERE = Path(__file__).resolve().parent
SOURCE = 'capture-20261103-215951-balanced-trial-positions-expert.log'
ROW = re.compile(r'(\[8001 S>C\] )(\d+)B ([0-9a-f]+)')


def patch_duration(frame, minutes):
    if minutes not in (3, 6, 9):
        raise ValueError('Duration must be 3, 6 or 9')
    plain = decode_reply(frame)
    # shortcut: these two observed creation layouts only; simulation use needs testing.
    if (len(plain) not in (215, 3911) or plain[208:213] not in
            (bytes.fromhex('0334000080'), bytes.fromhex('0344000080'))
            or plain[213] not in (3, 6, 9)):
        return frame, False
    patched = bytearray(plain)
    patched[213] = minutes
    result = encode_reply(bytes(patched), frame)
    assert len(result) == len(frame) and decode_reply(result) == bytes(patched)
    return result, True


def build(source, minutes, difficulty=None):
    lines = source.splitlines(keepends=True)
    rows = [(i, ROW.search(line)) for i, line in enumerate(lines) if ROW.search(line)]
    stream = bytearray()
    for _, match in rows:
        data = bytes.fromhex(match[3])
        if len(data) != int(match[2]):
            raise ValueError('Capture row length mismatch')
        stream.extend(data)
    frames = pop_frames(stream)
    if stream:
        raise ValueError('Incomplete lobby capture')
    patched = [patch_duration(frame, minutes) for frame in frames]
    count = sum(changed for _, changed in patched)
    if count < 2:
        raise ValueError('Expected both captured room creation layouts')
    if difficulty is not None:
        from difficulty_trial import set_difficulty
        opponents = 0
        selected = []
        for frame, changed in patched:
            plain = decode_reply(frame)
            if len(plain) == 225 and plain[4:8] == b'\x01\0\0\0':
                frame = set_difficulty(frame, difficulty)
                opponents += 1
            selected.append((frame, changed))
        if opponents != 1:
            raise ValueError('Expected one initial opponent reply')
        patched = selected
    data = b''.join(frame for frame, _ in patched)
    pos = 0
    for i, match in rows:
        size = int(match[2])
        replacement = match[1] + match[2] + 'B ' + data[pos:pos + size].hex()
        lines[i] = lines[i][:match.start()] + replacement + lines[i][match.end():]
        pos += size
    assert pos == len(data)
    return ''.join(lines), count


def main():
    source = (HERE / SOURCE).read_text(encoding='utf-8')
    for minutes in (3, 6, 9):
        text, count = build(source, minutes)
        name = f'duration-trial-{minutes}min.log'
        (HERE / name).write_text(text, encoding='utf-8')
        command = ('@echo off\ncd /d "%~dp0"\n'
                   'echo DENEYSEL: Oda suresi onceden secili. Gercek mac suresi henuz dogrulanmadi.\n'
                   'echo Oda acilinca sureyi degistirmeyin. End = oda, Page Up = baslat.\n'
                   '"Python\\python.exe" limited_run.py "Python\\python.exe" -u run_halftime_diagnostic.py '
                   '--local-candidate --redirect-all --manual-room --seconds 0 '
                   '--session-key 00112233445566778899aabbccddeeff --capture ' + name + '\npause\n')
        (HERE / f'SURE_DENE_{minutes}DK.cmd').write_text(command, encoding='ascii')
        print(f'Built {name}: {count} room snapshots; all other payload fields preserved')


if __name__ == '__main__':
    main()
