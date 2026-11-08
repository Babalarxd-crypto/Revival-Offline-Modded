"""Isolated level1/2 experiment, based on the observed normal-game reply225."""
from inspect_shop_capture import decode_reply
from card_patch import encode_reply

PREFIXES = {1:'d4796c14', 2:'0fef5cbc', 3:'0fef5cbc', 4:'85d93d0c', 10:'220ed1a3'}


def set_difficulty(template, level):
    if level not in range(1, 11):
        raise ValueError('Difficulty must be 1..10')
    reply = bytearray(decode_reply(template))
    if len(reply) != 225 or reply[4:8] != b'\x01\0\0\0' or reply[8] not in range(1, 11):
        raise ValueError('Unsupported opponent reply')
    # shortcut: levels5..9 lack recorded replies; use captured level4 prefix until validated.
    reply[:4] = bytes.fromhex(PREFIXES.get(level, PREFIXES[4]))
    reply[8] = level
    return encode_reply(bytes(reply), template)


def resequence(reply, sequence):
    from offline_replay import pop_frames
    buffer = bytearray(reply)
    frames = pop_frames(buffer)
    if buffer:
        raise ValueError('Incomplete room reply')
    result = []
    for frame in frames:
        template = bytearray(frame)
        template[3] = sequence
        result.append(encode_reply(decode_reply(frame), template))
        sequence = (sequence + 1) & 255
    return b''.join(result), sequence


def difficulty_reply(request, template, sequence, allow_team_selection=False):
    if len(request) != 285:
        return None
    data = decode_reply(request)
    reply = bytearray(decode_reply(template))
    if (len(data) != 256 or len(reply) != 225
            or data[4:8] != b'\x01\0\0\0'
            or data[28] not in range(1, 11)
            or any(data[110:232])):
        return None
    if data[17:21] != reply[217:221]:
        if not allow_team_selection:
            return None
        # Observed team-selection requests use level1 and a UTF16 team label.
        name = data[30:110].decode('utf-16-le', errors='strict').split('\0')[0]
        if data[28] != 1 or not 1 <= int.from_bytes(data[17:21], 'little') <= 200000 or not name.strip():
            return None
    level = data[28]
    # shortcut: opaque prefixes are captured, not derived for arbitrary sequences/teams.
    reply[:4] = bytes.fromhex(PREFIXES.get(level, PREFIXES[4]))
    reply[8] = level
    reply[217:221] = data[17:21]
    wire = bytearray(template)
    wire[3] = sequence
    return encode_reply(bytes(reply), wire), level


def main():
    from pathlib import Path
    root = Path(__file__).resolve().parent
    server = (root / 'offline_replay_halftime_diag.py').read_text(encoding='utf-8')
    runner = (root / 'run_halftime_diagnostic.py').read_text(encoding='utf-8')
    assert runner.count('HERE / "offline_replay_halftime_diag.py"') == 1
    runner = runner.replace('HERE / "offline_replay_halftime_diag.py"',
                            'HERE / "offline_replay_difficulty_trial.py"')
    for name, text in [('offline_replay_difficulty_trial.py', server),
                       ('run_difficulty_trial.py', runner)]:
        compile(text, name, 'exec')
        (root / name).write_text(text, encoding='utf-8')
    print('PASS isolated difficulty runner generated; main launcher unchanged')


if __name__ == '__main__':
    main()
