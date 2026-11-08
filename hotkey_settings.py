"""Shared, local-only room hotkeys for GUI and replay processes."""
import json
from pathlib import Path

PATH=Path(__file__).resolve().parent/'hotkeys.json'
KEYS={**{chr(n):n for n in range(65,91)},**{str(n):48+n for n in range(10)},
      'End':0x23,'Page Up':0x21,'Home':0x24,'Page Down':0x22,
      **{f'F{n}':0x6f+n for n in range(1,13)}}


def validate(room,start):
    if room not in KEYS or start not in KEYS or room==start:
        raise ValueError('İki farklı, desteklenen tuş seçin.')
    return room,start


def load():
    if not PATH.exists():
        return 'N','M'
    data=json.loads(PATH.read_text(encoding='utf-8'))
    return validate(data['room'],data['start'])


def save(room,start):
    validate(room,start)
    temporary=PATH.with_suffix('.json.tmp')
    temporary.write_text(json.dumps({'room':room,'start':start}),encoding='utf-8')
    temporary.replace(PATH)
