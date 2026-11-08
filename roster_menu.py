"""Portable, offline-only console roster editor for the verified capture schema."""
import re
import json
import subprocess
import sys
import time
from pathlib import Path
from card_patch import FIRST, RECORD, encode_reply
from inspect_shop_capture import capture_replies, decode_reply
from offline_replay import match_port, match_replay

HERE = Path(__file__).resolve().parent
SUPER = {115201074:'15 Ronaldo',115202104:'15 Messi',116520114:'16 Neymar',
         116201194:'16 Modric'}
catalog = HERE / 'super_cards.json'
if catalog.exists():
    SUPER.update({int(k):v for k,v in json.loads(catalog.read_text(encoding='utf-8')).items()})
duplicate_names = {name for name in SUPER.values() if list(SUPER.values()).count(name)>1}
SUPER = {cid:(f'{name} [surum {cid}]' if name in duplicate_names else name)
         for cid,name in SUPER.items()}
position_file = HERE / 'super_positions.json'
POSITIONS = {int(k):v for k,v in json.loads(position_file.read_text(encoding='utf-8')).items()} if position_file.exists() else {}
POSITIONS.update({115201072:'K FT',115202102:'FRV',115202112:'K FT',
                  114932330:'KNT',
                  114108151:'K FT',114501332:'KNT',115201042:'DF',
                  115201022:'DF',116201152:'BEK',114203012:'KL',
                  108453220:'BEK',107404060:'LBR'})
POSITION_CODES = {
    1:'KL', 2:'Mevki dogrulanmadi (2)', 3:'DF', 4:'BEK', 5:'BEK', 6:'LBR',
    7:'KNT', 8:'OOS', 9:'OOS', 10:'K FT', 11:'FRV', 12:'GF',
}


def position_label(card_id):
    label=POSITIONS.get(card_id)
    if not label:
        return 'Mevki bilinmiyor'
    if label.startswith('MEVKI-'):
        code=int(label[6:])
        return POSITION_CODES.get(code,'Mevki adi dogrulanmadi (kod '+str(code)+')')
    return label
NAMES = {**SUPER,115201072:'15 Ronaldo (Ender)',115202102:'15 Messi (Ender)',
         115202112:'15 Neymar (Ender)',114108151:'14 Navas',114501332:'14 Ji Sung',
         115201042:'15 Ramos',115201022:'15 Varane',116201152:'16 Carvajal',
         114203012:'14 Alves (Kaleci)',108453220:'08 Armand',107404060:'07 Rolfes'}

CARDS = dict(SUPER)
RARITIES = {cid:'Süper' for cid in SUPER}
extra_file = HERE/'extra_cards.json'
if extra_file.exists():
    for key,card in json.loads(extra_file.read_text(encoding='utf-8')).items():
        cid=int(key)
        if card['rarity'] not in ('Ender','Uzman','Mythic') or not 100000000<=cid<200000000:
            raise ValueError('Invalid extra card definition')
        CARDS[cid]=card['name']
        NAMES[cid]=card['name']
        RARITIES[cid]=card['rarity']
        if card['position'] is not None:
            POSITIONS[cid]=f'MEVKI-{int(card["position"])}'

known_positions = HERE/'known_positions.json'
if known_positions.exists():
    for key,code in json.loads(known_positions.read_text(encoding='utf-8')).items():
        if type(code) is not int or code not in POSITION_CODES:
            raise ValueError('Invalid known position code')
        POSITIONS.setdefault(int(key), f'MEVKI-{code}')


def inspect(path):
    frames = capture_replies(path)
    cards = {}
    for fi,frame in enumerate(frames):
        p = decode_reply(frame)
        if len(p)<FIRST+RECORD or p[FIRST]!=100 or (len(p)-FIRST-96)%RECORD:
            continue
        # The first card is a short header record; identity has the same stride.
        header_offset=FIRST-RECORD
        instance=p[header_offset+96:header_offset+104]
        cid=int.from_bytes(p[header_offset+104:header_offset+108],'little')
        if instance!=bytes(8) and 100000000<=cid<200000000:
            if instance in cards:
                raise ValueError('Duplicate header card instance; unsupported capture')
            cards[instance]=(fi,header_offset,cid)
        for o in range(FIRST,len(p)-96,RECORD):
            instance=p[o+96:o+104]
            if instance in cards:
                raise ValueError('Duplicate card instance; unsupported capture')
            cards[instance]=(fi,o,int.from_bytes(p[o+104:o+108],'little'))
    squads=[]
    # shortcut: only the verified 2914-byte squad schema; reject other versions.
    for frame in frames:
        p=decode_reply(frame)
        if len(p)==2914:
            ids=[p[i:i+8] for i in range(241,329,8)]
            if len(set(ids))==11 and all(i in cards for i in ids):
                squads.append(ids)
    if len(squads)!=1:
        raise ValueError('Cannot uniquely identify starting XI; no changes made')
    return frames,cards,squads[0]


def replace(source,target,instance,new_id,restore_keeper=False,level=None):
    if new_id not in CARDS and not (restore_keeper and new_id==114203012):
        raise ValueError('Only catalogued card IDs allowed')
    raw=source.read_bytes()
    frames,cards,ids=inspect(source)
    if instance not in ids:
        raise ValueError('Card is not in selected starting XI')
    if restore_keeper and (new_id!=114203012 or cards[instance][2] not in (116103134,116103139)):
        raise ValueError('Unsupported goalkeeper rescue')
    fi,o,_=cards[instance]
    p=bytearray(decode_reply(frames[fi]))
    p[o+104:o+108]=new_id.to_bytes(4,'little')
    # User verified level field +119 in the isolated Super Ronaldo 5 ->25 trial.
    if level is not None and (type(level) is not int or not 1<=level<=0xffffffff):
        raise ValueError('Seviye 1..4294967295 arasında tam sayı olmalı (kayıt alanı uint32).')
    maximum=level if level is not None else {'Süper':25,'Uzman':20}.get(RARITIES.get(new_id))
    if maximum is not None:
        current=int.from_bytes(p[o+119:o+123],'little')
        if not 1<=current<=0xffffffff:
            raise ValueError('Unsupported card level layout; no changes made')
        p[o+119:o+123]=maximum.to_bytes(4,'little')
    patched=list(frames)
    patched[fi]=encode_reply(bytes(p),frames[fi])
    wire=b''.join(patched)
    lines=raw.decode('utf-8').splitlines()
    pos=0
    for i,line in enumerate(lines):
        m=re.fullmatch(r'(?:\d+\.\d+ )?\[8001 S>C\] (\d+)B ([0-9a-f]+)',line)
        if m:
            n=int(m[1])
            lines[i]=f'[8001 S>C] {n}B {wire[pos:pos+n].hex()}'
            pos+=n
    if pos!=len(wire):
        raise ValueError('Stream mismatch')
    with target.open('x',encoding='utf-8') as out:
        out.write('\n'.join(lines)+'\n')
    assert capture_replies(target)==patched
    _,after,new_ids=inspect(target)
    assert ids==new_ids and after[instance][2]==new_id
    assert all(after[i]==cards[i] for i in ids if i!=instance)
    assert source.read_bytes()==raw
    try:
        port=match_port(source)
    except ValueError:
        pass
    else:
        assert match_replay(target,port)==match_replay(source,port)


def search_items(items,query):
    return [i for i,label in enumerate(items) if query.casefold() in label.casefold()]


def choose(items,prompt):
    while True:
        query=input('Ara (isim/ID, hepsi icin Enter): ').strip()
        matches=search_items(items,query)
        if not matches:
            print('Sonuc yok. Tekrar arayin.')
            continue
        for n,i in enumerate(matches,1):
            print(f'{n}. {items[i]}')
        answer=input(prompt+' (yeniden aramak icin Enter): ').strip()
        if not answer:
            continue
        if answer.isdigit() and 1<=int(answer)<=len(matches):
            return matches[int(answer)-1]
        print('Gecersiz secim.')


def main():
    print('OFFLINE SUPER KADRO MENUSU - oyunu once kapatin.')
    print('Canli hesabi okumaz. Yalniz sectiginiz yerel kayittaki ilk 11 okunur.')
    paths=sorted(HERE.glob('capture-*.log'))
    if not paths:
        raise ValueError('No local capture files')
    source=paths[choose([p.name for p in paths],'Kayit: ')]
    _,cards,ids=inspect(source)
    labels=[f'{position_label(cards[i][2])} | {NAMES.get(cards[i][2], "Bilinmeyen oyuncu")} | ID {cards[i][2]} | {i.hex()}' for i in ids]
    instance=ids[choose(labels,'Degisecek kart: ')]
    options=sorted(SUPER,key=lambda c:(SUPER[c].casefold(),c))
    new_id=options[choose([position_label(c)+' | '+SUPER[c]+' / Super | ID '+str(c) for c in options],'Yeni oyuncu: ')]
    target=HERE/f'capture-menu-{time.time_ns()}.log'
    replace(source,target,instance,new_id)
    print('Olusturuldu:',target.name)
    print('Konum, mevki, maliyet/uyum oyunda kontrol edilmeli. Orijinal korundu.')
    if input('Bu kayitla oyunu ac? (e/h): ').strip().lower()=='e':
        args=[sys.executable,str(HERE/'run_offline_test.py'),'--local-candidate',
              '--redirect-all','--capture',str(target),'--session-key',
              '00112233445566778899aabbccddeeff','--seconds','0']
        try:
            match_port(target)
        except ValueError:
            args.append('--lobby-card')
            print('Lobi kaydi: MACA GIRMEYIN.')
        print('Sure siniri yok; bitirmek icin oyunu kapat.')
        subprocess.run(args,cwd=HERE,check=True)


if __name__=='__main__':
    try:
        main()
    except (ValueError,OSError,subprocess.CalledProcessError) as exc:
        print('Durduruldu:',exc)
    input('Kapatmak icin Enter...')
