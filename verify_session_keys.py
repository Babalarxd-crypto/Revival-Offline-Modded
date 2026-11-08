"""Validate observed AES candidates against recorded outbound protocol messages."""
import re
from offline_replay import match_rows, pop_channel_frames, decrypt_envelope


def verified_keys(path, candidates):
    ports={int(p) for p in re.findall(r'^\[(18\d{3}) C>S\]',path.read_text(encoding='utf-8'),re.M)}
    verified={}
    for port in sorted(ports):
        if port!=18030 and not 18020<=port<=18029:
            continue
        buffer=bytearray(b''.join(data for side,_,data in match_rows(path,port) if side=='OUT'))
        frames=pop_channel_frames(buffer)
        if buffer:
            raise ValueError('Kayıtta tamamlanmamış kanal paketi var.')
        matches=[]
        for token in candidates:
            if not re.fullmatch('[0-9a-f]{32}',token):
                raise ValueError('Geçersiz anahtar adayı')
            sequences=[]
            for frame in frames:
                plain=decrypt_envelope(frame,bytes.fromhex(token))
                if plain is None:
                    continue
                if port==18030:
                    valid=len(plain)>=5 and plain[2:4] in (b'\x02\x01',b'\x02\x02')
                else:
                    valid=len(frame)==56 and plain[2:5]==b'\x02\x01\x19'
                if valid:
                    sequences.append(int.from_bytes(plain[:2],'little'))
            if len(set(sequences))>=2 and any((b-a)%65536==1 for a,b in zip(sequences,sequences[1:])):
                matches.append(token)
        if len(matches)!=1:
            raise ValueError(f'{port}: tek bir anahtar en az iki ardışık şifreli mesajla doğrulanamadı.')
        verified[port]=matches[0]
    if 18030 not in verified:
        raise ValueError('Kanal anahtarı doğrulanamadı; yeniden kayıt önermeden önce gözlemciyi kontrol edin.')
    return verified


def normalize_capture(source, target, candidates):
    """Re-encrypt only AES envelopes in a new disk copy; plaintext stays identical."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    source_text=source.read_text(encoding='utf-8')
    keys=verified_keys(source,candidates)
    common=next((value for port,value in keys.items() if 18020<=port<=18029),keys[18030])
    lines=source_text.splitlines()
    streams={}
    for index,line in enumerate(lines):
        match=re.fullmatch(r'\[(18\d{3}) (C>S|S>C)\] (\d+)B ([0-9a-f]+)',line)
        if not match or int(match[1]) not in keys:
            continue
        data=bytes.fromhex(match[4])
        if len(data)!=int(match[3]):
            raise ValueError('Kanal bayt sayısı uyuşmuyor')
        streams.setdefault((int(match[1]),match[2]),[]).append((index,data))
    for (port,direction),chunks in streams.items():
        buffer=bytearray(b''.join(data for _,data in chunks))
        frames=pop_channel_frames(buffer)
        if buffer:
            raise ValueError('Eksik kanal paketi; kaynak korunuyor')
        patched=[]
        for frame in frames:
            plain=decrypt_envelope(frame,bytes.fromhex(keys[port]))
            if plain is None:
                patched.append(frame)
                continue
            header=3+frame[2]
            width=frame[header+2]
            start=header+3+width
            encryptor=Cipher(algorithms.AES(bytes.fromhex(common)),modes.ECB()).encryptor()
            new=frame[:start]+encryptor.update(plain)+encryptor.finalize()
            if decrypt_envelope(new,bytes.fromhex(common))!=plain:
                raise ValueError('Şifreleme doğrulanamadı')
            patched.append(new)
        wire=b''.join(patched)
        offset=0
        for index,data in chunks:
            size=len(data)
            lines[index]=f'[{port} {direction}] {size}B {wire[offset:offset+size].hex()}'
            offset+=size
        if offset!=len(wire):
            raise ValueError('Kanal uzunluğu değişti')
    lines=[line for line in lines if not line.startswith('[sessionkey]')]
    lines += [f'[sessionkey] port={port} key={common} observed=1' for port in sorted(keys)]
    result='\n'.join(lines)+'\n'
    with target.open('x',encoding='utf-8') as out:
        out.write(result)
    try:
        verified_keys(target,{common})
    except Exception:
        target.unlink()
        raise
    return target
