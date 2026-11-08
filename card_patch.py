"""Offline-only 8001 card-list patcher.

Encoding is the exact inverse of inspect_shop_capture.decode_reply: XOR with
the same keystream, then re-insert the all-zero padding seen in the capture.
Nothing here touches the network or the live account.
"""
import argparse
import re
from pathlib import Path

from inspect_shop_capture import PADDING, THRESHOLDS, capture_replies, decode_reply

KEY = b"RealMadrid"
CARD_PLAIN = 6521          # 4 + 0x80 + 29 * 217 + 96
CARD_WIRE = 6550
RECORD = 217
FIRST = 0x84


def keystream(sequence, length):
    return bytes(
        KEY[i % 10]
        ^ (sequence ^ ((i // 10) & 255)
           if ((i // 10) & 255) != sequence else 255 - sequence)
        for i in range(length)
    )


def encode_reply(plain, template):
    """Rebuild a wire frame using the template's sequence and padding group."""
    data_len = len(template) - 4
    group = max(i for i, lower in enumerate(THRESHOLDS) if data_len >= lower)
    copies, skips = PADDING[group]
    if len(plain) + sum(skips) != data_len:
        raise ValueError("Plain length does not fit template padding group")
    encrypted = bytes(a ^ b for a, b in zip(plain, keystream(template[3], len(plain))))
    padded = bytearray()
    pos = 0
    for copy, skip in zip(copies, skips):
        padded.extend(encrypted[pos:pos + copy])
        padded.extend(bytes(skip))
        pos += copy
    padded.extend(encrypted[pos:])
    return bytes([0x32]) + len(padded).to_bytes(2, "little") + bytes([template[3]]) + padded


def self_test(path):
    frames = capture_replies(path)
    for frame in frames:
        plain = decode_reply(frame)
        assert encode_reply(plain, frame) == frame
        patched = bytearray(plain)
        patched[0] ^= 0x5A
        assert decode_reply(encode_reply(bytes(patched), frame)) == bytes(patched)
    print(f"PASS: {len(frames)} frames round-trip byte-identically and payload edits survive")


def patch_capture(source, target, record_index=None, count=1, templates=None):
    lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    pattern = re.compile(r"\[8001 S>C\] (\d+)B ([0-9a-f]+)")
    row_index = [i for i, line in enumerate(lines) if pattern.search(line)]
    lengths = [len(pattern.search(lines[i])[2]) // 2 for i in row_index]
    stream = bytearray()
    for i in row_index:
        stream.extend(bytes.fromhex(pattern.search(lines[i])[2]))
    frames = []
    pos = 0
    while pos < len(stream):
        size = 4 + int.from_bytes(stream[pos + 1:pos + 3], "little")
        frames.append(bytes(stream[pos:pos + size]))
        pos += size
    card_indexes = [i for i, frame in enumerate(frames)
                    if len(frame) == CARD_WIRE and len(decode_reply(frame)) == CARD_PLAIN]
    if not card_indexes:
        raise ValueError("No card-list frame in capture")
    first = card_indexes[0]
    plain = bytearray(decode_reply(frames[first]))
    src = FIRST + RECORD
    if plain[src + 0x74:src + 0x78] != bytes.fromhex("00000006") or \
            plain[src + 0x78:src + 0x7c] != bytes.fromhex("00000092"):
        raise ValueError("Expected rarity-6 template-146 source record not found")
    if templates:
        count = len(templates)
    if record_index is None:
        indexes = [i for i in range(29) if plain[FIRST + i * RECORD + 0x7b] == 0][:count]
        if len(indexes) < count:
            raise ValueError("Not enough empty slots in the first card frame")
    else:
        indexes = [record_index]
    for slot, record_index in enumerate(indexes):
        dst = FIRST + record_index * RECORD
        plain[dst + 0x74:dst + 0x7c] = plain[src + 0x74:src + 0x7c]
        if templates:
            plain[dst + 0x78:dst + 0x7c] = b"\x00\x00\x00" + bytes([templates[slot]])
        # flag 1 marks an in-squad card; clones start unused so the
        # "Kullanilmayan" filter can show them.
        plain[dst + 0x7c:dst + 0x80] = b"\x00\x00\x00\x00"
    frames[first] = encode_reply(bytes(plain), frames[first])
    rebuilt = b"".join(frames)
    if len(rebuilt) != len(stream):
        raise ValueError("Patched stream length changed")
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    out = target.read_text(encoding="utf-8").splitlines()
    offset = 0
    for i, size in zip(row_index, lengths):
        text = rebuilt[offset:offset + size].hex()
        out[i] = f"[8001 S>C] {size}B {text}"
        offset += size
    target.write_text("\n".join(out) + "\n", encoding="utf-8")
    for slot, record_index in enumerate(indexes):
        dst = FIRST + record_index * RECORD
        template = templates[slot] if templates else 146
        print(f"PASS: frame {first} record {record_index} -> rarity 6 template {template} "
              f"instance {plain[dst + 0x60:dst + 0x68].hex()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--patch", type=Path, help="write a patched copy of the capture")
    parser.add_argument("--count", type=int, default=1,
                        help="number of empty slots to fill with the source card")
    parser.add_argument("--templates",
                        help="comma-separated template ids, one per empty slot")
    args = parser.parse_args()
    if args.self_test:
        self_test(args.capture)
    if args.patch:
        chosen = [int(x) for x in args.templates.split(",")] if args.templates else None
        patch_capture(args.capture, args.patch, count=args.count, templates=chosen)
