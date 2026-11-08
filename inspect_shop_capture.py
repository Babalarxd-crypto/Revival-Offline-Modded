"""Read recorded lobby replies only; no networking or live-process access.

Padding layout: BinaryTrU.exe SHA256
199c410ad9ced1f7ec8838e7f243366f96f63cde576f392c7de2965e9c3fad1f,
VAs 0xa699d0 / 0xa69b70 and tables 0xf83578 / 0xf835c0 / 0xf838b0.
The captured XOR variant is corroborated by the UI wallet and UTF-16 name.
The leading four decoded bytes and general field schema remain unidentified.
This is not a validated encoder and must not be used to construct live requests.
"""
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

from offline_replay import pop_frames


THRESHOLDS = (0, 1, 12, 17, 24, 34, 47, 57, 69, 79, 99, 114, 130, 150,
              181, 221, 281)
PADDING = (
    ((), ()),
    ((1,), (3,)),
    ((1, 4), (3, 3)),
    ((1, 4, 4), (3, 1, 2)),
    ((4, 4, 6), (2, 3, 3)),
    ((8, 4, 11), (3, 2, 3)),
    ((7, 8, 9, 11), (3, 3, 3, 2)),
    ((4, 7, 14, 13, 6), (2, 2, 2, 2, 3)),
    ((3, 15, 9, 16, 5, 7), (2, 2, 2, 3, 2, 2)),
    ((6, 14, 12, 14, 7, 10), (2, 3, 2, 2, 2, 2)),
    ((9, 2, 12, 14, 11, 16, 13), (2, 3, 2, 3, 3, 3, 2)),
    ((11, 4, 21, 12, 14, 12, 11), (3, 2, 3, 2, 2, 3, 3)),
    ((4, 24, 19, 6, 24, 16, 4, 10), (1, 3, 3, 3, 3, 2, 3, 1)),
    ((8, 4, 11, 17, 26, 18, 19, 26), (3, 3, 1, 3, 2, 3, 3, 1)),
    ((3, 17, 15, 19, 27, 11, 32, 34), (2, 1, 3, 3, 3, 2, 3, 3)),
    ((4, 16, 33, 26, 23, 22, 32, 15, 23), (1, 3, 2, 3, 3, 2, 3, 2, 1)),
    ((14, 8, 21, 29, 39, 35, 17, 32, 37, 24), (3, 3, 3, 2, 2, 3, 2, 2, 2, 3)),
)


def decode_reply(frame):
    """Decode this capture's 0x32 variant; no checksum/authenticity validation."""
    if (len(frame) < 5 or frame[0] != 0x32
            or int.from_bytes(frame[1:3], "little") != len(frame) - 4
            or len(frame) - 4 > 8192):
        raise ValueError("Invalid or unsupported lobby reply")
    data = frame[4:]
    group = max(i for i, lower in enumerate(THRESHOLDS) if len(data) >= lower)
    copies, skips = PADDING[group]
    unpacked = bytearray()
    pos = 0
    for copy, skip in zip(copies, skips):
        if pos + copy + skip > len(data):
            raise ValueError("Truncated lobby padding layout")
        unpacked.extend(data[pos:pos + copy])
        pos += copy + skip
    unpacked.extend(data[pos:])
    sequence = frame[3]
    key = b"RealMadrid"
    return bytes(value ^ key[i % 10]
                 ^ (sequence ^ ((i // 10) & 255)
                    if ((i // 10) & 255) != sequence else 255 - sequence)
                 for i, value in enumerate(unpacked))


def capture_replies(path):
    buffer = bytearray()
    frames = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = re.fullmatch(r"(?:\d+\.\d+ )?\[8001 S>C\] (\d+)B ([0-9a-f]+)", line)
        if match:
            chunk = bytes.fromhex(match[2])
            if len(chunk) != int(match[1]):
                raise ValueError("Capture byte count mismatch")
            buffer.extend(chunk)
            frames.extend(pop_frames(buffer))
    if buffer:
        raise ValueError("Capture ends in an incomplete lobby reply")
    return frames


def inspect(path):
    frames = capture_replies(path)
    wallet_candidates = []
    for index, frame in enumerate(frames):
        plain = decode_reply(frame)
        # shortcut: these two wallet offsets are established only for these
        # captured reply layouts; require a decoded schema before generalizing.
        offset = 178 if len(frame) == 741 and len(plain) == 712 else 8 if (
            len(frame) == 36 and len(plain) == 24) else None
        if offset is not None:
            gp, reserved, gold = struct.unpack_from("<III", plain, offset)
            wallet_candidates.append({"frame": index, "wire_bytes": len(frame),
                                      "decoded_offset": offset, "gp": gp,
                                      "reserved": reserved, "gold": gold})
    return {"capture": str(path),
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "server_lobby_frames": len(frames),
            "wallet_candidates": wallet_candidates,
            "limits": ["Read-only historical capture; no live state is changed.",
                       "No checksum validation or complete message schema.",
                       "Wallet display is not proof of pack grants or inventory writes."]}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    print(json.dumps(inspect(args.capture), indent=2))
