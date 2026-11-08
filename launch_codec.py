"""Local launch-data codec candidate, reconstructed from launcher assembly.

No game execution, environment writes, or network. Runtime compatibility is
unverified; this is not the game's network-packet cipher.
"""
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives.ciphers import Cipher, modes


def normalize_key(raw):
    # Launcher helper truncates at NUL, limits to 24, then space-pads to 24.
    return raw.split(b"\0", 1)[0][:24].ljust(24, b" ")


def encode(payload, raw_key):
    key = normalize_key(raw_key)
    padding = 8 - len(payload) % 8
    # Helper receives padding count in both RDX (length) and R8B (fill).
    padded = payload + bytes([padding]) * padding
    encryptor = Cipher(TripleDES(key), modes.CBC(key[:8])).encryptor()
    return (encryptor.update(padded) + encryptor.finalize()).hex()


def self_test():
    raw_key = b"local-test-key"
    key = normalize_key(raw_key)
    assert len(key) == 24
    assert normalize_key(b"abc\0ignored") == b"abc" + b" " * 21
    assert normalize_key(b"x" * 30) == b"x" * 24
    for payload in [b"", b"a", b"12345678", b"SERVER_IP=127.0.0.1;USER_ID=offline;"]:
        result = encode(payload, raw_key)
        assert result == result.lower() and len(result) % 16 == 0
        decryptor = Cipher(TripleDES(key), modes.CBC(key[:8])).decryptor()
        decoded = decryptor.update(bytes.fromhex(result)) + decryptor.finalize()
        padding = 8 - len(payload) % 8
        assert decoded == payload + bytes([padding]) * padding
    print("PASS: candidate launch codec roundtrip and key normalization")


if __name__ == "__main__":
    self_test()
