"""Build LOCAL launch-data candidates, without writing environment or launching.

The key and release fields must be explicitly supplied from validated evidence.
Do not use a real account/password. Game acceptance remains unverified.
"""
import ipaddress

from launch_codec import encode

RELEASE_KEYS = (
    "REVIVAL_LAUNCHER_BUILD", "REVIVAL_PATCHLINE", "REVIVAL_BUILD_ID",
    "REVIVAL_RELEASE_VERSION", "REVIVAL_MANIFEST_SHA256",
    "REVIVAL_HOST_SHA256", "REVIVAL_DLL_SHA256",
)


def build_environment(raw_key, release, *, username="offline", ticket="offline"):
    fields = {"SERVER_IP": "127.0.0.1", "USER_ID": username, "USER_PW": ticket}
    if set(release) != set(RELEASE_KEYS):
        raise ValueError("Exact seven release fields are required; do not invent metadata")
    fields.update((key, release[key]) for key in RELEASE_KEYS)
    for key, value in fields.items():
        if not isinstance(value, str) or not value or any(ch in value for ch in ";=\0\r\n"):
            raise ValueError(f"Invalid or empty launch field: {key}")
    if not ipaddress.ip_address(fields["SERVER_IP"]).is_loopback:
        raise ValueError("Local endpoint required")
    payload = "".join(f"{key}={value};" for key, value in fields.items()).encode("utf-8")
    return {"NMRunEnv_ENUM": "NMRP_DATA", "NMRP_DATA": encode(payload, raw_key),
            "REVIVAL_SERVER_IP": "127.0.0.1"}
