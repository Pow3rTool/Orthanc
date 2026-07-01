"""Release signing — the trust root for RCON self-update.

A dedicated **Ed25519** key (separate from the node CA) signs every published
RCON binary. The public key is baked into the RCON binary; RCON verifies the
signature before it ever touches a downloaded update. XConnect only *relays*
signed artifacts down the tunnel — it can never mint one. Unsigned/unverified
self-update would be a fleet-wide RCE backdoor; this is the gate.

Signature covers a canonical manifest line ``version|goos|goarch|sha256hex`` so
a verifier checks the artifact's identity AND its content hash in one shot.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.conf import settings

_KEY = "release-signing-key.pem"
_PUB = "release-signing-pub.pem"


def _dir() -> Path:
    d = Path(settings.CA_DIR)
    d.mkdir(parents=True, exist_ok=True)
    return d


def ensure_release_key() -> Ed25519PrivateKey:
    """Load (or mint once) the Ed25519 release-signing key. Private stays 0600
    under CA_DIR — same custody as the CA; never leaves the control plane."""
    kp = _dir() / _KEY
    if kp.exists():
        return serialization.load_pem_private_key(kp.read_bytes(), password=None)  # type: ignore[return-value]
    key = Ed25519PrivateKey.generate()
    kp.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    kp.chmod(0o600)
    (_dir() / _PUB).write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return key


def public_key_raw_b64() -> str:
    """The 32-byte raw Ed25519 public key, base64 — what to bake into RCON
    (`-ldflags -X main.releasePubKeyB64=…`)."""
    key = ensure_release_key()
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest(version: str, goos: str, goarch: str, sha256: str) -> bytes:
    return f"{version}|{goos}|{goarch}|{sha256}".encode()


def sign(version: str, goos: str, goarch: str, sha256: str) -> str:
    """Return base64 Ed25519 signature over the canonical manifest line."""
    key = ensure_release_key()
    return base64.b64encode(key.sign(_manifest(version, goos, goarch, sha256))).decode()
