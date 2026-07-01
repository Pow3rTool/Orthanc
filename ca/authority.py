"""Orthanc CA front.

This generates a local two-tier CA (a root that signs a short-lived online
intermediate) and signs node CSRs into short-lived leaf certs whose only SAN is
the node's SPIFFE URI:

    spiffe://<trust-domain>/<tenant>/node/<node-id>

Root + intermediate keys live here as plaintext PEM (root-only perms); at-rest
confidentiality is the filer's ZFS dataset encryption, by design. XConnect holds
NO signing key — it only ever consumes the trust bundle (the root) to pin.

Key material lives under settings.CA_DIR (gitignored: *.pem / *.key).
"""
from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django.conf import settings

_ROOT_KEY = "root-key.pem"
_ROOT_CERT = "root-cert.pem"
_INT_KEY = "int-key.pem"
_INT_CERT = "int-cert.pem"

# Root lives long (it's the pinned anchor); intermediate rotates more often.
_ROOT_DAYS = 3650
_INT_DAYS = 365


def _ca_dir() -> Path:
    d = Path(settings.CA_DIR)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _write(path: Path, data: bytes, *, private: bool) -> None:
    path.write_bytes(data)
    path.chmod(0o600 if private else 0o644)


def _name(cn: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Pow3rtool"),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def ensure_ca() -> None:
    """Create the dev root + intermediate if they don't exist yet. Idempotent."""
    d = _ca_dir()
    if (d / _INT_CERT).exists() and (d / _INT_KEY).exists():
        return

    # Root: self-signed CA, the pinned trust anchor.
    root_key = ec.generate_private_key(ec.SECP384R1())
    root_subject = _name("Pow3rtool Root CA")
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_subject)
        .issuer_name(root_subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - dt.timedelta(minutes=5))
        .not_valid_after(_now() + dt.timedelta(days=_ROOT_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA384())
    )

    # Intermediate: the online issuer (pathlen 0 — cannot mint further CAs).
    int_key = ec.generate_private_key(ec.SECP384R1())
    int_subject = _name("Pow3rtool Issuing CA")
    int_cert = (
        x509.CertificateBuilder()
        .subject_name(int_subject)
        .issuer_name(root_cert.subject)
        .public_key(int_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - dt.timedelta(minutes=5))
        .not_valid_after(_now() + dt.timedelta(days=_INT_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(int_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
                       critical=False)
        .sign(root_key, hashes.SHA384())
    )

    # Root + intermediate keys are written as PLAINTEXT PEM (NoEncryption) on
    # purpose: at-rest confidentiality is the filer's ZFS dataset encryption +
    # root-only perms (_write ... private=True). Don't "fix" this to an encrypted
    # PEM — a passphrase sitting on the same host is theatre. (Docs: ARCHITECTURE.md
    # "Private keys at rest".)
    _write(d / _ROOT_KEY, root_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()), private=True)
    _write(d / _ROOT_CERT, root_cert.public_bytes(serialization.Encoding.PEM), private=False)
    _write(d / _INT_KEY, int_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()), private=True)
    _write(d / _INT_CERT, int_cert.public_bytes(serialization.Encoding.PEM), private=False)


def _load_issuer() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    d = _ca_dir()
    key = serialization.load_pem_private_key((d / _INT_KEY).read_bytes(), password=None)
    cert = x509.load_pem_x509_certificate((d / _INT_CERT).read_bytes())
    return key, cert


def trust_bundle_pem() -> str:
    """The anchor RCON/XConnect pin: root + intermediate, PEM concatenated."""
    ensure_ca()
    d = _ca_dir()
    return ((d / _ROOT_CERT).read_text() + (d / _INT_CERT).read_text())


def root_pem() -> str:
    ensure_ca()
    return (_ca_dir() / _ROOT_CERT).read_text()


def ca_pin() -> str:
    """The out-of-band CA pin an operator hands to `rcon enroll --ca-pin`: the
    sha256 of the ROOT CA's SubjectPublicKeyInfo, as "sha256:<hex>". Pinning the
    long-lived root (not the intermediate) survives intermediate rotation. This is
    exactly what RCON's verifyCAPin checks the received trust bundle against, so a
    MITM that swaps in its own CA at enrollment is rejected."""
    ensure_ca()
    cert = x509.load_pem_x509_certificate((_ca_dir() / _ROOT_CERT).read_bytes())
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return "sha256:" + hashlib.sha256(spki).hexdigest()


def _require_strong_key(pubkey) -> None:
    """Reject weak subscriber keys before we sign them. The CA itself is P-384; it
    must not emit a leaf weaker than modern minimums (a 1024-bit RSA / P-192 leaf
    would be a signed-by-us weak identity). Accept EC >= P-256, RSA >= 3072, or
    modern EdDSA; refuse anything else."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
    if isinstance(pubkey, ec.EllipticCurvePublicKey):
        if pubkey.curve.key_size < 256:
            raise ValueError(f"EC key too weak: {pubkey.curve.name} (need >= P-256)")
    elif isinstance(pubkey, rsa.RSAPublicKey):
        if pubkey.key_size < 3072:
            raise ValueError(f"RSA key too weak: {pubkey.key_size}-bit (need >= 3072)")
    elif isinstance(pubkey, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        pass  # modern EdDSA — fine
    else:
        raise ValueError(f"unsupported key type for issuance: {type(pubkey).__name__}")


def sign_csr(csr_pem: str, *, spiffe_uri: str, ttl_hours: int | None = None) -> x509.Certificate:
    """Validate a CSR and issue a short-lived leaf with the SPIFFE URI SAN.

    The leaf carries clientAuth + serverAuth: the RCON is the TLS *client* dialing
    XConnect (clientAuth) but the RPC *server* over the reversed mux (serverAuth).
    """
    ensure_ca()
    ttl = ttl_hours if ttl_hours is not None else settings.NODE_CERT_TTL_HOURS

    csr = x509.load_pem_x509_csr(csr_pem.encode())
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")
    _require_strong_key(csr.public_key())

    issuer_key, issuer_cert = _load_issuer()
    san = x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_uri)])

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))  # identity lives in the SPIFFE SAN, not the subject
        .issuer_name(issuer_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - dt.timedelta(minutes=5))
        .not_valid_after(_now() + dt.timedelta(hours=ttl))
        .add_extension(san, critical=True)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=True, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                       critical=False)
        .sign(issuer_key, hashes.SHA384())
    )
    return cert


def issue_system_cert(spiffe_uri: str, *, ttl_days: int = 365) -> tuple[str, str, str]:
    """Mint a fresh keypair + signed cert for an infrastructure principal (XConnect,
    the control server, ...). Returns (key_pem, cert_pem, spki_fingerprint_hex).

    System identities are operator-gated and longer-lived than node certs (they're
    managed by hand, not auto-renewed over a tunnel). In production the principal
    should generate its own key and submit a CSR; this lab helper generates both
    for bootstrap convenience.
    """
    import hashlib

    ensure_ca()
    key = ec.generate_private_key(ec.SECP384R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([]))
           .sign(key, hashes.SHA384()))
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()
    cert = sign_csr(csr_pem, spiffe_uri=spiffe_uri, ttl_hours=ttl_days * 24)

    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    spki = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return key_pem, cert_pem, hashlib.sha256(spki).hexdigest()


def sign_system_csr(csr_pem: str, *, spiffe_uri: str, ttl_days: int = 365) -> tuple[str, str]:
    """Sign an EXTERNALLY-generated CSR for an infrastructure principal — Orthanc
    never sees the private key (the production path; the principal generates its own
    key + CSR and submits only the CSR). Returns (cert_pem, spki_fingerprint_hex).
    `issue_system_cert` (generates both) is the lab convenience. Mirrors sign_csr."""
    import hashlib

    ensure_ca()
    cert = sign_csr(csr_pem, spiffe_uri=spiffe_uri, ttl_hours=ttl_days * 24)
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    spki = csr.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return cert_pem, hashlib.sha256(spki).hexdigest()


def spki_fingerprint_from_csr(csr_pem: str) -> str:
    """SHA-256 of the CSR public key's SubjectPublicKeyInfo (DER) — the durable
    key identity used to dedupe and to approve-by-fingerprint."""
    import hashlib
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    spki = csr.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()
