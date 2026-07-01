#!/usr/bin/env python3
"""Stand-in RCON enrollment client — exercises the Orthanc trust spine end-to-end.

    DEPRECATED: the public POST /<tenant>/register and GET /<tenant>/enroll/<id>
    routes have been REMOVED from Orthanc — enrollment is XConnect-fronted via
    /bootstrap, relayed over the mTLS control link. This script will 404 against a
    current Orthanc. Kept only as a reference for the CSR -> sign -> chain-verify
    shape; the live path is `rcon enroll` -> XConnect `/bootstrap`.

    register: generate an EC device key + CSR, POST /<tenant>/register
    poll    : GET /<tenant>/enroll/<id>; when ACTIVE, save the cert and verify
              (a) the SAN is exactly the expected SPIFFE id, and
              (b) the leaf chains leaf->intermediate->root.

Uses only stdlib + cryptography (no requests), so it runs under the Orthanc venv.
This is a throwaway harness; the real conformance client is RCON/reference.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID


def _post(url: str, payload: dict) -> tuple[int, dict]:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def _get(url: str) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(url) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def cmd_register(args) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    key = ec.generate_private_key(ec.SECP256R1())
    (out / "device-key.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([]))
           .sign(key, hashes.SHA256()))
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

    status, body = _post(f"{args.base}/{args.tenant}/register",
                         {"csr": csr_pem, "join_token": args.token, "name": args.name})
    print(f"register -> HTTP {status}")
    print(json.dumps(body, indent=2))
    if status not in (200, 201):
        return 1
    (out / "enrollment.json").write_text(json.dumps(body))
    print(f"\nfingerprint: {body['spki_fingerprint']}")
    print(f"enroll id  : {body['enrollment_id']}")
    return 0


def cmd_poll(args) -> int:
    out = Path(args.out)
    meta = json.loads((out / "enrollment.json").read_text())
    status, body = _get(f"{args.base}/{args.tenant}/enroll/{meta['enrollment_id']}")
    print(f"poll -> HTTP {status}, state={body.get('state')}")
    if body.get("state") != "active":
        return 2  # not yet approved
    cert_pem = body["certificate"]
    bundle_pem = body["trust_bundle"]
    (out / "device-cert.pem").write_text(cert_pem)
    (out / "trust-bundle.pem").write_text(bundle_pem)

    leaf = x509.load_pem_x509_certificate(cert_pem.encode())
    bundle = _load_chain(bundle_pem)
    root, intermediate = bundle[0], bundle[1]

    # (a) SAN is exactly the expected SPIFFE id
    sans = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    uris = sans.get_values_for_type(x509.UniformResourceIdentifier)
    assert uris == [body["spiffe_id"]], f"SAN {uris} != expected {body['spiffe_id']}"

    # (b) chain: leaf <- intermediate <- root
    leaf.verify_directly_issued_by(intermediate)
    intermediate.verify_directly_issued_by(root)

    print("VERIFIED:")
    print(f"  SAN SPIFFE id : {uris[0]}")
    print(f"  chains to     : {intermediate.subject.rfc4514_string()} <- {root.subject.rfc4514_string()}")
    print(f"  not_after     : {leaf.not_valid_after_utc.isoformat()}")
    print(f"  bound_name    : {body.get('bound_name')}")
    return 0


def _load_chain(pem: str) -> list[x509.Certificate]:
    # bundle is root then intermediate (see authority.trust_bundle_pem)
    certs, buf = [], []
    for line in pem.splitlines(keepends=True):
        buf.append(line)
        if "END CERTIFICATE" in line:
            certs.append(x509.load_pem_x509_certificate("".join(buf).encode()))
            buf = []
    return certs


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--base", default="http://127.0.0.1:8099")
    p.add_argument("--tenant", required=True)
    p.add_argument("--out", default="/tmp/rcon-enroll")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("register")
    r.add_argument("--token", required=True)
    r.add_argument("--name", default="")
    r.set_defaults(func=cmd_register)

    q = sub.add_parser("poll")
    q.set_defaults(func=cmd_poll)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
