"""Independent OBO-token validation at the control plane.

XConnect validates the OBO bearer at the edge AND forwards it down the (mTLS)
control link. Orthanc re-validates it here against the Entra tenant JWKS, so the
caller's identity is anchored to *Entra's signature* — which Orthanc verifies
itself — rather than to XConnect's word for it.

This is the mitigation for the architecture's central trust fact: without it, a
compromised XConnect (or theft of its service cert) lets an attacker assert any
principal and inherit any grant → fleet RCE. With it, a compromised XConnect can
only RELAY a real, unexpired token (bounded replay within the token's lifetime) —
it cannot fabricate an arbitrary identity. See ARCHITECTURE threat model.
"""
from __future__ import annotations

import threading

import jwt
from django.conf import settings
from jwt import PyJWKClient

_lock = threading.Lock()
_jwks_client: PyJWKClient | None = None


class OBOError(Exception):
    """Raised when a forwarded OBO token fails independent validation."""


def _client() -> PyJWKClient:
    # PyJWKClient caches keys internally; this process (run_control) is long-lived,
    # so we build one client and reuse it across calls.
    global _jwks_client
    with _lock:
        if _jwks_client is None:
            tid = settings.OBO_TENANT_ID
            if not tid:
                raise OBOError("OBO_TENANT_ID not configured")
            _jwks_client = PyJWKClient(
                f"https://login.microsoftonline.com/{tid}/discovery/v2.0/keys")
        return _jwks_client


def _audiences() -> list[str]:
    # Accept the configured audience(s) and their bare (api://-stripped) form,
    # mirroring how XConnect accepts both the App ID URI and the bare app-id GUID.
    out: list[str] = []
    for a in (settings.OBO_AUDIENCE or "").split(","):
        a = a.strip()
        if a:
            out.append(a)
            out.append(a.removeprefix("api://"))
    return out


def validate(token: str) -> dict:
    """Verify signature (tenant JWKS), issuer (v2), audience, expiry, and the
    required delegated scope. Returns the VERIFIED principal kwargs (the same
    shape authorize() expects). Raises OBOError on any failure — callers must
    fail closed (deny) on a raised error."""
    if not token:
        raise OBOError("no token forwarded")
    tid = settings.OBO_TENANT_ID
    auds = _audiences()
    if not auds:
        raise OBOError("OBO_AUDIENCE not configured")
    try:
        signing_key = _client().get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=auds,
            issuer=f"https://login.microsoftonline.com/{tid}/v2.0",
            options={"require": ["exp", "iss", "aud"]},
        )
    except OBOError:
        raise
    except Exception as exc:  # jwt.* errors + JWKS fetch failures
        raise OBOError(f"token invalid: {exc}") from exc

    scopes = (claims.get("scp") or "").split()
    required = settings.OBO_REQUIRED_SCOPE
    if required and required not in scopes:
        raise OBOError(f"missing required scope {required!r}")

    return {
        "principal_upn": claims.get("preferred_username") or claims.get("upn") or "",
        "principal_oid": claims.get("oid", ""),
        "principal_tid": claims.get("tid", ""),
        "principal_name": claims.get("name", ""),
        "principal_groups": claims.get("groups", []) or [],
        # The AGENT (harness) — the OAuth client app this token was issued to.
        # Derived from the INDEPENDENTLY-validated token so the agent-jail gate
        # can't be spoofed by a compromised broker asserting a fake azp.
        "principal_app": claims.get("azp") or claims.get("appid") or "",
    }
