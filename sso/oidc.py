"""MSAL confidential-client wiring for Entra ID SSO.

Authenticates Orthanc to its app registration with a CERTIFICATE credential
(private_key_jwt) — no client secret ever exists. We only ever run the
authorization-code flow for *delegated* sign-in; identity + app-role claims come
back in the ID token, so no Microsoft Graph call (and no Graph permission) is
needed.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import msal
from django.conf import settings


@lru_cache(maxsize=1)
def _client_credential() -> dict:
    key_path = Path(settings.AZURE_CLIENT_CERT_KEY)
    if not key_path.is_absolute():
        key_path = Path(settings.BASE_DIR) / key_path
    return {
        "private_key": key_path.read_text(),
        "thumbprint": settings.AZURE_CLIENT_CERT_THUMBPRINT,
    }


def build_app() -> msal.ConfidentialClientApplication:
    return msal.ConfidentialClientApplication(
        client_id=settings.AZURE_CLIENT_ID,
        authority=settings.AZURE_AUTHORITY,
        client_credential=_client_credential(),
    )


def initiate_auth_code_flow(redirect_uri: str) -> dict:
    """Returns a flow dict (carries state + PKCE verifier) to stash in the session."""
    return build_app().initiate_auth_code_flow(
        scopes=settings.AZURE_SCOPES, redirect_uri=redirect_uri)


def acquire_token_by_auth_code_flow(flow: dict, auth_response: dict) -> dict:
    return build_app().acquire_token_by_auth_code_flow(flow, auth_response)
