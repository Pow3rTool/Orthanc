"""Operator SSO endpoints: /oidc/login, /oidc/callback, /oidc/logout, /oidc/me.

Delegated auth-code flow against Entra. The session holds a compact operator
record (oid, upn, tiers); we don't call Graph and don't persist tokens.
"""
from __future__ import annotations

import urllib.parse

from django.conf import settings
from django.http import HttpResponse, HttpResponseBadRequest, JsonResponse
from django.shortcuts import redirect
from django.utils.html import escape
from django.utils.http import url_has_allowed_host_and_scheme

from . import oidc
from .roles import SESSION_KEY, operator_session

_FLOW_KEY = "oidc_flow"
_NEXT_KEY = "oidc_next"


def _safe_next(request, candidate):
    """Only honor a post-login `next` that points back at THIS site — an
    attacker-supplied absolute URL (//evil.example or https://evil) would be an
    open redirect we could be lured through. Anything off-site falls back to the
    default landing page."""
    if candidate and url_has_allowed_host_and_scheme(
        candidate, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return candidate
    return settings.LOGIN_REDIRECT_URL


def home(request):
    """Authenticated landing — shows the operator's SSO identity and granted tier.
    This is the post-login target (NOT Django's /admin/, which is a separate realm)."""
    op = request.session.get(SESSION_KEY)
    if not op:
        return redirect("oidc-login")
    tier = op.get("tier") or "&mdash; (no tier granted — default-deny)"
    src = op.get("tier_sources", {})
    html = f"""<!doctype html><html><head><title>Orthanc</title>
<style>body{{font-family:system-ui,sans-serif;max-width:48rem;margin:4rem auto;padding:0 1rem;color:#222}}
.card{{border:1px solid #ddd;border-radius:8px;padding:1.25rem 1.5rem}}
.k{{color:#666;display:inline-block;width:9rem}} a{{color:#0a58ca}} code{{background:#f4f4f4;padding:.1rem .3rem;border-radius:4px}}</style>
</head><body>
<h1>Orthanc <small style="color:#888;font-weight:400">· control plane</small></h1>
<div class="card">
<p><span class="k">Signed in as</span> <b>{escape(op.get('name',''))}</b></p>
<p><span class="k">UPN</span> <code>{escape(op.get('upn',''))}</code></p>
<p><span class="k">Tier</span> <b>{tier}</b></p>
<p><span class="k">Tier sources</span> app_role=<code>{escape(str(src.get('app_role')))}</code>,
   operator_table=<code>{escape(str(src.get('operator_table')))}</code></p>
</div>
<p style="margin-top:1.5rem">
<a href="/oidc/me">/oidc/me (json)</a> &nbsp;·&nbsp;
<a href="/oidc/logout">Sign out</a></p>
</body></html>"""
    return HttpResponse(html)


def login(request):
    request.session[_NEXT_KEY] = _safe_next(request, request.GET.get("next"))
    flow = oidc.initiate_auth_code_flow(redirect_uri=settings.AZURE_REDIRECT_URI)
    request.session[_FLOW_KEY] = flow
    return redirect(flow["auth_uri"])


def callback(request):
    flow = request.session.pop(_FLOW_KEY, None)
    if not flow:
        return HttpResponseBadRequest("no auth flow in session (restart login)")
    # MSAL validates state + PKCE + id_token signature/nonce against the flow and
    # RAISES ValueError (not an error dict) on a mismatch. That happens when the
    # session's flow was overwritten by a concurrent /oidc/login (e.g. a stale tab
    # or a background poller) between this login's start and its callback. Treat it
    # as a recoverable "stale flow" and bounce to a fresh login instead of 500ing.
    try:
        result = oidc.acquire_token_by_auth_code_flow(flow, request.GET.dict())
    except ValueError:
        next_url = request.session.pop(_NEXT_KEY, None) or settings.LOGIN_REDIRECT_URL
        return redirect(f"{settings.LOGIN_URL}?next={urllib.parse.quote(next_url)}")
    if "error" in result:
        return HttpResponseBadRequest(
            f"{result.get('error')}: {result.get('error_description', '')}")

    operator = operator_session(result.get("id_token_claims", {}))
    request.session[SESSION_KEY] = operator
    next_url = _safe_next(request, request.session.pop(_NEXT_KEY, None))
    return redirect(next_url)


def logout(request):
    request.session.flush()
    # Bounce through Entra's end-session endpoint so the IdP session clears too.
    post_logout = request.build_absolute_uri("/")
    return redirect(
        f"{settings.AZURE_AUTHORITY}/oauth2/v2.0/logout?"
        + urllib.parse.urlencode({"post_logout_redirect_uri": post_logout}))


def me(request):
    """Tiny debug/whoami endpoint — reflects the current operator session."""
    return JsonResponse(request.session.get(SESSION_KEY) or {"authenticated": False})
