"""Resolve a signed-in operator's tier and gate views by tier.

Primary source: the Entra **app-role** claim (`roles`) — e.g. `orthanc.admin`,
mapped via settings.SSO_ROLE_CLAIMS. Individual-user app-role assignment is free
(only group-based assignment needs Entra Premium).

Break-glass override: an Orthanc-local `Operator` row (grant_operator CLI) — lets
you grant access without the portal, or recover if app roles aren't emitting. The
effective tier is the HIGHER of the two sources. Default-deny when neither grants.

Entra authenticates *who* you are; Orthanc still owns the policy of what each tier
may DO (and the fleet-tenant->nodes->verb mapping).
"""
from __future__ import annotations

from functools import wraps

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect

TIER_RANK = {"viewer": 1, "approver": 2, "admin": 3}

SESSION_KEY = "orthanc_operator"


def _highest(tiers) -> str | None:
    tiers = [t for t in tiers if t]
    return max(tiers, key=lambda t: TIER_RANK.get(t, 0)) if tiers else None


def identity_from_claims(claims: dict) -> dict:
    return {
        "oid": claims.get("oid"),
        "name": claims.get("name", ""),
        "upn": claims.get("preferred_username", ""),
        "tid": claims.get("tid"),
    }


def tier_from_app_roles(claims: dict) -> str | None:
    mapping = settings.SSO_ROLE_CLAIMS
    return _highest(mapping[r] for r in claims.get("roles", []) if r in mapping)


def operator_session(claims: dict) -> dict:
    """Session record: authenticated identity + the effective tier (None => denied)."""
    from .models import Operator  # local import to avoid app-loading order issues

    identity = identity_from_claims(claims)
    role_tier = tier_from_app_roles(claims)
    op = Operator.resolve(oid=identity["oid"], upn=identity["upn"])
    db_tier = op.tier if op else None

    identity["tier"] = _highest([role_tier, db_tier])
    identity["tier_sources"] = {"app_role": role_tier, "operator_table": db_tier}
    return identity


def has_tier(operator: dict | None, required: str) -> bool:
    if not operator or not operator.get("tier"):
        return False
    return TIER_RANK.get(operator["tier"], 0) >= TIER_RANK.get(required, 0)


def require_tier(required: str):
    """View decorator: redirect anonymous to login, 403 if under-privileged."""
    def decorator(view):
        @wraps(view)
        def wrapped(request, *args, **kwargs):
            operator = request.session.get(SESSION_KEY)
            if not operator:
                return redirect(f"{settings.LOGIN_URL}?next={request.path}")
            if not has_tier(operator, required):
                raise PermissionDenied(f"requires '{required}' tier")
            return view(request, *args, **kwargs)
        return wrapped
    return decorator
