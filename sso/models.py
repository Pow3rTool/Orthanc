"""Operator authZ — Orthanc-local, NOT Entra app roles.

Entra authenticates the human (we trust the `oid`/UPN in the validated token);
Orthanc decides what tier they get. This keeps authZ entirely in our control and
needs no Entra Premium (app roles / group-based assignment / custom directory
roles all want P1+). Default-deny: an authenticated user with no Operator row
gets nothing.
"""
from __future__ import annotations

from django.db import models
from django.utils import timezone


class Operator(models.Model):
    """A human allowed to operate Orthanc, with a coarse tier."""

    class Tier(models.TextChoices):
        VIEWER = "viewer", "Viewer"
        APPROVER = "approver", "Approver"
        ADMIN = "admin", "Admin"

    # UPN is what an admin types to grant access *before* the user has ever
    # logged in; oid (Entra object id, immutable) is backfilled on first login
    # and is the authoritative key thereafter.
    upn = models.EmailField(unique=True)
    oid = models.CharField(max_length=64, unique=True, null=True, blank=True, db_index=True)
    tier = models.CharField(max_length=10, choices=Tier.choices, default=Tier.VIEWER)
    display_name = models.CharField(max_length=200, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(null=True, blank=True)
    granted_by = models.CharField(max_length=200, blank=True)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.upn} [{self.tier}]"

    @classmethod
    def resolve(cls, *, oid: str | None, upn: str | None) -> "Operator | None":
        """Look up by immutable oid first, then by UPN (backfilling oid on first
        login). Returns None if there is no active operator row (default-deny)."""
        op = None
        if oid:
            op = cls.objects.filter(oid=oid, is_active=True).first()
        if op is None and upn:
            op = cls.objects.filter(upn__iexact=upn, is_active=True).first()
            if op is not None and oid and not op.oid:
                op.oid = oid
                op.save(update_fields=["oid"])
        if op is not None:
            op.last_login = timezone.now()
            op.save(update_fields=["last_login"])
        return op
