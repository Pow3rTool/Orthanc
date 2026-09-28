"""Tests for SSO tier resolution: Entra app-role claim + local operator override."""
from __future__ import annotations

from django.test import TestCase

from .models import Operator
from .roles import has_tier, operator_session, tier_from_app_roles


class TierResolutionTests(TestCase):
    def test_app_role_claim_maps_to_tier(self):
        # Mirrors the real assignment: value "orthanc.admin" in the roles claim.
        s = operator_session({"oid": "u1", "preferred_username": "a@example.test",
                              "roles": ["orthanc.admin"]})
        self.assertEqual(s["tier"], "admin")
        self.assertEqual(s["tier_sources"], {"app_role": "admin", "operator_table": None})

    def test_unknown_app_role_is_ignored(self):
        self.assertIsNone(tier_from_app_roles({"roles": ["some.other.role"]}))

    def test_local_operator_grants_without_app_role(self):
        Operator.objects.create(upn="b@example.test", tier="approver")
        s = operator_session({"oid": "u2", "preferred_username": "b@example.test"})
        self.assertEqual(s["tier"], "approver")
        self.assertEqual(s["tier_sources"]["operator_table"], "approver")

    def test_highest_tier_of_both_sources_wins(self):
        Operator.objects.create(upn="c@example.test", tier="viewer")
        s = operator_session({"oid": "u3", "preferred_username": "c@example.test",
                              "roles": ["orthanc.admin"]})
        self.assertEqual(s["tier"], "admin")  # app_role admin > table viewer

    def test_default_deny_when_neither_source_grants(self):
        s = operator_session({"oid": "u4", "preferred_username": "nobody@example.test"})
        self.assertIsNone(s["tier"])
        self.assertFalse(has_tier(s, "viewer"))

    def test_oid_backfilled_on_first_login(self):
        Operator.objects.create(upn="d@example.test", tier="admin")
        operator_session({"oid": "oid-d", "preferred_username": "d@example.test"})
        self.assertEqual(Operator.objects.get(upn="d@example.test").oid, "oid-d")

    def test_has_tier_is_hierarchical(self):
        self.assertTrue(has_tier({"tier": "admin"}, "approver"))
        self.assertFalse(has_tier({"tier": "viewer"}, "approver"))
        self.assertFalse(has_tier(None, "viewer"))
