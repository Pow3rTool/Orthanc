"""Regression tests for the Witchhunt in-flight ('running') tracking.

Covers the ingest routing (start->InFlightCall, terminal->CallEvent+clear), the
idempotency/out-of-order guards, the restart-corrective (instance-epoch clear),
the TTL sweep, and the live-tail feed shape. The control endpoint is a raw
BaseHTTPRequestHandler, so we exercise its persistence helpers directly (they
touch no connection state) rather than standing up the TLS server.
"""
from __future__ import annotations

from django.core.management import call_command
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from ca.management.commands.run_control import Handler
from sso.roles import SESSION_KEY
from .models import (
    AgentApp, CallEvent, Enrollment, Grant, InFlightCall, Principal,
    SystemIdentity, Tenant,
)
from .services import authorize


def _iso(dt):
    return dt.isoformat()


class InFlightIngestTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug="acme", name="Acme")
        self.xc = SystemIdentity.objects.create(
            role="xconnect", tenant=self.tenant,
            spiffe_id="spiffe://pow3rtool/acme/system/xconnect/1",
            spki_fingerprint="a" * 64, is_active=True)
        self.h = Handler.__new__(Handler)  # no __init__: helpers need no socket
        self.now = timezone.now()

    def _start(self, rid, **kw):
        e = {"phase": "start", "rid": rid, "ts": _iso(self.now),
             "upn": "alice@example.test", "oid": "oid-a", "verb": "run",
             "app": "agent-guid-1", "app_name": "Ops Agent",
             "node": "web1", "svid": "spiffe://pow3rtool/acme/node/n1",
             "detail": "sleep 5"}
        e.update(kw)
        return e

    def _end(self, rid, **kw):
        e = {"rid": rid, "ts": _iso(self.now), "upn": "alice@example.test",
             "oid": "oid-a", "verb": "run", "app": "agent-guid-1",
             "app_name": "Ops Agent", "node": "web1",
             "svid": "spiffe://pow3rtool/acme/node/n1", "allowed": True,
             "status": "ok", "rc": 0, "dur_ms": 5000, "detail": "sleep 5"}
        e.update(kw)
        return e

    def test_start_creates_inflight_not_callevent(self):
        counts = self.h._persist_calls(self.xc, [self._start("r1")], self.now, "inst-1")
        self.assertEqual(counts["started"], 1)
        self.assertEqual(CallEvent.objects.count(), 0)
        row = InFlightCall.objects.get(request_id="r1")
        self.assertEqual(row.tenant, self.tenant)
        self.assertEqual(row.system_identity, self.xc)
        self.assertEqual(row.instance_id, "inst-1")
        self.assertEqual(row.verb, "run")
        self.assertEqual(row.target, "web1")
        self.assertEqual(row.principal_app, "agent-guid-1")
        self.assertEqual(row.agent_label, "Ops Agent (agent-gu)")

    def test_terminal_creates_callevent_and_clears_inflight(self):
        self.h._persist_calls(self.xc, [self._start("r1")], self.now, "inst-1")
        counts = self.h._persist_calls(self.xc, [self._end("r1")], self.now, "inst-1")
        self.assertEqual(counts["stored"], 1)
        self.assertEqual(counts["cleared"], 1)
        self.assertFalse(InFlightCall.objects.filter(request_id="r1").exists())
        ev = CallEvent.objects.get(request_id="r1")
        self.assertEqual(ev.status, "ok")
        self.assertEqual(ev.duration_ms, 5000)
        self.assertEqual(ev.principal_app, "agent-guid-1")
        self.assertEqual(ev.principal_app_name, "Ops Agent")

    def test_start_and_end_same_batch_nets_to_completed(self):
        counts = self.h._persist_calls(
            self.xc, [self._start("r1"), self._end("r1")], self.now, "inst-1")
        self.assertEqual(counts["stored"], 1)
        self.assertEqual(InFlightCall.objects.count(), 0)
        self.assertEqual(CallEvent.objects.filter(request_id="r1").count(), 1)

    def test_terminal_is_idempotent_on_request_id(self):
        self.h._persist_calls(self.xc, [self._end("r1")], self.now, "inst-1")
        # re-ship (control-link requeue) the same terminal event
        self.h._persist_calls(self.xc, [self._end("r1")], self.now, "inst-1")
        self.assertEqual(CallEvent.objects.filter(request_id="r1").count(), 1)

    def test_out_of_order_start_does_not_resurrect_finished_call(self):
        # terminal lands first (reordered delivery), then the start shows up late
        self.h._persist_calls(self.xc, [self._end("r1")], self.now, "inst-1")
        counts = self.h._persist_calls(self.xc, [self._start("r1")], self.now, "inst-1")
        self.assertEqual(counts["started"], 0)
        self.assertFalse(InFlightCall.objects.filter(request_id="r1").exists())

    def test_start_without_rid_is_dropped(self):
        ev = self._start("")  # no correlation id -> untrackable
        counts = self.h._persist_calls(self.xc, [ev], self.now, "inst-1")
        self.assertEqual(counts["started"], 0)
        self.assertEqual(InFlightCall.objects.count(), 0)

    def test_legacy_terminal_without_rid_still_audited(self):
        # an XConnect that predates this feature ships no phase/rid
        legacy = {"ts": _iso(self.now), "upn": "bob@example.test", "verb": "read",
                  "node": "db1", "allowed": True, "status": "ok"}
        counts = self.h._persist_calls(self.xc, [legacy], self.now, "")
        self.assertEqual(counts["stored"], 1)
        self.assertEqual(CallEvent.objects.filter(request_id="").count(), 1)


class InFlightCorrectiveTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug="acme", name="Acme")
        self.xc1 = SystemIdentity.objects.create(
            role="xconnect", tenant=self.tenant,
            spiffe_id="spiffe://pow3rtool/acme/system/xconnect/1",
            spki_fingerprint="a" * 64, is_active=True)
        self.xc2 = SystemIdentity.objects.create(
            role="xconnect", tenant=self.tenant,
            spiffe_id="spiffe://pow3rtool/acme/system/xconnect/2",
            spki_fingerprint="b" * 64, is_active=True)
        self.h = Handler.__new__(Handler)
        self.now = timezone.now()

    def _running(self, rid, xc, instance_id, started_at=None):
        return InFlightCall.objects.create(
            tenant=self.tenant, request_id=rid, system_identity=xc,
            instance_id=instance_id, principal_upn="alice@example.test",
            verb="run", target="web1", detail="sleep 9999",
            started_at=started_at or self.now)

    def test_restart_clears_prior_instance_rows_as_orphaned(self):
        self._running("r1", self.xc1, "old-instance")
        cleared = self.h._clear_stale_inflight(self.xc1, "new-instance")
        self.assertEqual(cleared, 1)
        self.assertFalse(InFlightCall.objects.filter(request_id="r1").exists())
        ev = CallEvent.objects.get(request_id="r1")
        self.assertEqual(ev.status, "orphaned")
        self.assertTrue(ev.allowed)

    def test_restart_clear_is_scoped_to_the_reporting_identity(self):
        self._running("r1", self.xc1, "old")
        self._running("r2", self.xc2, "other")
        self.h._clear_stale_inflight(self.xc1, "new")
        self.assertFalse(InFlightCall.objects.filter(request_id="r1").exists())
        self.assertTrue(InFlightCall.objects.filter(request_id="r2").exists())

    def test_same_instance_rows_survive(self):
        self._running("r1", self.xc1, "inst-1")
        cleared = self.h._clear_stale_inflight(self.xc1, "inst-1")
        self.assertEqual(cleared, 0)
        self.assertTrue(InFlightCall.objects.filter(request_id="r1").exists())

    def test_no_instance_id_is_a_noop(self):
        self._running("r1", self.xc1, "inst-1")
        self.assertEqual(self.h._clear_stale_inflight(self.xc1, ""), 0)
        self.assertTrue(InFlightCall.objects.filter(request_id="r1").exists())

    def test_sweep_orphans_old_rows_only(self):
        old = self.now - timezone.timedelta(minutes=120)
        self._running("old", self.xc1, "inst-1", started_at=old)
        self._running("fresh", self.xc1, "inst-1", started_at=self.now)
        call_command("sweep_inflight", "--minutes", "60")
        self.assertFalse(InFlightCall.objects.filter(request_id="old").exists())
        self.assertTrue(InFlightCall.objects.filter(request_id="fresh").exists())
        ev = CallEvent.objects.get(request_id="old")
        self.assertEqual(ev.status, "orphaned")


class WitchhuntTailFeedTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug="acme", name="Acme")
        self.now = timezone.now()
        session = self.client.session
        session[SESSION_KEY] = {"tier": "viewer", "name": "tester"}
        session.save()

    def test_tail_returns_inflight_snapshot_and_duration(self):
        node = Enrollment.objects.create(
            tenant=self.tenant, state=Enrollment.State.ACTIVE,
            spki_fingerprint="c" * 64, csr_pem="", bound_name="web1-host")
        svid = f"spiffe://pow3rtool/acme/node/{node.id}"
        InFlightCall.objects.create(
            tenant=self.tenant, request_id="r1", instance_id="inst-1",
            principal_upn="alice@example.test", principal_app="agent-guid-1",
            principal_app_name="Ops Agent", verb="run", target=str(node.id),
            target_svid=svid, detail="sleep 5", started_at=self.now)
        CallEvent.objects.create(
            tenant=self.tenant, request_id="r2", occurred_at=self.now,
            principal_upn="bob@example.test", principal_app="agent-guid-2",
            principal_app_name="Deploy Bot", verb="run", target=str(node.id),
            target_svid=svid, allowed=True, status="ok", rc=0,
            duration_ms=4200, detail="uptime")
        resp = self.client.get(reverse("console:witchhunt_tail"), secure=True)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("now", data)
        self.assertEqual(len(data["inflight"]), 1)
        self.assertEqual(data["inflight"][0]["request_id"], "r1")
        self.assertIn("started_iso", data["inflight"][0])
        self.assertEqual(data["inflight"][0]["agent"], "Ops Agent (agent-gu)")
        # bare GUID target resolves to the friendly node name in the feed
        self.assertTrue(data["inflight"][0]["target"].startswith("web1-host ("))
        self.assertEqual(len(data["events"]), 1)
        self.assertEqual(data["events"][0]["dur_ms"], 4200)
        self.assertEqual(data["events"][0]["agent"], "Deploy Bot (agent-gu)")
        self.assertTrue(data["events"][0]["target"].startswith("web1-host ("))

    def test_tail_result_denied_filter_hides_running(self):
        InFlightCall.objects.create(
            tenant=self.tenant, request_id="r1", instance_id="inst-1",
            principal_upn="alice@example.test", verb="run", target="web1",
            started_at=self.now)
        resp = self.client.get(reverse("console:witchhunt_tail"),
                               {"result": "denied"}, secure=True)
        self.assertEqual(resp.json()["inflight"], [])

    def test_curated_agent_name_overrides_token_name_in_feed(self):
        AgentApp.objects.create(app_id="agent-guid-9", name="Turnstone-MCP")
        CallEvent.objects.create(
            tenant=self.tenant, request_id="r9", occurred_at=self.now,
            principal_upn="bob@example.test", principal_app="agent-guid-9",
            principal_app_name="raw token name", verb="run", target="db1",
            allowed=True, status="ok", rc=0, duration_ms=10, detail="uptime")
        data = self.client.get(reverse("console:witchhunt_tail"), secure=True).json()
        ev = [e for e in data["events"] if e["detail"] == "uptime"][0]
        self.assertEqual(ev["agent"], "Turnstone-MCP (agent-gu)")


class AgentAppRegistryTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug="acme", name="Acme")
        self.h = Handler.__new__(Handler)
        self.now = timezone.now()

    def test_touch_autoseeds_name_equals_guid(self):
        AgentApp.touch("guid-abc")
        a = AgentApp.objects.get(app_id="guid-abc")
        self.assertEqual(a.name, "guid-abc")
        self.assertFalse(a.named)               # GUID default is not a real name
        self.assertEqual(a.display_name, "guid-abc")

    def test_touch_is_idempotent(self):
        AgentApp.touch("guid-abc")
        AgentApp.touch("guid-abc")
        self.assertEqual(AgentApp.objects.filter(app_id="guid-abc").count(), 1)

    def test_named_after_rename(self):
        AgentApp.touch("guid-abc")
        a = AgentApp.objects.get(app_id="guid-abc")
        a.name = "Turnstone-MCP"
        a.save()
        self.assertTrue(a.named)
        self.assertEqual(a.display_name, "Turnstone-MCP (guid-abc)")

    def test_ingest_discovers_agent_app(self):
        xc = SystemIdentity.objects.create(
            role="xconnect", tenant=self.tenant,
            spiffe_id="spiffe://pow3rtool/acme/system/xconnect/1",
            spki_fingerprint="a" * 64, is_active=True)
        ev = {"rid": "r1", "ts": self.now.isoformat(), "upn": "a@example.test",
              "app": "discovered-guid", "verb": "run", "node": "web1",
              "allowed": True, "status": "ok"}
        self.h._persist_calls(xc, [ev], self.now, "inst-1")
        self.assertTrue(AgentApp.objects.filter(app_id="discovered-guid").exists())

    def test_agent_edit_renames(self):
        AgentApp.touch("guid-xyz")
        session = self.client.session
        session[SESSION_KEY] = {"tier": "approver", "name": "op"}
        session.save()
        resp = self.client.post(reverse("console:agent_edit"),
                                {"app_id": "guid-xyz", "name": "Deploy Bot",
                                 "description": "the deployer"}, secure=True)
        self.assertEqual(resp.status_code, 302)
        a = AgentApp.objects.get(app_id="guid-xyz")
        self.assertEqual(a.name, "Deploy Bot")
        self.assertEqual(a.description, "the deployer")

    def test_agent_edit_requires_approver(self):
        AgentApp.touch("guid-xyz")
        session = self.client.session
        session[SESSION_KEY] = {"tier": "viewer", "name": "op"}
        session.save()
        resp = self.client.post(reverse("console:agent_edit"),
                                {"app_id": "guid-xyz", "name": "Nope"}, secure=True)
        self.assertEqual(resp.status_code, 403)
        self.assertFalse(AgentApp.objects.get(app_id="guid-xyz").named)


class WitchhuntFilterSearchTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug="acme", name="Acme")
        self.now = timezone.now()
        session = self.client.session
        session[SESSION_KEY] = {"tier": "viewer", "name": "t"}
        session.save()

    def _event(self, rid, **kw):
        d = dict(tenant=self.tenant, request_id=rid, occurred_at=self.now,
                 principal_upn="a@example.test", verb="run", allowed=True, status="ok")
        d.update(kw)
        return CallEvent.objects.create(**d)

    def _tail(self, **params):
        return self.client.get(reverse("console:witchhunt_tail"), params, secure=True).json()

    def test_command_search_matches_detail(self):
        self._event("r1", detail="wget https://example.test/payload")
        self._event("r2", detail="ls -la /tmp")
        d = self._tail(q="wget")
        rids = [e["url"] for e in d["events"]]
        self.assertEqual(len(d["events"]), 1)
        self.assertIn("wget", d["events"][0]["detail"])

    def test_command_search_matches_domain_in_command(self):
        self._event("r1", detail="curl asdf.com")
        self._event("r2", detail="curl example.org")
        d = self._tail(q="asdf.com")
        self.assertEqual(len(d["events"]), 1)

    def test_agent_filter_by_curated_name(self):
        AgentApp.objects.create(app_id="guid-ts", name="Turnstone-MCP")
        self._event("r1", principal_app="guid-ts", detail="a")
        self._event("r2", principal_app="guid-other", detail="b")
        d = self._tail(agent="Turnstone")
        self.assertEqual(len(d["events"]), 1)
        self.assertEqual(d["events"][0]["agent"], "Turnstone-MCP (guid-ts)")

    def test_agent_filter_by_guid(self):
        self._event("r1", principal_app="guid-ts", detail="a")
        self._event("r2", principal_app="guid-other", detail="b")
        d = self._tail(agent="guid-ts")
        self.assertEqual(len(d["events"]), 1)

    def test_node_filter_by_friendly_name(self):
        node = Enrollment.objects.create(
            tenant=self.tenant, state=Enrollment.State.ACTIVE,
            spki_fingerprint="d" * 64, csr_pem="", bound_name="database")
        svid = f"spiffe://pow3rtool/acme/node/{node.id}"
        self._event("r1", target_svid=svid, target=str(node.id), detail="a")
        self._event("r2", target_svid="spiffe://pow3rtool/acme/node/other", detail="b")
        d = self._tail(node="database")
        self.assertEqual(len(d["events"]), 1)


class WitchhuntPageTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug="acme", name="Acme")
        session = self.client.session
        session[SESSION_KEY] = {"tier": "viewer", "name": "t", "upn": "t@example.test"}
        session.save()

    def test_default_is_live_mode(self):
        resp = self.client.get(reverse("console:witchhunt"), secure=True)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Executing now")      # live section marker
        self.assertContains(resp, 'name="q"')           # command search box present

    def test_search_mode_paginates(self):
        CallEvent.objects.create(
            tenant=self.tenant, occurred_at=timezone.now(),
            principal_upn="a@example.test", verb="run", allowed=True, status="ok",
            detail="uptime")
        resp = self.client.get(reverse("console:witchhunt"),
                               {"mode": "search"}, secure=True)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "matching event")     # search/paginated marker

    def test_live_url_redirects_to_merged_page(self):
        resp = self.client.get(reverse("console:witchhunt_live"), secure=True)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("mode=live", resp.url)


class AgentJailTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug="acme", name="Acme")

    def _authz(self, app, verb="run", oid="oid-a"):
        return authorize(tenant=self.tenant, principal_oid=oid,
                         principal_upn="a@example.test", principal_app=app, verb=verb)

    def test_empty_azp_denied_failclosed(self):
        d = self._authz("")
        self.assertFalse(d["allowed"])
        self.assertIn("no agent", d["reason"])

    def test_unknown_agent_autoseeds_pending_and_denied(self):
        d = self._authz("new-guid")
        self.assertFalse(d["allowed"])
        self.assertIn("awaiting operator approval", d["reason"])
        self.assertEqual(AgentApp.objects.get(app_id="new-guid").state,
                         AgentApp.State.PENDING)

    def test_pending_agent_blocked(self):
        AgentApp.objects.create(app_id="p-guid", name="p-guid",
                                state=AgentApp.State.PENDING)
        self.assertFalse(self._authz("p-guid")["allowed"])

    def test_denied_agent_blocked(self):
        AgentApp.objects.create(app_id="bad-guid", name="Bad",
                                state=AgentApp.State.DENIED)
        d = self._authz("bad-guid")
        self.assertFalse(d["allowed"])
        self.assertIn("denied", d["reason"])

    def test_approved_agent_passes_gate_to_grant_check(self):
        AgentApp.objects.create(app_id="ok-guid", name="OK",
                                state=AgentApp.State.APPROVED)
        d = self._authz("ok-guid")
        # gate passed → now it's the GRANT layer that denies (no grant exists)
        self.assertFalse(d["allowed"])
        self.assertIn("no grant", d["reason"])

    def test_approved_agent_with_grant_allowed(self):
        AgentApp.objects.create(app_id="ok-guid", name="OK",
                                state=AgentApp.State.APPROVED)
        p = Principal.objects.create(oid="oid-a", tid="t", upn="a@example.test")
        Grant.objects.create(tenant=self.tenant, subject_kind=Grant.Kind.USER,
                             subject="oid-a", principal=p,
                             verb_class=Grant.VerbClass.FULL, is_active=True)
        self.assertTrue(self._authz("ok-guid")["allowed"])

    def test_console_approve_and_deny(self):
        AgentApp.touch("c-guid")
        session = self.client.session
        session[SESSION_KEY] = {"tier": "approver", "name": "op", "upn": "op@x"}
        session.save()
        self.client.post(reverse("console:agent_set_state"),
                         {"app_id": "c-guid", "state": "approved", "name": "Cool"},
                         secure=True)
        a = AgentApp.objects.get(app_id="c-guid")
        self.assertEqual(a.state, AgentApp.State.APPROVED)
        self.assertEqual(a.name, "Cool")
        self.client.post(reverse("console:agent_set_state"),
                         {"app_id": "c-guid", "state": "denied"}, secure=True)
        self.assertEqual(AgentApp.objects.get(app_id="c-guid").state,
                         AgentApp.State.DENIED)
