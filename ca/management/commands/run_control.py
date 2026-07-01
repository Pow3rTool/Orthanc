"""Orthanc control listener — the XConnect-only door.

A standalone mTLS HTTP/JSON server (separate process from the web; NOT behind
nginx) that terminates the client cert itself so it can derive the caller's
tenant from the SPIFFE SAN. Every request is hard-scoped to the tenant of the
ACTIVE SystemIdentity the client cert maps to. Bind it to a private interface
and firewall the port (UFW/infra) to XConnect sources only.

    POST /control/v1/hello      -> identity echo (proves the link + scoping)
    POST /control/v1/allowlist  -> ACTIVE node SVIDs for the caller's tenant
    POST /control/v1/sign       -> {csr,purpose:enroll|renew,...} broker CA ops
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
from django.conf import settings
from django.core.management.base import BaseCommand

from ca import authority
from enrollment.models import AgentApp, CallEvent, Enrollment, InFlightCall, SystemIdentity
from enrollment.services import (
    EnrollmentError, authorize, knowledge_append, knowledge_search,
    principal_grants, register, renew, update_for,
)

_SERVER_KEY = "control-server-key.pem"
_SERVER_CERT = "control-server-cert.pem"


def _node_id_from_svid(svid: str) -> str:
    """node UUID = last path segment of spiffe://…/node/<uuid>."""
    svid = svid or ""
    return svid.rstrip("/").split("/")[-1] if "/node/" in svid else ""


def _ensure_server_identity() -> tuple[Path, Path]:
    """Mint the tower's own control-server cert (spiffe://<td>/system/orthanc-control)
    once; XConnect pins our CA and verifies this SPIFFE id."""
    d = Path(settings.CA_DIR)
    key_p, cert_p = d / _SERVER_KEY, d / _SERVER_CERT
    if not (key_p.exists() and cert_p.exists()):
        uri = f"spiffe://{settings.SPIFFE_TRUST_DOMAIN}/system/orthanc-control"
        key_pem, cert_pem, _ = authority.issue_system_cert(uri, ttl_days=365)
        key_p.write_text(key_pem); key_p.chmod(0o600)
        cert_p.write_text(cert_pem)
    return key_p, cert_p


def _spki_fingerprint(cert: x509.Certificate) -> str:
    spki = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(spki).hexdigest()


def _spiffe_id(cert: x509.Certificate) -> str | None:
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        return uris[0] if uris else None
    except x509.ExtensionNotFound:
        return None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        # Control-link access log -> stderr (journald). This was a no-op, which
        # left a blind spot: a compromised XConnect's sign/authorize/whoami calls
        # left NO server-side trace if it lied in /report. Now every request +
        # response code is logged, plus an explicit caller-identity line from
        # do_POST/do_GET. (M2 — audit completeness.)
        sys.stderr.write("[control %s] %s - %s\n" % (
            dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
            self.address_string(), fmt % args))

    def _json(self, code: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _caller(self) -> SystemIdentity | None:
        """Authenticate the client cert -> the ACTIVE SystemIdentity it maps to.
        TLS already proved the cert chains to our CA; here we bind it to a
        registered, non-revoked identity and thus a tenant."""
        der = self.connection.getpeercert(binary_form=True)
        if not der:
            return None
        cert = x509.load_der_x509_certificate(der)
        ident = SystemIdentity.resolve(_spki_fingerprint(cert))
        if ident is not None:
            # Record liveness so the dashboard can show "XConnect last seen Ns ago".
            SystemIdentity.objects.filter(pk=ident.pk).update(
                last_seen=dt.datetime.now(dt.timezone.utc))
        return ident

    # Caps: never let one report balloon memory/DB. A flood is itself a signal,
    # but we bound what a single heartbeat can write.
    _CALLS_PER_BATCH = 500
    _DETAIL_MAX = 4000
    _OUTPUT_MAX = 80000  # slack over XConnect's 64 KiB capture cap

    @staticmethod
    def _as_int(v):
        """Coerce a reported numeric field to int, or None if absent/garbage."""
        if v is None:
            return None
        try:
            return int(v)
        except (TypeError, ValueError):
            return None

    def _clear_stale_inflight(self, caller, instance_id) -> int:
        """Restart-corrective. When an XConnect restarts it mints a fresh
        instance_id, so any 'running' row of THIS identity carrying a different
        instance_id belongs to a process that is provably gone — it can't still be
        running. Clear those (recording an honest 'orphaned' outcome). Scoped to
        the authenticated identity so one XConnect can't clear another's rows. A
        no-op for an XConnect that doesn't report an instance_id (back-compat)."""
        if not instance_id:
            return 0
        stale = InFlightCall.objects.filter(
            system_identity=caller).exclude(instance_id=instance_id)
        return InFlightCall.orphan(stale, status="orphaned", reason="xconnect restarted")

    def _persist_calls(self, caller, calls, now, instance_id="") -> dict:
        """Persist a batch of call events for `caller`'s tenant. Two kinds, split by
        the event's `phase`:

          * phase=="start" → a 'running' row in InFlightCall (transient liveness;
            never a CallEvent). Only emitted for authorized+resolved calls.
          * anything else  → a terminal CallEvent (append-only audit) AND clears the
            matching 'running' row by request_id.

        Hard-scoped to the authenticated control-link identity's tenant — the
        client can't attribute a call elsewhere. Bounded per batch + per field. The
        request_id (`rid`) is the idempotency key: a re-shipped batch (control-link
        requeue) can neither double-write a CallEvent nor resurrect a finished call
        as 'running'."""
        tenant = caller.tenant
        if not isinstance(calls, list) or not calls:
            return {"started": 0, "stored": 0, "cleared": 0}

        started_evs, terminal_evs = [], []
        for c in calls[: self._CALLS_PER_BATCH]:
            if not isinstance(c, dict):
                continue
            (started_evs if c.get("phase") == "start" else terminal_evs).append(c)

        # --- terminal events: append-only CallEvents, deduped by request_id ---
        term_rids = {str(c.get("rid", "")) for c in terminal_evs if c.get("rid")}
        existing_term = set(
            CallEvent.objects.filter(tenant=tenant, request_id__in=term_rids)
            .values_list("request_id", flat=True)) if term_rids else set()
        rows, seen = [], set()
        for c in terminal_evs:
            rid = str(c.get("rid", ""))
            if rid:
                if rid in existing_term or rid in seen:
                    continue  # already persisted (idempotent requeue) — skip
                seen.add(rid)
            occurred = self._parse_ts(c.get("ts")) or now
            rows.append(CallEvent(
                tenant=tenant,
                request_id=rid[:64],
                occurred_at=occurred,
                principal_upn=str(c.get("upn", ""))[:255],
                principal_oid=str(c.get("oid", ""))[:64],
                principal_tid=str(c.get("tid", ""))[:64],
                principal_app=str(c.get("app", ""))[:64],
                principal_app_name=str(c.get("app_name", ""))[:128],
                verb=str(c.get("verb", ""))[:32],
                target=str(c.get("node", ""))[:255],
                target_svid=str(c.get("svid", ""))[:255],
                allowed=bool(c.get("allowed", False)),
                reason=str(c.get("reason", ""))[:255],
                status=str(c.get("status", ""))[:64],
                detail=str(c.get("detail", ""))[: self._DETAIL_MAX],
                http_status=self._as_int(c.get("http_status")),
                rc=self._as_int(c.get("rc")),
                duration_ms=self._as_int(c.get("dur_ms")),
                output=str(c.get("output", ""))[: self._OUTPUT_MAX],
                output_truncated=bool(c.get("output_truncated", False)),
            ))
        if rows:
            CallEvent.objects.bulk_create(rows)

        # A finished call is no longer 'running' — clear its in-flight row.
        cleared = 0
        if term_rids:
            cleared = InFlightCall.objects.filter(
                tenant=tenant, request_id__in=term_rids).delete()[0]

        # --- start events: upsert 'running' rows (skip if the call already ended) ---
        started = 0
        for c in started_evs:
            rid = str(c.get("rid", ""))
            if not rid:
                continue  # a start with no correlation id can't be tracked/cleared
            # Out-of-order guard: don't resurrect a call whose terminal event landed
            # first (this batch, or an earlier one).
            if rid in existing_term or rid in seen or \
                    CallEvent.objects.filter(tenant=tenant, request_id=rid).exists():
                continue
            InFlightCall.objects.update_or_create(
                request_id=rid[:64],
                defaults=dict(
                    tenant=tenant,
                    system_identity=caller,
                    instance_id=str(instance_id or c.get("instance_id", ""))[:64],
                    principal_upn=str(c.get("upn", ""))[:255],
                    principal_oid=str(c.get("oid", ""))[:64],
                    principal_tid=str(c.get("tid", ""))[:64],
                    principal_app=str(c.get("app", ""))[:64],
                    principal_app_name=str(c.get("app_name", ""))[:128],
                    verb=str(c.get("verb", ""))[:32],
                    target=str(c.get("node", ""))[:255],
                    target_svid=str(c.get("svid", ""))[:255],
                    detail=str(c.get("detail", ""))[: self._DETAIL_MAX],
                    started_at=self._parse_ts(c.get("ts")) or now,
                ))
            started += 1

        # Discover the agent apps seen in this batch — auto-seed (name=GUID) so a
        # new harness shows up in the console to be renamed. Same spirit as how a
        # calling principal is discovered on first contact.
        for app in {str(c.get("app", "")) for c in started_evs + terminal_evs if c.get("app")}:
            AgentApp.touch(app)

        return {"started": started, "stored": len(rows), "cleared": cleared}

    @staticmethod
    def _parse_ts(s):
        """Parse an XConnect-stamped RFC3339 timestamp; None on anything off."""
        if not s or not isinstance(s, str):
            return None
        try:
            return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None

    def _principal_kwargs(self, body):
        """Principal kwargs for authZ. When OBO validation is on (default once
        OBO_AUDIENCE is configured), derive them from the INDEPENDENTLY re-verified
        forwarded token — not from XConnect's asserted claims — and return None on
        any failure so callers fail CLOSED (deny). When off (dev), trust the
        asserted claims."""
        from django.conf import settings
        if not settings.OBO_VALIDATE_TOKEN:
            return dict(
                principal_upn=body.get("principal_upn", ""),
                principal_oid=body.get("principal_oid", ""),
                principal_tid=body.get("principal_tid", ""),
                principal_name=body.get("principal_name", ""),
                principal_groups=body.get("principal_groups", []) or [],
                # Dev mode trusts the asserted azp; validate-mode re-derives it from
                # the verified token (obo.validate) so the agent gate can't be spoofed.
                principal_app=body.get("principal_app", ""))
        from enrollment import obo
        try:
            return obo.validate(body.get("principal_token", ""))
        except obo.OBOError as exc:
            self.log_message("OBO token validation failed: %s", exc)
            return None

    def do_POST(self):
        # Cap the declared body so a bogus/huge Content-Length can't make us
        # allocate unbounded memory (this is a raw HTTP server, with none of
        # Django's DATA_UPLOAD_MAX_MEMORY_SIZE protection). Control payloads
        # (CSRs, audit batches) are well under this. Reject oversized bodies
        # without draining, and close the connection so we don't try to parse
        # the (unread) remainder as a pipelined request.
        max_body = 32 << 20  # 32 MB
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length < 0 or length > max_body:
            self.close_connection = True
            return self._json(413, {"error": "request body too large"})
        # Always drain the request body FIRST — even on rejection — or leftover
        # bytes get parsed as the next request on a kept-alive HTTP/1.1 connection.
        raw = self.rfile.read(length) if length else b""

        caller = self._caller()
        # Forensic breadcrumb: WHICH system identity (or an unknown cert) hit WHICH
        # route — independent of whatever the caller self-reports in /report.
        self.log_message("POST %s caller=%s", self.path,
                         caller.spiffe_id if caller else "UNKNOWN-CERT")
        if caller is None:
            return self._json(403, {"error": "client cert is not a known/active system identity"})

        try:
            body = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            return self._json(400, {"error": "body must be JSON"})

        route = self.path.rstrip("/")
        if route == "/control/v1/hello":
            return self._json(200, {
                "ok": True,
                "your_spiffe_id": caller.spiffe_id,
                "tenant": caller.tenant.slug if caller.tenant else None,
                "role": caller.role,
                "server_time": dt.datetime.now(dt.timezone.utc).isoformat(),
            })

        if route == "/control/v1/revstate":
            # Cheap revocation signal for XConnect's FAST revocation poll: the
            # monotonic count of revoked enrollments for this tenant (revoked rows
            # persist, so it only ever increases). XConnect polls this often (O(1),
            # not the heavy allow-list) and does a full refresh + tunnel reconcile
            # only when it climbs — bounding revoke→tunnel-kill to the poll interval
            # without dialing down (the plane split: Orthanc never pushes).
            if caller.tenant is None:
                return self._json(403, {"error": "tower-global identity has no tenant"})
            n = Enrollment.objects.filter(
                tenant=caller.tenant, state=Enrollment.State.REVOKED).count()
            return self._json(200, {"revoked": n})

        if route == "/control/v1/allowlist":
            if caller.tenant is None:
                return self._json(403, {"error": "tower-global identity has no tenant allow-list"})
            nodes = [
                {"svid": e.spiffe_id, "spki_fingerprint": e.spki_fingerprint,
                 "bound_name": e.bound_name, "description": e.description,
                 "not_after": e.cert_not_after.isoformat() if e.cert_not_after else None}
                for e in Enrollment.objects.filter(
                    tenant=caller.tenant, state=Enrollment.State.ACTIVE).select_related("tenant")
            ]
            return self._json(200, {
                "tenant": caller.tenant.slug,
                "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "count": len(nodes), "nodes": nodes,
            })

        if route == "/control/v1/report":
            # XConnect reports its currently-live reverse-tunnels for this tenant
            # (liveness + per-node running version/arch). Accepts the legacy format
            # (list of svid strings) OR the rich format (list of
            # {svid, version, goarch}) so a not-yet-upgraded XConnect still works.
            # Returns pending operator update-nudges (SVIDs) for this tenant — the
            # PULL side of the console "update now" button.
            if caller.tenant is None:
                return self._json(403, {"error": "tower-global identity has no tenant"})
            now = dt.datetime.now(dt.timezone.utc)
            norm = []
            for it in (body.get("tunnels", []) or []):
                if isinstance(it, str):
                    norm.append({"svid": it})
                elif isinstance(it, dict) and it.get("svid"):
                    norm.append(it)

            def _nid(svid):  # node UUID = last path segment of …/node/<uuid>
                return svid.rstrip("/").split("/")[-1] if "/node/" in svid else None

            live_ids = [n for n in (_nid(x["svid"]) for x in norm) if n]
            updated = Enrollment.objects.filter(
                tenant=caller.tenant, state=Enrollment.State.ACTIVE, id__in=live_ids
            ).update(last_tunnel_at=now)
            # Per-node runtime version/arch where the (upgraded) XConnect reported it.
            for x in norm:
                nodeid = _nid(x["svid"])
                if not nodeid or not x.get("version"):
                    continue
                Enrollment.objects.filter(tenant=caller.tenant, id=nodeid).update(
                    running_version=str(x.get("version", ""))[:40],
                    running_goarch=str(x.get("goarch", ""))[:20],
                    last_report_at=now)
            # Persist any audit/call events in this batch (the Witchhunt log) +
            # update the 'running' set. HARD-SCOPED to the reporting XConnect's
            # tenant. The instance_id drives the restart-corrective: clear any
            # 'running' rows left by a prior incarnation of THIS XConnect first.
            inst = str(body.get("instance_id", ""))[:64]
            self._clear_stale_inflight(caller, inst)
            counts = self._persist_calls(caller, body.get("calls", []) or [], now, inst)
            stored = counts["stored"]
            # Hand out operator-requested update nudges (as SVIDs), then clear them.
            pend = list(Enrollment.objects.filter(
                tenant=caller.tenant, state=Enrollment.State.ACTIVE, update_requested=True))
            pending = [e.spiffe_id for e in pend]
            if pend:
                Enrollment.objects.filter(id__in=[e.id for e in pend]).update(update_requested=False)
            return self._json(200, {"ok": True, "reported": len(norm), "updated": updated,
                                    "calls_stored": stored, "pending_nudges": pending})

        if route == "/control/v1/calllog":
            # Low-latency audit ship: XConnect flushes buffered call events here
            # within ~200ms of a call (vs waiting for the heartbeat), so the
            # Witchhunt log feels live. Persist-ONLY — no tunnel liveness / nudge
            # side effects (those stay on /report), so a fast flush can't race or
            # clobber the nudge-clear path.
            if caller.tenant is None:
                return self._json(403, {"error": "tower-global identity has no tenant"})
            now = dt.datetime.now(dt.timezone.utc)
            inst = str(body.get("instance_id", ""))[:64]
            self._clear_stale_inflight(caller, inst)
            counts = self._persist_calls(caller, body.get("calls", []) or [], now, inst)
            return self._json(200, {"ok": True, "calls_stored": counts["stored"],
                                    "started": counts["started"], "cleared": counts["cleared"]})

        if route == "/control/v1/whoami":
            if caller.tenant is None:
                return self._json(403, {"error": "tower-global identity has no tenant"})
            pr = self._principal_kwargs(body)
            if pr is None:
                return self._json(403, {"error": "OBO token validation failed"})
            return self._json(200, principal_grants(tenant=caller.tenant, **pr))

        if route == "/control/v1/authorize":
            # XConnect asks: may this OBO principal exercise <verb> (on a node of
            # this tenant)? Runs on every call — bounds even background OBO use.
            # The principal is derived from the INDEPENDENTLY-verified OBO token.
            if caller.tenant is None:
                return self._json(403, {"error": "tower-global identity cannot authorize"})
            pr = self._principal_kwargs(body)
            if pr is None:
                return self._json(403, {"allowed": False, "reason": "OBO token validation failed"})
            decision = authorize(tenant=caller.tenant, verb=body.get("verb", ""), **pr)
            return self._json(200, decision)

        if route in ("/control/v1/knowledge/search", "/control/v1/knowledge/append"):
            # The shared "wiki for agents". XConnect relays the OBO principal + the
            # resolved node SVID; we authorize (which also discovers the principal),
            # then read/write Postgres. Provenance is stamped server-side from the
            # principal — never from the client.
            if caller.tenant is None:
                return self._json(403, {"error": "tower-global identity has no tenant"})
            writing = route.endswith("/append")
            verb = "knowledge_write" if writing else "knowledge_read"
            pr = self._principal_kwargs(body)
            if pr is None:
                return self._json(403, {"error": "not authorized",
                                        "reason": "OBO token validation failed"})
            decision = authorize(tenant=caller.tenant, verb=verb, **pr)
            if not decision.get("allowed"):
                return self._json(403, {"error": "not authorized",
                                        "reason": decision.get("reason", "")})
            node_id = _node_id_from_svid(body.get("svid", "")) or body.get("node_id", "") or ""
            if writing:
                try:
                    return self._json(200, knowledge_append(
                        tenant=caller.tenant, node_id=node_id,
                        content=body.get("content", ""),
                        principal_oid=pr["principal_oid"],   # verified provenance
                        principal_upn=pr["principal_upn"],
                        source="agent"))  # OBO path is always agent-sourced
                except EnrollmentError as exc:
                    return self._json(400, {"error": str(exc)})
            return self._json(200, knowledge_search(
                tenant=caller.tenant, node_id=node_id, query=body.get("query", "")))

        if route == "/control/v1/enroll_status":
            # Poll an enrollment (by id, hard-scoped to the caller's tenant).
            # Returns the signed cert + trust bundle once an operator approves —
            # the node-bootstrap poll, relayed by XConnect's /bootstrap door.
            if caller.tenant is None:
                return self._json(403, {"error": "tower-global identity has no tenant"})
            e = Enrollment.objects.filter(
                tenant=caller.tenant, id=body.get("enrollment_id", "") or None
            ).select_related("tenant").first()
            if e is None:
                return self._json(404, {"error": "no such enrollment for this tenant"})
            out = {"state": e.state, "spiffe_id": e.spiffe_id, "bound_name": e.bound_name}
            if e.state == Enrollment.State.ACTIVE:
                out["certificate"] = e.cert_pem
                out["trust_bundle"] = authority.trust_bundle_pem()
                out["not_after"] = e.cert_not_after.isoformat() if e.cert_not_after else None
            return self._json(200, out)

        if route == "/control/v1/update_for":
            # XConnect asks (on a node's behalf, on tunnel-up or a nudge): is this
            # node behind its channel's target? If so, return the SIGNED binary to
            # relay down the tunnel. The node verifies the Ed25519 signature itself.
            if caller.tenant is None:
                return self._json(403, {"error": "tower-global identity has no tenant"})
            svid = body.get("svid", "") or ""
            node_id = svid.rstrip("/").split("/")[-1] if "/node/" in svid else (body.get("node_id", "") or "")
            return self._json(200, update_for(
                tenant=caller.tenant, node_id=node_id,
                current_version=body.get("current_version", "") or "",
                goos=body.get("goos", "") or "", goarch=body.get("goarch", "") or ""))

        if route == "/control/v1/sign":
            if caller.tenant is None:
                return self._json(403, {"error": "tower-global identity cannot broker signing"})
            csr = body.get("csr")
            purpose = body.get("purpose")
            if not csr:
                return self._json(400, {"error": "csr required"})
            try:
                if purpose == "enroll":
                    e = register(tenant_slug=caller.tenant.slug, csr_pem=csr,
                                 join_token_raw=body.get("join_token", ""),
                                 requested_name=body.get("name", ""))
                    return self._json(200, {"state": e.state, "enrollment_id": str(e.id),
                                            "spiffe_id": e.spiffe_id})
                if purpose == "renew":
                    e = renew(tenant=caller.tenant, csr_pem=csr)
                    return self._json(200, {"state": e.state, "certificate": e.cert_pem,
                                            "spiffe_id": e.spiffe_id,
                                            "not_after": e.cert_not_after.isoformat()})
                return self._json(400, {"error": "purpose must be 'enroll' or 'renew'"})
            except EnrollmentError as exc:
                return self._json(400, {"error": str(exc)})

        return self._json(404, {"error": "no such control method"})


class Command(BaseCommand):
    help = "Run the XConnect-only mTLS control listener (separate from the web)."

    def add_arguments(self, parser):
        parser.add_argument("--bind", default="127.0.0.1")
        parser.add_argument("--port", type=int, default=8443)

    def handle(self, *args, **opts):
        from django.conf import settings
        from django.core.management.base import CommandError
        # Fail closed: if OBO validation is enabled but unconfigured, every authZ
        # call would deny (or we'd silently trust XConnect) — refuse to start
        # instead, mirroring the SECRET_KEY guard.
        if settings.OBO_VALIDATE_TOKEN and not (settings.OBO_TENANT_ID and settings.OBO_AUDIENCE):
            raise CommandError(
                "OBO token validation is ON but ORTHANC_OBO_TENANT_ID / ORTHANC_OBO_AUDIENCE "
                "are not set (the XConnect API app's tenant + audience). Set them, or set "
                "ORTHANC_OBO_VALIDATE_TOKEN=false to run without independent validation (NOT recommended).")
        if not settings.OBO_VALIDATE_TOKEN:
            self.stdout.write(self.style.WARNING(
                "WARNING: OBO token validation is OFF — the control plane trusts XConnect's "
                "asserted principal verbatim. Set ORTHANC_OBO_AUDIENCE to enable independent validation."))

        key_p, cert_p = _ensure_server_identity()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # TLS 1.3 only — both peers are ours (XConnect Go client), so there's no
        # legacy compat to keep; refuse anything older.
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(certfile=str(cert_p), keyfile=str(key_p))
        # Pin OUR CA as the only acceptable client-cert issuer; require a client cert.
        ctx.load_verify_locations(cadata=authority.trust_bundle_pem())
        ctx.verify_mode = ssl.CERT_REQUIRED

        httpd = ThreadingHTTPServer((opts["bind"], opts["port"]), Handler)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        self.stdout.write(self.style.SUCCESS(
            f"Orthanc control listener (mTLS) on {opts['bind']}:{opts['port']} "
            f"— XConnect-only; firewall this port to XConnect sources."))
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            httpd.shutdown()
