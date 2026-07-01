"""Enrollment business logic, shared by the HTTP API and the operator CLI.

Keeping it here (not in views) means `manage.py approve_enrollment` and the
`POST /<tenant>/register` endpoint exercise exactly the same code path.
"""
from __future__ import annotations

from django.db import transaction
from django.utils import timezone

from ca import authority
from .models import (
    CLASS_RANK, KNOWLEDGE_BUDGET_CHARS, KNOWLEDGE_ENTRY_MAX_CHARS,
    VERB_CLASS_REQUIRED, ChannelTarget, Enrollment, Grant, JoinToken,
    NodeKnowledge, Release, Tenant,
)


class EnrollmentError(Exception):
    """Raised for any client-correctable enrollment failure (maps to HTTP 4xx)."""


def _principal_q(principal_oid: str, principal_upn: str, principal_groups):
    """The Grant-match predicate for an OBO principal: by immutable oid (the
    discovered Principal) first, with a legacy fallback to pre-discovery UPN-keyed
    grants (principal still null), plus any group-keyed grants."""
    from django.db.models import Q
    q = Q(pk__in=[])
    if principal_oid:
        q |= Q(subject_kind=Grant.Kind.USER, principal__oid=principal_oid)
    if principal_upn:  # legacy UPN-keyed grants (created before discovery) still honored
        q |= Q(subject_kind=Grant.Kind.USER, principal__isnull=True, subject__iexact=principal_upn)
    if principal_groups:
        q |= Q(subject_kind=Grant.Kind.GROUP, subject__in=principal_groups)
    return q


def authorize(*, tenant, principal_upn: str = "", principal_oid: str = "",
              principal_tid: str = "", principal_name: str = "",
              principal_groups=None, principal_app: str = "", verb: str) -> dict:
    """Default-deny authZ for a Caller's OBO principal: does any active Grant for
    this tenant cover (principal) at >= the verb's required class?

    Returns {"allowed": bool, "reason": str, "require_confirmation": bool}. This
    runs on EVERY call regardless of whether a human is interactively present —
    it's the perimeter that bounds a background/non-interactive OBO Caller. As a
    side-effect it *discovers* the principal (upserts a Principal row) so a brand
    new user is visible + grantable in the console the instant they first knock.

    The AGENT JAIL runs first: the call is also gated on the calling harness (the
    OAuth client app / azp). An unrecognized harness is discovered in a 'pending'
    state and DENIED until an operator approves it — so a trusted user acting
    through an un-vetted agent still can't reach the fabric. `principal_app` is the
    azp the tower re-derived from the validated token (see obo.validate), not a
    value asserted by the broker.
    """
    from .models import AgentApp, Principal
    Principal.seen(oid=principal_oid, tid=principal_tid, upn=principal_upn, name=principal_name)

    # --- Agent jail (fail-closed) ---
    if not principal_app:
        return {"allowed": False, "require_confirmation": False,
                "reason": "no agent (azp) claim on token — cannot identify the "
                          "calling harness"}
    agent = AgentApp.touch(principal_app)  # discover (pending) + bump last_seen
    if agent is None or not agent.approved:
        state = agent.state if agent else "unknown"
        return {"allowed": False, "require_confirmation": False,
                "reason": f"agent '{agent.display_name if agent else principal_app}' "
                          f"is {state} — awaiting operator approval"}

    principal_groups = principal_groups or []
    required = VERB_CLASS_REQUIRED.get(verb, "full")
    need = CLASS_RANK[required]
    q = _principal_q(principal_oid, principal_upn, principal_groups)

    best = None
    for g in Grant.objects.filter(tenant=tenant, is_active=True).filter(q):
        if CLASS_RANK.get(g.verb_class, 0) >= need:
            if best is None or CLASS_RANK[g.verb_class] > CLASS_RANK[best.verb_class]:
                best = g
    if best is None:
        who = principal_upn or principal_oid or "unknown principal"
        return {"allowed": False,
                "reason": f"no grant for '{who}' covering '{verb}' (needs {required}) — "
                          "registered, awaiting access assignment",
                "require_confirmation": False}
    # require_confirmation is a PASS-THROUGH advisory, not enforced here: the bus
    # owns the coarse readonly/full boundary (above); step-up is delegated to the
    # trusted caller (turnstone) which MUST honor this flag. See ARCHITECTURE
    # "Trust boundaries & security decisions".
    return {"allowed": True, "reason": f"grant {best.verb_class} covers {verb}",
            "require_confirmation": best.require_confirmation}


def principal_grants(*, tenant, principal_upn: str = "", principal_oid: str = "",
                     principal_tid: str = "", principal_name: str = "",
                     principal_groups=None, principal_app: str = "") -> dict:
    """Debug/whoami helper: every active Grant in this tenant that applies to the
    principal, plus the effective (highest) verb-class. Also discovers the
    principal (whoami is a call too).

    The AGENT JAIL applies here too (mirrors authorize): whoami must not enumerate
    a principal's effective authorization surface for an un-approved/denied harness
    — that would leak grants past the gate. An un-approved agent gets an empty,
    default-deny answer.
    """
    from .models import AgentApp, Principal
    Principal.seen(oid=principal_oid, tid=principal_tid, upn=principal_upn, name=principal_name)

    # --- Agent jail (fail-closed), before any grant disclosure ---
    def _jailed(reason):
        return {"tenant": tenant.slug, "grants": [], "effective_verb_class": None,
                "default_deny": True, "agent": {"allowed": False, "reason": reason}}
    if not principal_app:
        return _jailed("no agent (azp) claim on token — cannot identify the calling harness")
    agent = AgentApp.touch(principal_app)
    if agent is None or not agent.approved:
        state = agent.state if agent else "unknown"
        return _jailed(f"agent '{agent.display_name if agent else principal_app}' "
                       f"is {state} — awaiting operator approval")

    principal_groups = principal_groups or []
    q = _principal_q(principal_oid, principal_upn, principal_groups)

    grants, best = [], None
    for g in Grant.objects.filter(tenant=tenant, is_active=True).filter(q):
        grants.append({"subject_kind": g.subject_kind, "subject": g.subject,
                       "verb_class": g.verb_class, "require_confirmation": g.require_confirmation})
        if best is None or CLASS_RANK[g.verb_class] > CLASS_RANK[best]:
            best = g.verb_class
    return {"tenant": tenant.slug, "grants": grants, "effective_verb_class": best,
            "default_deny": best is None,
            "agent": {"allowed": True, "name": agent.display_name}}


def update_for(*, tenant, node_id: str, current_version: str, goos: str, goarch: str) -> dict:
    """Resolve the self-update target for a node (its channel's ChannelTarget).

    Returns ``{update: bool, ...}``. When an update is due, includes the signed
    artifact (``version``, ``sha256``, ``signature``, ``binary_b64``) — XConnect
    relays it down the tunnel and RCON verifies the Ed25519 signature against its
    baked key before swapping. The binary is re-hashed here as a belt-and-braces
    integrity check against on-disk corruption.
    """
    import base64
    from pathlib import Path
    from django.conf import settings

    e = Enrollment.objects.filter(
        tenant=tenant, id=node_id or None, state=Enrollment.State.ACTIVE).first()
    if e is None:
        return {"update": False, "reason": "unknown or inactive node"}
    ct = ChannelTarget.objects.filter(
        channel=e.update_channel, goos=goos, goarch=goarch).select_related("release").first()
    if ct is None:
        return {"update": False, "channel": e.update_channel,
                "reason": f"no target for channel '{e.update_channel}' {goos}/{goarch}"}
    rel: Release = ct.release
    if rel.version == current_version:
        return {"update": False, "channel": e.update_channel, "version": rel.version}
    try:
        data = (Path(settings.CA_DIR) / rel.blob_path).read_bytes()
    except OSError:
        return {"update": False, "reason": "release blob missing on disk"}
    if releases_sha(data) != rel.sha256:
        return {"update": False, "reason": "release blob hash mismatch — refusing to serve"}
    return {
        "update": True, "channel": e.update_channel, "version": rel.version,
        "sha256": rel.sha256, "signature": rel.signature,
        "binary_b64": base64.b64encode(data).decode(),
    }


def releases_sha(data: bytes) -> str:
    from ca import releases
    return releases.sha256_hex(data)


# ---------------------------------------------------------------------------
# Node knowledge — the shared "wiki for agents".
#
# XConnect relays /control/v1/knowledge/{search,append} here; it never touches
# the DB. The control endpoint authorizes (knowledge_read / knowledge_write) and
# discovers the principal BEFORE calling these, so by the time we're here the
# caller is allowed — we still take the principal fields to stamp provenance.
# ---------------------------------------------------------------------------

def _resolve_node(tenant, node_id: str) -> "Enrollment | None":
    if not node_id:
        return None
    return Enrollment.objects.filter(tenant=tenant, id=node_id).first()


def _node_active_chars(tenant, node) -> int:
    """Total chars of this node's ACTIVE knowledge — the budget meter."""
    return sum(len(c) for c in NodeKnowledge.objects
               .filter(tenant=tenant, node=node, state=NodeKnowledge.State.ACTIVE)
               .values_list("content", flat=True))


def _similar_nodes(tenant, node, limit: int = 3):
    """L2 candidates: other ACTIVE nodes in the tenant whose name/role looks like
    this node's, for 'a sibling box knew X — may apply here too' inference.

    Lab-scale name similarity in Python (difflib over a bounded candidate set).
    This is the seam where pg_trgm (in-Postgres) and later pgvector +
    qwen3-embedding take over at fleet scale (P3); the result shape is identical,
    so swapping the ranker later is local to this function.
    """
    import difflib

    mine = (node.bound_name or node.requested_name or "").lower()
    others = list(Enrollment.objects.filter(
        tenant=tenant, state=Enrollment.State.ACTIVE
    ).exclude(pk=node.pk)[:200])  # bounded scan; fine for the lab, capped for safety
    scored = []
    for o in others:
        name = (o.bound_name or o.requested_name or "").lower()
        # Same explicit role is a strong signal; otherwise fuzzy name overlap.
        if node.role and o.role and node.role == o.role:
            score = 1.0
        elif mine and name:
            score = difflib.SequenceMatcher(None, mine, name).ratio()
        else:
            score = 0.0
        if score >= 0.6:
            scored.append((score, o))
    scored.sort(key=lambda t: t[0], reverse=True)
    return [o for _, o in scored[:limit]]


def knowledge_search(*, tenant, node_id: str = "", query: str = "", limit: int = 50) -> dict:
    """Layered read of a node's knowledge (XConnect → agent).

    L0 critical_core — operator-curated, always returned (node + matching role +
        tenant-wide). The anti-outage floor; survives whatever MCP client is wired.
    L1 node_knowledge — this node's current ACTIVE entries (newest first, bounded).
    L2 similar_nodes — inferred from like-named/same-role siblings; labelled
        "may not apply".

    `over_budget` trips when the node's ACTIVE knowledge exceeds the soft cap —
    a curation signal for a platform engineer (compaction is deferred by design).
    """
    node = _resolve_node(tenant, node_id)
    if node is None:
        return {"error": "unknown or inactive node for this tenant", "node_id": node_id}

    NK = NodeKnowledge
    active = NK.objects.filter(tenant=tenant, state=NK.State.ACTIVE)

    # L0 — critical core: this node, OR this node's role (node-less), OR tenant-wide.
    from django.db.models import Q
    core_q = Q(node=node)
    if node.role:
        core_q |= Q(node__isnull=True, role=node.role)
    core_q |= Q(node__isnull=True, role="")  # tenant-wide critical core
    l0 = list(active.filter(critical=True).filter(core_q).order_by("-created_at")[:limit])

    # L1 — this node's non-critical current state (critical ones already in L0).
    l1 = list(active.filter(node=node, critical=False).order_by("-created_at")[:limit])

    # Optional query focus (substring) — keep it simple; semantic search is P3.
    if query:
        ql = query.lower()
        l1 = [k for k in l1 if ql in k.content.lower()] or l1  # never empty out L1 on a miss

    # L2 — similar-node inferred (best-effort; never the reason a search fails).
    l2 = []
    try:
        for sib in _similar_nodes(tenant, node):
            for k in active.filter(node=sib).order_by("-critical", "-created_at")[:2]:
                d = k.as_dict()
                d["from_node"] = sib.bound_name or sib.requested_name or sib.node_id
                d["caveat"] = "from a similar node — may not apply"
                l2.append(d)
    except Exception:  # pragma: no cover - L2 is advisory; degrade silently
        l2 = []

    node_chars = _node_active_chars(tenant, node)
    return {
        "node_id": node.node_id,
        "node_name": node.bound_name or node.requested_name,
        "role": node.role,
        "critical_core": [k.as_dict() for k in l0],
        "node_knowledge": [k.as_dict() for k in l1],
        "similar_nodes": l2,
        "active_chars": node_chars,
        "budget": KNOWLEDGE_BUDGET_CHARS,
        "over_budget": node_chars > KNOWLEDGE_BUDGET_CHARS,
        "guidance": (
            "Knowledge over budget — treat as needing curation; a platform engineer "
            "should prune stale/duplicate entries." if node_chars > KNOWLEDGE_BUDGET_CHARS
            else "Heed critical_core. node_knowledge is what prior agents recorded about "
                 "THIS box; similar_nodes is inferred and may not apply."
        ),
    }


@transaction.atomic
def knowledge_append(*, tenant, node_id: str, content: str,
                     principal_oid: str = "", principal_upn: str = "",
                     source: str = "agent", critical: bool = False,
                     severity: str = "", role: str = "") -> dict:
    """Append one knowledge entry to a node. Provenance is stamped here from the
    authenticated principal — NEVER from the client. Agents (source != operator)
    cannot mark an entry `critical` (the L0 core is operator-curated)."""
    node = _resolve_node(tenant, node_id)
    if node is None:
        raise EnrollmentError("unknown or inactive node for this tenant")
    content = (content or "").strip()
    if not content:
        raise EnrollmentError("content required")

    src = source if source in dict(NodeKnowledge.Source.choices) else NodeKnowledge.Source.AGENT
    is_operator = src == NodeKnowledge.Source.OPERATOR
    row = NodeKnowledge.objects.create(
        tenant=tenant,
        node=node,
        role=(role or node.role or "")[:64],
        content=content[:KNOWLEDGE_ENTRY_MAX_CHARS],
        source=src,
        author_oid=(principal_oid or "")[:64],
        author_upn=(principal_upn or "")[:255],
        trust_tier="operator" if is_operator else src,
        # Only operators can seed the always-surfaced critical core.
        critical=bool(critical) and is_operator,
        severity=(severity or "")[:16],
    )
    node_chars = _node_active_chars(tenant, node)
    return {
        "ok": True,
        "id": str(row.id),
        "node_id": node.node_id,
        "stored_chars": len(row.content),
        "truncated": len(content) > KNOWLEDGE_ENTRY_MAX_CHARS,
        "active_chars": node_chars,
        "over_budget": node_chars > KNOWLEDGE_BUDGET_CHARS,
    }


@transaction.atomic
def register(*, tenant_slug: str, csr_pem: str, join_token_raw: str,
             requested_name: str = "", src_ip: str | None = None) -> Enrollment:
    """Enter (or re-confirm) a node in the PENDING queue.

    Idempotent by key: re-registering the same public key returns the existing
    enrollment without spending another token use.
    """
    try:
        tenant = Tenant.objects.get(slug=tenant_slug, is_active=True)
    except Tenant.DoesNotExist:
        raise EnrollmentError("unknown or inactive tenant")

    # Validate the CSR up front and derive the durable key identity.
    try:
        fingerprint = authority.spki_fingerprint_from_csr(csr_pem)
    except Exception as exc:  # malformed CSR / bad key
        raise EnrollmentError(f"invalid CSR: {exc}")

    existing = Enrollment.objects.filter(tenant=tenant, spki_fingerprint=fingerprint).first()
    if existing is not None:
        return existing  # idempotent — don't burn another token use

    # New key: a valid, tenant-matching join token is required to enter the queue.
    token = JoinToken.resolve(join_token_raw) if join_token_raw else None
    if token is None:
        raise EnrollmentError("invalid join token")
    # Lock the row so concurrent registrations can't over-spend max_uses.
    token = JoinToken.objects.select_for_update().select_related("tenant").get(pk=token.pk)
    if token.tenant_id != tenant.id:
        raise EnrollmentError("join token is not valid for this tenant")
    if not token.is_valid():
        raise EnrollmentError("join token is expired, revoked, or spent")

    enrollment = Enrollment.objects.create(
        tenant=tenant,
        spki_fingerprint=fingerprint,
        csr_pem=csr_pem,
        requested_name=requested_name,
        src_ip=src_ip,
        join_token=token,
        state=Enrollment.State.PENDING,
    )
    token.uses += 1
    token.save(update_fields=["uses"])
    return enrollment


@transaction.atomic
def approve(enrollment: Enrollment, *, bound_name: str, approved_by: str = "operator",
            description: str | None = None) -> Enrollment:
    """Operator approval: bind name<->key (immutable) and issue the signed cert.
    Optionally set the human description (intent-mapping for agents) at approval."""
    enrollment = Enrollment.objects.select_for_update().get(pk=enrollment.pk)
    if enrollment.state != Enrollment.State.PENDING:
        raise EnrollmentError(f"cannot approve from state '{enrollment.state}'")
    if not bound_name:
        raise EnrollmentError("a bound name is required at approval")

    cert = authority.sign_csr(enrollment.csr_pem, spiffe_uri=enrollment.spiffe_id)
    from cryptography.hazmat.primitives import serialization

    enrollment.bound_name = bound_name
    if description is not None:
        enrollment.description = description[:255]
    enrollment.cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    enrollment.cert_serial = format(cert.serial_number, "x")
    enrollment.cert_not_after = cert.not_valid_after_utc
    enrollment.state = Enrollment.State.ACTIVE
    enrollment.approved_at = timezone.now()
    enrollment.approved_by = approved_by
    enrollment.save()
    return enrollment


@transaction.atomic
def renew(*, tenant, csr_pem: str) -> Enrollment:
    """Key-continuity renewal: re-issue a fresh cert for an existing ACTIVE node.

    No operator, no join token — the node proves itself by presenting a CSR whose
    key matches an ACTIVE, non-revoked enrollment in this tenant (the SPKI is the
    durable identity). Brokered by XConnect over the control link; same SVID is
    preserved for audit/policy continuity.
    """
    from ca import authority
    from cryptography.hazmat.primitives import serialization

    try:
        fingerprint = authority.spki_fingerprint_from_csr(csr_pem)
    except Exception as exc:
        raise EnrollmentError(f"invalid CSR: {exc}")

    enrollment = (Enrollment.objects.select_for_update()
                  .filter(tenant=tenant, spki_fingerprint=fingerprint).first())
    if enrollment is None:
        raise EnrollmentError("no enrollment matches this key in this tenant")
    if enrollment.state != Enrollment.State.ACTIVE:
        raise EnrollmentError(f"cannot renew from state '{enrollment.state}'")

    cert = authority.sign_csr(csr_pem, spiffe_uri=enrollment.spiffe_id)
    enrollment.cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    enrollment.cert_serial = format(cert.serial_number, "x")
    enrollment.cert_not_after = cert.not_valid_after_utc
    enrollment.save(update_fields=["cert_pem", "cert_serial", "cert_not_after"])
    return enrollment


@transaction.atomic
def revoke(enrollment: Enrollment, *, revoked_by: str = "operator") -> Enrollment:
    """Pull the node from the allow-list. (Killing a live tunnel is XConnect's
    job over the control channel — this is the authoritative state change.)"""
    enrollment = Enrollment.objects.select_for_update().get(pk=enrollment.pk)
    enrollment.state = Enrollment.State.REVOKED
    enrollment.revoked_at = timezone.now()
    enrollment.revoked_by = revoked_by
    enrollment.save(update_fields=["state", "revoked_at", "revoked_by"])
    return enrollment
