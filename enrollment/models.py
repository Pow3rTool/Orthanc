"""Enrollment data model — the trust spine.

Tenants, tenant-scoped join tokens, and the enrollment state machine:

    PENDING --approve(by fingerprint, bind name<->key)--> ACTIVE --> REVOKED

The durable identity of a node is its key (the SPKI fingerprint), never its
self-asserted hostname/IP. The allow-list XConnect enforces is simply the set of
ACTIVE enrollments for a tenant.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid

from django.conf import settings
from django.contrib.postgres.indexes import GinIndex
from django.core.validators import RegexValidator
from django.db import models
from django.utils import timezone

# Tenant slugs are baked into every SPIFFE SVID and the registration URL path,
# so keep them to a conservative DNS-ish lowercase label.
TENANT_SLUG_VALIDATOR = RegexValidator(
    regex=r"^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$",
    message="tenant slug must be 2-40 chars, lowercase alnum/hyphen, no leading/trailing hyphen",
)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Tenant(models.Model):
    """An isolated fleet. The `<tenant>` in spiffe://<trust_domain>/<tenant>/node/<id>."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    slug = models.SlugField(max_length=40, unique=True, validators=[TENANT_SLUG_VALIDATOR])
    name = models.CharField(max_length=200, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.slug


class JoinToken(models.Model):
    """Short-lived, tenant-scoped bootstrap token that gates the PENDING queue.

    Only a SHA-256 hash of the secret is stored; the raw token is shown exactly
    once at mint time (Teleport/k8s bootstrap-token style).
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="join_tokens")
    token_hash = models.CharField(max_length=64, unique=True, db_index=True)
    label = models.CharField(max_length=200, blank=True)
    created_by = models.CharField(max_length=200, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    max_uses = models.PositiveIntegerField(default=1)
    uses = models.PositiveIntegerField(default=0)
    revoked = models.BooleanField(default=False)

    PREFIX = "pjt_"  # pow3rtool join token

    @classmethod
    def mint(cls, *, tenant: Tenant, ttl_minutes: int | None = None,
             max_uses: int = 1, label: str = "", created_by: str = "") -> tuple["JoinToken", str]:
        """Create a token, returning (instance, raw_secret). The raw secret is
        not recoverable afterwards."""
        ttl = ttl_minutes if ttl_minutes is not None else settings.JOIN_TOKEN_TTL_MINUTES
        raw = cls.PREFIX + secrets.token_urlsafe(32)
        tok = cls.objects.create(
            tenant=tenant,
            token_hash=_sha256_hex(raw.encode()),
            label=label,
            created_by=created_by,
            expires_at=timezone.now() + timezone.timedelta(minutes=ttl),
            max_uses=max_uses,
        )
        return tok, raw

    @classmethod
    def resolve(cls, raw: str) -> "JoinToken | None":
        try:
            return cls.objects.select_related("tenant").get(token_hash=_sha256_hex(raw.encode()))
        except cls.DoesNotExist:
            return None

    @property
    def is_spent(self) -> bool:
        return self.uses >= self.max_uses

    def is_valid(self) -> bool:
        return (
            not self.revoked
            and not self.is_spent
            and self.expires_at > timezone.now()
            and self.tenant.is_active
        )


class Enrollment(models.Model):
    """One node's path from CSR to a signed, tenant-scoped device cert."""

    class State(models.TextChoices):
        PENDING = "pending", "Pending"
        ACTIVE = "active", "Active"
        REVOKED = "revoked", "Revoked"
        DENIED = "denied", "Denied"

    # The enrollment id doubles as the stable node-id in the SVID path once approved.
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="enrollments")
    state = models.CharField(max_length=10, choices=State.choices, default=State.PENDING, db_index=True)

    # Durable key identity — SHA-256 of the CSR's SubjectPublicKeyInfo (DER).
    # Unique per tenant: re-registering the same key is idempotent, not a dupe.
    spki_fingerprint = models.CharField(max_length=64, db_index=True)
    csr_pem = models.TextField()

    # Self-asserted at registration (informational only until an operator binds it).
    requested_name = models.CharField(max_length=255, blank=True)
    src_ip = models.GenericIPAddressField(null=True, blank=True)

    # Bound at approval, immutable thereafter.
    bound_name = models.CharField(max_length=255, blank=True)

    # Operator-set, human-meaningful description/role surfaced to callers so an
    # agent can map intent ("the database box") to an opaque hostname
    # (e.g. "host-7q2x"). Free-form; editable. Filterable in host discovery.
    description = models.CharField(max_length=255, blank=True)

    # Self-update cohort. Each channel has its own target version (ChannelTarget),
    # so you can promote a build to "canary"/"dev" (scream-test groups) without
    # touching "stable". Editable. Default keeps a fresh node conservative.
    update_channel = models.CharField(max_length=64, default="stable", db_index=True)

    # Node role/type (e.g. "proxmox-host", "postgres", "web-frontend"). Cheap
    # grouping that lets shared role-knowledge (P2) and critical-core-by-role
    # attach to a class of nodes, and lets a blank-slate scale-set member inherit
    # its peers' playbook. Operator-set, free-form, editable.
    role = models.CharField(max_length=64, blank=True)

    # Issued leaf cert (set at approval / renewal).
    cert_pem = models.TextField(blank=True)
    cert_serial = models.CharField(max_length=64, blank=True)
    cert_not_after = models.DateTimeField(null=True, blank=True)

    join_token = models.ForeignKey(JoinToken, on_delete=models.SET_NULL, null=True, blank=True,
                                   related_name="enrollments")

    created_at = models.DateTimeField(auto_now_add=True)
    approved_at = models.DateTimeField(null=True, blank=True)
    approved_by = models.CharField(max_length=200, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    revoked_by = models.CharField(max_length=200, blank=True)
    # Last time an XConnect reported a live reverse-tunnel for this node.
    last_tunnel_at = models.DateTimeField(null=True, blank=True)

    # Runtime fleet state, reported by XConnect over the control link (the node
    # tells XConnect its /health version on connect; XConnect relays it up). Lets
    # operators SEE running version vs the channel target (drift) without SSH —
    # version is NOT exposed on the agent/MCP surface.
    running_version = models.CharField(max_length=40, blank=True)
    running_goarch = models.CharField(max_length=20, blank=True)
    last_report_at = models.DateTimeField(null=True, blank=True)
    # Operator-requested one-shot update nudge. Orthanc can't dial down to XConnect
    # (control link is XConnect-initiated), so this is a PULL: XConnect picks it up
    # on its next report poll, nudges the node, and Orthanc clears it.
    update_requested = models.BooleanField(default=False)

    class Meta:
        constraints = [
            # Dedupe by key within a tenant (NOT by IP — NAT/shared egress is fine).
            models.UniqueConstraint(fields=["tenant", "spki_fingerprint"],
                                    name="uniq_tenant_spki"),
        ]
        indexes = [models.Index(fields=["tenant", "state"])]

    def __str__(self) -> str:  # pragma: no cover - trivial
        label = self.bound_name or self.requested_name or self.spki_fingerprint[:12]
        return f"{self.tenant.slug}/{label} [{self.state}]"

    @property
    def node_id(self) -> str:
        return str(self.id)

    @property
    def spiffe_id(self) -> str:
        return f"spiffe://{settings.SPIFFE_TRUST_DOMAIN}/{self.tenant.slug}/node/{self.node_id}"

    def target_version(self) -> str | None:
        """The version this node's channel currently targets (for its arch), or
        None if the arch is unknown or no target is set for that channel/arch."""
        if not self.running_goarch:
            return None
        ct = (ChannelTarget.objects
              .filter(channel=self.update_channel, goos="linux", goarch=self.running_goarch)
              .select_related("release").first())
        return ct.release.version if ct else None

    @property
    def is_behind(self) -> bool:
        tv = self.target_version()
        return bool(tv and self.running_version and tv != self.running_version)


class SystemIdentity(models.Model):
    """A non-node infrastructure principal (e.g. an XConnect, or the tower's own
    control-link server). Operator-gated, not the join-token node flow.

    SVID shapes:
      spiffe://<td>/<tenant>/system/xconnect/<id>   (tenant-scoped data-plane broker)
      spiffe://<td>/system/orthanc-control          (tower-global, no tenant)
    The control listener authenticates an inbound XConnect by matching the
    presented cert's SPKI fingerprint to an ACTIVE row here, then scopes the
    session to this row's tenant.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    # Null tenant = tower-global system identity (e.g. orthanc-control itself).
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, null=True, blank=True,
                               related_name="system_identities")
    role = models.CharField(max_length=40)  # 'xconnect', 'orthanc-control', ...
    spiffe_id = models.CharField(max_length=255, unique=True)
    spki_fingerprint = models.CharField(max_length=64, unique=True, db_index=True)
    cert_pem = models.TextField(blank=True)
    cert_not_after = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=200, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)  # last control-link contact

    def __str__(self) -> str:  # pragma: no cover - trivial
        scope = self.tenant.slug if self.tenant else "(tower)"
        return f"{scope}/{self.role} [{'active' if self.is_active else 'revoked'}]"

    @classmethod
    def resolve(cls, spki_fingerprint: str) -> "SystemIdentity | None":
        return cls.objects.select_related("tenant").filter(
            spki_fingerprint=spki_fingerprint, is_active=True).first()


# Required verb-class per RCON path. Two honest tiers only: `readonly` (observe —
# no shell, no mutation) and `full` (run/jobs + file mutation). We dropped the old
# `run` vs `write` split because `run` already grants shell, and shell *is*
# mutation (`echo >> file`, `sed -i`) — so a separate write tier was a fiction.
# Default-deny: anything unlisted needs `full`.
VERB_CLASS_REQUIRED = {
    "health": "readonly", "read": "readonly", "stat": "readonly",
    "list": "readonly", "list_dir": "readonly", "glob": "readonly", "grep": "readonly",
    "run": "full", "jobs": "full", "cancel": "full", "stream": "full", "tail": "full",
    "edit": "full", "write": "full", "put_file": "full", "get_file": "full",
    # Node knowledge (the "wiki for agents"): reading is observation (readonly);
    # writing modifies a box's memory — a mutation — so it needs `full`. readonly
    # principals must not be able to seed knowledge the next agent will trust.
    "knowledge_read": "readonly", "knowledge_write": "full",
}
CLASS_RANK = {"readonly": 1, "full": 2}

# Soft cap on a node's ACTIVE knowledge before the console flags it for curation
# and `search` notes "over budget". Compaction itself is deferred (a platform
# engineer prunes) — this is just the trip wire. ~10k chars ≈ a few KB of context.
KNOWLEDGE_BUDGET_CHARS = 10_000
# Hard cap on a single appended entry so one write can't blow the whole budget.
KNOWLEDGE_ENTRY_MAX_CHARS = 4_000


class Principal(models.Model):
    """A Caller (OBO) human discovered via XConnect — NOT an Orthanc operator.

    Populated as a side-effect of `authorize`: the first time XConnect asks about a
    token's principal we upsert this row, so the user becomes visible (and
    grantable) the instant their agent first knocks — no provisioning pipeline, no
    SCIM, no group-claim flattening (which doesn't survive real-world directories).
    Keyed on the immutable Entra object id (`oid`); UPN/name are display context
    that can drift. A Principal with no active Grant is authenticated-but-
    unauthorized — default-deny until an operator assigns access per tenant.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    oid = models.CharField(max_length=64, unique=True, db_index=True)
    tid = models.CharField(max_length=64, blank=True)  # Entra home-tenant id (NOT a fleet Tenant)
    upn = models.CharField(max_length=255, blank=True)
    display_name = models.CharField(max_length=200, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    seen_count = models.PositiveIntegerField(default=0)

    class Meta:
        ordering = ["upn", "oid"]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.upn or self.oid

    @classmethod
    def seen(cls, *, oid: str, tid: str = "", upn: str = "", name: str = ""):
        """Upsert on every authorize. Refreshes drifting display fields + bumps the
        seen counter without a read-modify-write race. Returns the Principal (or
        None when the token carried no oid)."""
        if not oid:
            return None
        from django.db.models import F
        obj, created = cls.objects.get_or_create(
            oid=oid, defaults={"tid": tid or "", "upn": upn or "", "display_name": name or ""})
        fields = {"seen_count": F("seen_count") + 1, "last_seen": timezone.now()}
        if upn and upn != obj.upn:
            fields["upn"] = upn
        if name and name != obj.display_name:
            fields["display_name"] = name
        if tid and not obj.tid:
            fields["tid"] = tid
        cls.objects.filter(pk=obj.pk).update(**fields)
        # Self-heal on first discovery: adopt any pre-existing legacy UPN grants
        # (principal=NULL, keyed on UPN) onto this immutable oid, so a user granted
        # before they were ever seen shows up correctly once their agent connects.
        if created and upn:
            Grant.objects.filter(
                subject_kind=Grant.Kind.USER, principal__isnull=True, subject__iexact=upn
            ).update(principal=obj, subject=oid)
        return obj


class Grant(models.Model):
    """Coarse authZ: a subject (an OBO principal UPN, or a group) may exercise up
    to a verb-class on a tenant's nodes. Default-deny — no Grant, no access. This
    is the perimeter that bounds a Caller even when it acts non-interactively in
    the background (see memory obo-background-capability)."""

    class Kind(models.TextChoices):
        USER = "user", "User (UPN)"
        GROUP = "group", "Group"

    class VerbClass(models.TextChoices):
        READONLY = "readonly", "Read-only"
        FULL = "full", "Full"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="grants")
    subject_kind = models.CharField(max_length=8, choices=Kind.choices, default=Kind.USER)
    subject = models.CharField(max_length=255)  # USER: oid (or legacy UPN); GROUP: group oid
    # For USER grants: the discovered principal (immutable oid). Groups use `subject`.
    principal = models.ForeignKey(
        "Principal", on_delete=models.CASCADE, null=True, blank=True, related_name="grants")
    verb_class = models.CharField(max_length=8, choices=VerbClass.choices, default=VerbClass.READONLY)
    # Step-up flag for full-class verbs. NOT enforced at the bus by design — there's
    # no human at the message-bus layer (esp. for non-interactive OBO). It is a
    # PASS-THROUGH ADVISORY: authorize() returns it, and the trusted authorized
    # caller (turnstone: MCP approval + judge model) MUST honor it. See ARCHITECTURE
    # "Trust boundaries & security decisions" for the delegation + residual.
    require_confirmation = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=200, blank=True)

    class Meta:
        indexes = [models.Index(fields=["tenant", "subject"])]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.tenant.slug}: {self.subject_kind}:{self.subject} -> {self.verb_class}"


class Release(models.Model):
    """A published, signed RCON binary artifact (one per version × os × arch).

    The binary lives on disk under CA_DIR/releases/; this row holds its identity,
    content hash, and the Ed25519 signature over ``version|goos|goarch|sha256``.
    Channel-agnostic — which cohort runs it is decided by ChannelTarget.
    """
    version = models.CharField(max_length=64, db_index=True)
    goos = models.CharField(max_length=32)        # linux, windows, darwin
    goarch = models.CharField(max_length=32)      # amd64, arm64
    sha256 = models.CharField(max_length=64)
    signature = models.TextField()                # base64 Ed25519 over the manifest
    size = models.BigIntegerField(default=0)
    blob_path = models.CharField(max_length=512)  # CA_DIR-relative path to the binary
    notes = models.CharField(max_length=255, blank=True)
    published_at = models.DateTimeField(auto_now_add=True)
    published_by = models.CharField(max_length=200, blank=True)

    class Meta:
        unique_together = [("version", "goos", "goarch")]
        indexes = [models.Index(fields=["goos", "goarch"])]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"rcon {self.version} ({self.goos}/{self.goarch})"


class ChannelTarget(models.Model):
    """Points an update channel (cohort) at the Release it should run, per arch.

    Promoting a build to "canary" sets ChannelTarget(canary, os, arch) = release;
    nodes whose Enrollment.update_channel == "canary" then converge to it, while
    "stable" stays put — the scream-test mechanism.
    """
    channel = models.CharField(max_length=64, db_index=True)
    goos = models.CharField(max_length=32)
    goarch = models.CharField(max_length=32)
    release = models.ForeignKey(Release, on_delete=models.PROTECT, related_name="channel_targets")
    updated_at = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=200, blank=True)

    class Meta:
        unique_together = [("channel", "goos", "goarch")]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.channel} {self.goos}/{self.goarch} -> {self.release.version}"


class NodeKnowledge(models.Model):
    """Shared, central, agent- and operator-writable knowledge about a node — a
    "wiki for agents". Like per-project CLAUDE.md/memory, but central (persisted
    here in Postgres), shared across whichever MCP client the user wired up, and
    scoped to a node (or a role). Surfaced + appended through the xconnect MCP
    (`search_node_knowledge` / `append_node_knowledge`); XConnect itself never
    touches this DB — it relays over the control link and Orthanc does the I/O.

    TRUST: agent-written knowledge is a prompt-injection vector for the *next*
    agent, so provenance (author oid/upn, source, time) is stamped SERVER-SIDE
    from the authenticated OBO principal — never accepted from the client. Agents
    cannot self-promote an entry to `critical` (the L0 always-surfaced core);
    only operators (via the console) can.

    LIFECYCLE: append-only. `supersede`/`retract` move a row out of the ACTIVE set
    (so it stops being surfaced) but keep it in the log for audit.
    """

    class Source(models.TextChoices):
        OPERATOR = "operator", "Operator (console)"
        AGENT = "agent", "Agent (OBO)"
        FABRIC = "fabric", "Fabric (system)"
        EXTERNAL = "external", "External"

    class State(models.TextChoices):
        ACTIVE = "active", "Active"
        SUPERSEDED = "superseded", "Superseded"
        RETRACTED = "retracted", "Retracted"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="knowledge")
    # Node-scoped knowledge. NULL node = role/tenant-level (shared role playbook or
    # tenant-wide critical core) — see `role`.
    node = models.ForeignKey(Enrollment, on_delete=models.CASCADE, null=True, blank=True,
                             related_name="knowledge")
    # Role this knowledge applies to (when node is null, or to tag node entries).
    # Lets a blank-slate scale-set member inherit its role's playbook.
    role = models.CharField(max_length=64, blank=True)
    content = models.TextField()

    # Provenance — STAMPED SERVER-SIDE from the authenticated principal. Never
    # trust the client for any of these.
    source = models.CharField(max_length=10, choices=Source.choices, default=Source.AGENT)
    author_oid = models.CharField(max_length=64, blank=True)
    author_upn = models.CharField(max_length=255, blank=True)
    # operator|fabric|agent|external — agent-written defaults lower-trust because it
    # feeds the next agent's context. Surfaced so a reader can weigh it.
    trust_tier = models.CharField(max_length=10, default="agent")
    # L0 "critical core": always surfaced regardless of budget/query. Operator-only.
    critical = models.BooleanField(default=False)
    severity = models.CharField(max_length=16, blank=True)  # info|warn|critical (display hint)

    state = models.CharField(max_length=10, choices=State.choices,
                             default=State.ACTIVE, db_index=True)
    supersedes = models.ForeignKey("self", on_delete=models.SET_NULL, null=True, blank=True,
                                   related_name="superseded_by")
    retract_reason = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["tenant", "node", "state"]),
            models.Index(fields=["tenant", "state", "critical"]),
        ]

    def __str__(self) -> str:  # pragma: no cover - trivial
        where = self.node.bound_name if self.node else (self.role or "(tenant)")
        return f"{self.tenant.slug}/{where} [{self.state}] {self.content[:40]!r}"

    def as_dict(self) -> dict:
        """Client-facing shape (what an agent sees). Provenance included so the
        reader can weigh trust; raw author oid stays internal-ish but harmless."""
        return {
            "id": str(self.id),
            "content": self.content,
            "source": self.source,
            "trust_tier": self.trust_tier,
            "critical": self.critical,
            "severity": self.severity,
            "author": self.author_upn or self.author_oid or "",
            "role": self.role,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


def _agent_label(app: str, app_name: str) -> str:
    """Render an acting agent as 'Name (id8)' — display name + short client-app id
    — falling back to whichever is present, or "" when the token carried no app
    claim. Shared by CallEvent + InFlightCall so the Witchhunt reads consistently."""
    short = app[:8] if app else ""
    if app_name and short:
        return f"{app_name} ({short})"
    return app_name or app or ""


class CallEvent(models.Model):
    """One audited fabric call — the "Witchhunt" log. WHO (OBO principal) did
    WHAT (verb) WHERE (target node), WHETHER it was allowed, and the OUTCOME.

    Born at XConnect (the only point that sees the full picture: it validated the
    token, got the authZ decision from Orthanc, resolved the target node, and
    injected the request). XConnect buffers events and ships them BATCHED on its
    control-link heartbeat (`/control/v1/report` carries `calls`); Orthanc
    persists them here, hard-scoped to the reporting XConnect's tenant — the
    client-supplied tenant is never trusted. Denials are kept too (the most
    interesting rows in an audit). Retention is handled out-of-band by the
    `prune_call_events` command.
    """

    id = models.BigAutoField(primary_key=True)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="call_events")
    occurred_at = models.DateTimeField(db_index=True)  # XConnect-stamped (the call's real time)
    received_at = models.DateTimeField(auto_now_add=True)  # when the tower persisted it

    # Per-call correlation id minted by XConnect: ties this terminal row to its
    # transient "running" record (InFlightCall, cleared when this arrives) and lets
    # the node-side RCON audit be cross-referenced to this central one. Also the
    # idempotency key — a re-shipped batch (control-link requeue) can't double-write
    # the same call. Blank for events from an XConnect that predates this (back-compat).
    request_id = models.CharField(max_length=64, blank=True, db_index=True)

    # WHO — the OBO principal. oid is the durable audit key (upn can change).
    principal_upn = models.CharField(max_length=255, blank=True, db_index=True)
    principal_oid = models.CharField(max_length=64, blank=True, db_index=True)
    principal_tid = models.CharField(max_length=64, blank=True)
    # The AGENT acting on the principal's behalf — the OAuth client app that
    # obtained the token (OBO azp/appid), with its display name when present. Lets
    # an operator tell WHICH of an admin's several agents made the call.
    principal_app = models.CharField(max_length=64, blank=True, db_index=True)
    principal_app_name = models.CharField(max_length=128, blank=True)

    # WHAT / WHERE — verb class + the target node (as asked, and as resolved).
    verb = models.CharField(max_length=32, blank=True)
    target = models.CharField(max_length=255, blank=True)       # caller-supplied node ref (name/fragment)
    target_svid = models.CharField(max_length=255, blank=True)  # resolved SVID (empty if unresolved)

    # OUTCOME — the perimeter decision + how the call ended.
    allowed = models.BooleanField(default=False, db_index=True)
    reason = models.CharField(max_length=255, blank=True)  # authZ reason
    status = models.CharField(max_length=64, blank=True)   # ok|denied|no-tunnel|ambiguous|error:…
    detail = models.TextField(blank=True)                  # bounded command/path summary

    # RESULT capture — what the call actually DID (drill-down on a log line).
    # Populated only for calls that reached a node. Output is bounded centrally
    # (XConnect caps at 64 KB); output_truncated flags that more was produced.
    http_status = models.IntegerField(null=True, blank=True)   # RCON's HTTP code
    rc = models.IntegerField(null=True, blank=True)            # process exit code (run/jobs)
    duration_ms = models.IntegerField(null=True, blank=True)   # node-side duration
    output = models.TextField(blank=True)                      # response body (stdout/stderr/etc.)
    output_truncated = models.BooleanField(default=False)

    class Meta:
        ordering = ["-occurred_at", "-id"]
        indexes = [
            models.Index(fields=["tenant", "-occurred_at"]),
            models.Index(fields=["tenant", "allowed", "-occurred_at"]),
            models.Index(fields=["tenant", "principal_oid", "-occurred_at"]),
            # Trigram index so the command/path search (detail ILIKE '%q%') stays
            # fast as the log grows — the Witchhunt search box hits this.
            GinIndex(fields=["detail"], name="callevent_detail_trgm",
                     opclasses=["gin_trgm_ops"]),
        ]

    def __str__(self) -> str:  # pragma: no cover - trivial
        verdict = "ALLOW" if self.allowed else "DENY"
        return f"{self.tenant.slug} {verdict} {self.principal_upn} {self.verb} {self.target}"

    @property
    def principal_label(self) -> str:
        """Short display name — the username before the @ (the tenant/domain is
        noise in a dense log). Falls back to the oid, then a dash."""
        if self.principal_upn:
            return self.principal_upn.split("@", 1)[0]
        return self.principal_oid or "—"

    @property
    def agent_label(self) -> str:
        """The acting agent as 'Name (id8)' (app display name + short client-app
        id), or just the id, or "" when the token carried no app claim."""
        return _agent_label(self.principal_app, self.principal_app_name)


class InFlightCall(models.Model):
    """A fabric call XConnect has authorized and INJECTED but not yet seen finish
    — the "running" rows of the Witchhunt live view.

    This is TRANSIENT LIVENESS state, deliberately NOT part of the audit log. The
    CallEvent table stays append-only and records only *completed* (decided) calls;
    "running" is modelled here, the same way tunnel-liveness is a separate signal
    from the audit trail. Lifecycle:

      * XConnect ships a `phase="start"` event the moment it injects an
        allowed+resolved call → a row is upserted here (never a CallEvent).
      * When the call finishes, XConnect ships the terminal event (same
        request_id) → a CallEvent is persisted append-only AND this row is deleted.

    A row that never gets its terminal event (XConnect crashed mid-call, the node
    hung) can't linger as "running" forever:
      * On restart XConnect mints a fresh instance_id; the next report clears any
        row of this identity from a prior instance (that process is provably gone).
      * `sweep_inflight` ages rows past a TTL into an 'orphaned' terminal CallEvent
        (outcome unknown — recorded honestly) and removes them.

    Born at XConnect like CallEvent, hard-scoped to the reporting XConnect's
    identity + tenant — the client cannot attribute a running call elsewhere."""

    id = models.BigAutoField(primary_key=True)
    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="inflight_calls")

    # The per-call correlation id minted by XConnect; ties this running row to the
    # terminal CallEvent that clears it. Unique → a re-shipped start is idempotent.
    request_id = models.CharField(max_length=64, unique=True)

    # WHICH XConnect owns this row, and its current process incarnation. On restart
    # XConnect mints a new instance_id, so rows carrying a prior instance_id are
    # provably stale and get cleared (the restart-corrective).
    system_identity = models.ForeignKey(SystemIdentity, on_delete=models.CASCADE,
                                        null=True, blank=True, related_name="inflight_calls")
    instance_id = models.CharField(max_length=64, blank=True, db_index=True)

    # WHO / WHAT / WHERE — same shape as CallEvent, minus the outcome. Enough to
    # display the running row AND to synthesize an honest 'orphaned' CallEvent if
    # this row is ever swept without a real terminal event.
    principal_upn = models.CharField(max_length=255, blank=True)
    principal_oid = models.CharField(max_length=64, blank=True)
    principal_tid = models.CharField(max_length=64, blank=True)
    principal_app = models.CharField(max_length=64, blank=True)       # agent (OBO azp/appid)
    principal_app_name = models.CharField(max_length=128, blank=True)  # agent display name
    verb = models.CharField(max_length=32, blank=True)
    target = models.CharField(max_length=255, blank=True)
    target_svid = models.CharField(max_length=255, blank=True)
    detail = models.TextField(blank=True)

    started_at = models.DateTimeField(db_index=True)       # XConnect-stamped call start
    received_at = models.DateTimeField(auto_now_add=True)  # when the tower recorded it

    class Meta:
        ordering = ["-started_at", "-id"]
        indexes = [
            models.Index(fields=["tenant", "-started_at"]),
            models.Index(fields=["system_identity", "instance_id"]),
        ]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.tenant.slug} RUNNING {self.principal_upn} {self.verb} {self.target}"

    @property
    def principal_label(self) -> str:
        if self.principal_upn:
            return self.principal_upn.split("@", 1)[0]
        return self.principal_oid or "—"

    @property
    def agent_label(self) -> str:
        return _agent_label(self.principal_app, self.principal_app_name)

    def to_orphan_callevent(self, status: str = "orphaned", reason: str = "") -> "CallEvent":
        """Synthesize the terminal audit row for a running call we can no longer
        observe (its XConnect restarted, or it aged past the TTL) — the outcome is
        unknown, recorded HONESTLY rather than letting the call silently vanish.
        No rc/output: we never saw it finish."""
        return CallEvent(
            tenant=self.tenant,
            request_id=self.request_id,
            occurred_at=self.started_at,
            principal_upn=self.principal_upn,
            principal_oid=self.principal_oid,
            principal_tid=self.principal_tid,
            principal_app=self.principal_app,
            principal_app_name=self.principal_app_name,
            verb=self.verb,
            target=self.target,
            target_svid=self.target_svid,
            allowed=True,          # it was authorized — that's how it started
            reason=reason,
            status=status,
            detail=self.detail,
        )

    @classmethod
    def orphan(cls, queryset, status: str = "orphaned", reason: str = "") -> int:
        """Turn each running row in `queryset` into an honest terminal CallEvent and
        remove it; returns how many rows were cleared. Idempotent on request_id — it
        won't duplicate a CallEvent that already exists for the same call (e.g. a
        real terminal event that raced in)."""
        rows = list(queryset.select_related("tenant"))
        if not rows:
            return 0
        rids = [r.request_id for r in rows if r.request_id]
        existing = set(CallEvent.objects.filter(request_id__in=rids)
                       .values_list("request_id", flat=True)) if rids else set()
        events = [r.to_orphan_callevent(status=status, reason=reason)
                  for r in rows if r.request_id not in existing]
        if events:
            CallEvent.objects.bulk_create(events)
        cls.objects.filter(pk__in=[r.pk for r in rows]).delete()
        return len(rows)


class AgentApp(models.Model):
    """Operator-curated friendly name for an AGENT — the OAuth client app (the OBO
    `azp`/`appid`) that calls the fabric on a user's behalf, i.e. the *harness*
    (e.g. Turnstone-MCP). A v2 access token carries only the app's GUID, no
    reliable display name, so we map GUID -> name HERE, exactly the way a node gets
    a `bound_name`.

    Rows are AUTO-SEEDED the first time an app is seen, in the PENDING state with
    name defaulting to the GUID. The agent jail then DENIES a pending/denied agent
    at /authorize until an operator approves it (and names it) in the console —
    mirroring the node enrollment approve flow. You gate WHICH harness may act;
    you never gate the trusted admin behind it."""

    class State(models.TextChoices):
        PENDING = "pending", "Pending"     # seen, not yet approved → calls denied
        APPROVED = "approved", "Approved"  # operator-approved → calls allowed
        DENIED = "denied", "Denied"        # explicitly banned → calls denied

    app_id = models.CharField(max_length=64, unique=True)   # the OBO azp/appid GUID
    name = models.CharField(max_length=128, blank=True)     # operator-set friendly name
    description = models.CharField(max_length=255, blank=True)
    state = models.CharField(max_length=10, choices=State.choices,
                             default=State.PENDING, db_index=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=200, blank=True)

    class Meta:
        ordering = ["state", "name", "app_id"]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name or self.app_id

    @property
    def named(self) -> bool:
        """True once an operator has given it a real name (not the GUID default)."""
        return bool(self.name and self.name != self.app_id)

    @property
    def approved(self) -> bool:
        return self.state == self.State.APPROVED

    @property
    def display_name(self) -> str:
        """'name (guid8)' once named, else the bare GUID."""
        return f"{self.name} ({self.app_id[:8]})" if self.named else self.app_id

    @classmethod
    def touch(cls, app_id: str) -> "AgentApp | None":
        """Record that we've seen this agent app — auto-seed (PENDING, name=GUID)
        so it appears in the console worklist to be approved + named, and bump
        last_seen. Returns the row (the agent jail checks its state). Cheap; called
        from the call-ingest + authorize paths the way principals are discovered."""
        if not app_id:
            return None
        app_id = app_id[:64]
        obj, created = cls.objects.get_or_create(app_id=app_id, defaults={"name": app_id})
        if not created:
            cls.objects.filter(pk=obj.pk).update(last_seen=timezone.now())
        return obj
