"""Operator management console — the SSO-gated dashboard.

Read views need 'viewer'; approve/revoke need 'approver' (see sso.roles). All
data is the same tenant/enrollment/system-identity tables the control link and
CLI use — this is just the human window onto them.
"""
from __future__ import annotations

import datetime as dt

from django.contrib import messages
from django.core.paginator import Paginator
from django.db.models import F, Q
from django.http import JsonResponse
from django.urls import reverse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST

from enrollment import services
from ca import authority
from django.conf import settings
from enrollment.models import (
    AgentApp, CallEvent, ChannelTarget, Enrollment, Grant, InFlightCall,
    JoinToken, Principal, Release, SystemIdentity, Tenant,
)
from sso.roles import SESSION_KEY, has_tier, require_tier, require_tier_api

# Cohorts an operator can assign from the console (free-form in the DB, but these
# are the ones we offer in the UI).
CHANNELS = ["stable", "canary", "dev"]

# An XConnect that contacted the tower within this window is "live".
FRESH_SECONDS = 90


def _operator(request):
    return request.session.get(SESSION_KEY)


def _annotate_freshness(idents):
    now = timezone.now()
    for i in idents:
        i.is_fresh = bool(i.last_seen and (now - i.last_seen) <= dt.timedelta(seconds=FRESH_SECONDS))
    return idents


@require_tier("viewer")
def dashboard(request):
    fresh_cutoff = timezone.now() - dt.timedelta(seconds=FRESH_SECONDS)
    tenants = list(Tenant.objects.order_by("slug"))
    for t in tenants:
        ns = Enrollment.objects.filter(tenant=t)
        t.n_active = ns.filter(state=Enrollment.State.ACTIVE).count()
        t.n_pending = ns.filter(state=Enrollment.State.PENDING).count()
        t.n_revoked = ns.filter(state=Enrollment.State.REVOKED).count()
        t.n_connected = ns.filter(state=Enrollment.State.ACTIVE,
                                  last_tunnel_at__gte=fresh_cutoff).count()
        t.n_xconnect = t.system_identities.filter(role="xconnect", is_active=True).count()

    xconnects = _annotate_freshness(list(
        SystemIdentity.objects.filter(role="xconnect").select_related("tenant").order_by("tenant__slug")))
    pending = list(Enrollment.objects.filter(state=Enrollment.State.PENDING)
                   .select_related("tenant").order_by("created_at"))

    return render(request, "console/dashboard.html", {
        "operator": _operator(request),
        "tenants": tenants,
        "xconnects": xconnects,
        "pending": pending,
        "totals": {
            "tenants": len(tenants),
            "active": Enrollment.objects.filter(state=Enrollment.State.ACTIVE).count(),
            "pending": len(pending),
            "connected": Enrollment.objects.filter(
                state=Enrollment.State.ACTIVE, last_tunnel_at__gte=fresh_cutoff).count(),
            "xconnects_live": sum(1 for x in xconnects if x.is_fresh),
        },
        "fresh_seconds": FRESH_SECONDS,
    })


@require_tier("viewer")
def tenant_detail(request, slug):
    tenant = get_object_or_404(Tenant, slug=slug)
    now = timezone.now()
    nodes = list(Enrollment.objects.filter(tenant=tenant).order_by("state", "bound_name"))
    for n in nodes:
        n.tunnel_fresh = bool(n.last_tunnel_at and (now - n.last_tunnel_at) <= dt.timedelta(seconds=FRESH_SECONDS))
    idents = _annotate_freshness(list(tenant.system_identities.order_by("role")))
    can_act = has_tier(_operator(request), "approver")
    grants = list(Grant.objects.filter(tenant=tenant, is_active=True)
                  .select_related("principal").order_by("subject_kind", "subject"))
    # Principals already granted here — excluded from the "assign" picker.
    granted_oids = {g.principal_id for g in grants if g.principal_id}
    assignable = [p for p in Principal.objects.all() if p.id not in granted_oids] if can_act else []

    # Join tokens (deploy credentials) for this tenant. By default show only the
    # ACTIVE ones — expired/used/revoked pile up and make the page noisy; reveal
    # them with ?show_tokens=all. The raw secret is never recoverable (only sha256).
    show_all_tokens = request.GET.get("show_tokens") == "all"
    active_q = (tenant.join_tokens
                .filter(revoked=False, expires_at__gt=now, uses__lt=F("max_uses")))
    total_tokens = tenant.join_tokens.count()
    hidden_tokens = total_tokens - active_q.count()
    src = tenant.join_tokens if show_all_tokens else active_q
    tokens = list(src.order_by("-created_at")[:50])
    for t in tokens:
        if t.revoked:
            t.status = "revoked"
        elif t.expires_at <= now:
            t.status = "expired"
        elif t.uses >= t.max_uses:
            t.status = "used up"
        else:
            t.status = "active"
    # A token minted on the previous request is shown ONCE here, then dropped.
    minted = request.session.pop("minted_token", None)
    if minted and minted.get("tenant") != slug:
        minted = None  # never surface another tenant's secret

    return render(request, "console/tenant.html", {
        "operator": _operator(request),
        "tenant": tenant,
        "nodes": nodes,
        "idents": idents,
        "grants": grants,
        "assignable": assignable,
        "verb_classes": Grant.VerbClass.choices,
        "channels": CHANNELS,
        "State": Enrollment.State,
        "can_act": can_act,
        "tokens": tokens,
        "show_all_tokens": show_all_tokens,
        "hidden_tokens": hidden_tokens,
        "minted": minted,
        "bootstrap_url": settings.BOOTSTRAP_URL,
        "default_ttl": settings.JOIN_TOKEN_TTL_MINUTES,
        "ca_pin": authority.ca_pin(),
    })


@require_tier("approver")
@require_POST
def set_channel(request, slug):
    """Assign a node to a self-update cohort (stable/canary/dev). Orthanc owns this
    — the node has no say; its channel decides which ChannelTarget it converges to."""
    e = get_object_or_404(Enrollment, id=request.POST.get("enrollment_id"), tenant__slug=slug)
    ch = (request.POST.get("channel") or "").strip()
    if ch not in CHANNELS:
        messages.error(request, f"unknown channel '{ch}'")
        return redirect("console:tenant", slug=slug)
    e.update_channel = ch
    e.save(update_fields=["update_channel"])
    messages.success(request, f"{e.bound_name or e.node_id}: channel → {ch}")
    return redirect("console:tenant", slug=slug)


@require_tier("approver")
@require_POST
def request_update(request, slug):
    """Operator 'update now': flag the node; XConnect picks it up on its next report
    poll and nudges it (Orthanc never dials down — the control link is XConnect's)."""
    e = get_object_or_404(Enrollment, id=request.POST.get("enrollment_id"),
                          tenant__slug=slug, state=Enrollment.State.ACTIVE)
    e.update_requested = True
    e.save(update_fields=["update_requested"])
    messages.success(request, f"{e.bound_name or e.node_id}: update nudge queued "
                              "(XConnect will action it within a heartbeat)")
    return redirect("console:tenant", slug=slug)


@require_tier("viewer")
def releases(request):
    """Read-only release/rollout overview: published signed builds + which version
    each channel targets (per arch). Operator-only; nothing here touches MCP."""
    rels = list(Release.objects.order_by("-published_at"))
    targets = list(ChannelTarget.objects.select_related("release").order_by("channel", "goarch"))
    return render(request, "console/releases.html", {
        "operator": _operator(request),
        "releases": rels,
        "targets": targets,
    })


@require_tier("viewer")
def users(request):
    """Discovered Caller (OBO) principals — the users whose agents have knocked.
    Authenticated ≠ authorized: a principal with no grant is awaiting assignment."""
    principals = list(Principal.objects.all())
    grants = (Grant.objects.filter(is_active=True, principal__isnull=False)
              .select_related("tenant", "principal"))
    by_principal = {}
    for g in grants:
        by_principal.setdefault(g.principal_id, []).append(g)
    for p in principals:
        p.grant_list = by_principal.get(p.id, [])
        p.unassigned = not p.grant_list
    return render(request, "console/users.html", {
        "operator": _operator(request),
        "principals": principals,
        "n_unassigned": sum(1 for p in principals if p.unassigned),
    })


def _node_uuid(svid):
    """The node UUID is the last segment of a …/node/<uuid> SVID; "" otherwise."""
    if svid and "/node/" in svid:
        return svid.rstrip("/").split("/")[-1]
    return ""


def _node_name_map(rows):
    """Bulk-resolve uuid -> friendly node name for the nodes these rows target, so
    the Witchhunt can show a human name instead of a bare GUID. One query per page."""
    ids = {_node_uuid(r.target_svid) for r in rows}
    ids.discard("")
    if not ids:
        return {}
    out = {}
    for e in Enrollment.objects.filter(id__in=ids):
        out[str(e.id)] = e.bound_name or e.description or e.requested_name or ""
    return out


def _node_label(target, svid, name_map):
    """'name (uuid8)' when we know the node's name, else the caller-supplied target
    (e.g. a denied/no-tunnel call that never resolved), else a dash."""
    uuid = _node_uuid(svid)
    name = name_map.get(uuid, "") if uuid else ""
    if name and uuid:
        return f"{name} ({uuid[:8]})"
    return target or (uuid[:8] if uuid else "") or "—"


def _agent_name_map(rows):
    """Bulk-resolve agent app GUID -> operator-curated friendly name (only where an
    operator has actually named it; an un-named app falls back to its GUID)."""
    ids = {r.principal_app for r in rows if r.principal_app}
    ids.discard("")
    if not ids:
        return {}
    return {a.app_id: a.name for a in AgentApp.objects.filter(app_id__in=ids) if a.named}


def _agent_label(app, token_name, name_map):
    """The acting agent (harness) as 'name (guid8)' — preferring the operator's
    curated name, then any display name the token carried, then the bare GUID."""
    if not app:
        return token_name or "—"
    name = name_map.get(app) or token_name
    return f"{name} ({app[:8]})" if name and name != app else app


@require_tier("viewer")
def witchhunt(request):
    """The Witchhunt — who (OBO principal) via which agent (harness) ran what
    (verb) where (node), allowed or denied, and how it ended. ONE page, two modes
    sharing one filter bar:
      * mode=live   (default) — streams the running set + recent completions.
      * mode=search          — pages the full history with command-text search.
    Read-only; events are written by XConnect over the control link."""
    f = _parse_filters(request)
    mode = request.GET.get("mode", "live")
    if mode not in ("live", "search"):
        mode = "live"

    # Filter querystring WITHOUT mode/page, so the mode toggle + page links keep
    # the active filters (and the live poller scopes to the same set).
    params = request.GET.copy()
    params.pop("page", None)
    params.pop("mode", None)
    filter_qs = params.urlencode()

    ctx = {
        "operator": _operator(request),
        "mode": mode,
        "filter_qs": filter_qs,
        "tenants": list(Tenant.objects.order_by("slug")),
        "verbs": ["run", "full", "read", "knowledge_read", "knowledge_write"],
        "f": f,
    }

    if mode == "search":
        try:
            limit = max(1, min(1000, int(request.GET.get("limit", "200"))))
        except ValueError:
            limit = 200
        qs = _witchhunt_filter(request, CallEvent.objects.select_related("tenant"))
        paginator = Paginator(qs, limit)
        page = paginator.get_page(request.GET.get("page"))
        # Resolve friendly node + agent names for this page (one query each).
        name_map = _node_name_map(page.object_list)
        amap = _agent_name_map(page.object_list)
        for e in page.object_list:
            e.node_label = _node_label(e.target, e.target_svid, name_map)
            e.agent_disp = _agent_label(e.principal_app, e.principal_app_name, amap)
        ctx.update({
            "page_obj": page,
            "events": page.object_list,
            "total": paginator.count,
            "denied_shown": sum(1 for e in page.object_list if not e.allowed),
            "limit": limit,
        })
    return render(request, "console/witchhunt.html", ctx)


# Filters shared by the witchhunt history table, the live stream, and the running
# set, so every surface scopes identically. CallEvent and InFlightCall carry the
# same who/what/where field names, so the field filters apply to both; only the
# outcome `result` differs (a running call has no outcome yet).
def _parse_filters(request):
    g = request.GET.get
    return {
        "tenant": g("tenant", "").strip(),
        "principal": g("principal", "").strip(),
        "agent": g("agent", "").strip(),
        "node": g("node", "").strip(),
        "verb": g("verb", "").strip(),
        "result": g("result", "").strip(),  # allowed|denied|""
        "q": g("q", "").strip(),            # command/path text search
    }


def _apply_common_filters(qs, f):
    if f["tenant"]:
        qs = qs.filter(tenant__slug=f["tenant"])
    if f["principal"]:
        qs = qs.filter(Q(principal_upn__icontains=f["principal"]) |
                       Q(principal_oid__icontains=f["principal"]))
    if f["agent"]:
        # Match the GUID, any name the token carried, OR an operator-curated name —
        # so "Turnstone" finds calls even when the token had no display name.
        cond = (Q(principal_app__icontains=f["agent"]) |
                Q(principal_app_name__icontains=f["agent"]))
        app_ids = list(AgentApp.objects.filter(name__icontains=f["agent"])
                       .values_list("app_id", flat=True))
        if app_ids:
            cond |= Q(principal_app__in=app_ids)
        qs = qs.filter(cond)
    if f["node"]:
        # Match the caller-supplied ref / svid OR a friendly node name (bound_name).
        cond = Q(target__icontains=f["node"]) | Q(target_svid__icontains=f["node"])
        for nid in (Enrollment.objects.filter(bound_name__icontains=f["node"])
                    .values_list("id", flat=True)):
            cond |= Q(target_svid__icontains=str(nid))
        qs = qs.filter(cond)
    if f["verb"]:
        qs = qs.filter(verb=f["verb"])
    if f["q"]:
        qs = qs.filter(detail__icontains=f["q"])  # the command / path that ran
    return qs


def _witchhunt_filter(request, qs):
    f = _parse_filters(request)
    qs = _apply_common_filters(qs, f)
    if f["result"] == "allowed":
        qs = qs.filter(allowed=True)
    elif f["result"] == "denied":
        qs = qs.filter(allowed=False)
    return qs


def _inflight_filter(request, qs):
    """The same field filters, applied to the 'running' rows. A running call is
    always an authorized one (we only track allowed+injected calls), so
    result=denied hides them; result=allowed/"" keeps them."""
    f = _parse_filters(request)
    if f["result"] == "denied":
        return qs.none()
    return _apply_common_filters(qs, f)


@require_tier("viewer")
def witchhunt_live(request):
    """Back-compat: the live tail is now the default mode of the merged Witchhunt
    page. Preserve any querystring filters and land in live mode."""
    params = request.GET.copy()
    params["mode"] = "live"
    return redirect(f"{reverse('console:witchhunt')}?{params.urlencode()}")


@require_tier_api("viewer")
def witchhunt_tail(request):
    """JSON cursor feed for the live tail. Returns events newer than ?after=<id>
    (or the most recent batch when absent), matching the same filters, newest
    first. The client advances its cursor by max_id."""
    qs = _witchhunt_filter(request, CallEvent.objects.select_related("tenant"))
    try:
        after = int(request.GET.get("after", "0"))
    except ValueError:
        after = 0
    if after > 0:
        qs = qs.filter(id__gt=after)
    rows = list(qs.order_by("-id")[:200])  # cap each poll so a burst can't flood
    name_map = _node_name_map(rows)
    amap = _agent_name_map(rows)
    events = [{
        "id": e.id,
        "ts": e.occurred_at.strftime("%H:%M:%S"),
        "ts_full": e.occurred_at.isoformat(),
        "upn": e.principal_label,
        "upn_full": e.principal_upn or e.principal_oid or "—",
        "agent": _agent_label(e.principal_app, e.principal_app_name, amap),
        "verb": e.verb,
        "target": _node_label(e.target, e.target_svid, name_map),
        "target_raw": e.target or "—",
        "allowed": e.allowed,
        "reason": e.reason,
        "status": e.status,
        "rc": e.rc,
        "dur_ms": e.duration_ms,
        "detail": (e.detail or "")[:400],
        "url": reverse("console:witchhunt_detail", args=[e.id]),
    } for e in rows]
    max_id = rows[0].id if rows else after

    # The 'running' set is a SNAPSHOT (not an id-cursor stream): the client
    # replaces it wholesale each poll, so a call that just finished drops off here
    # and reappears among `events`. started_iso + the server `now` let the client
    # render a live-ticking "running Ns" without trusting the browser clock.
    inflight_qs = _inflight_filter(
        request, InFlightCall.objects.select_related("tenant"))
    inflight_rows = list(inflight_qs.order_by("-started_at")[:200])
    in_names = _node_name_map(inflight_rows)
    in_amap = _agent_name_map(inflight_rows)
    inflight = [{
        "request_id": r.request_id,
        "ts": r.started_at.strftime("%H:%M:%S"),
        "started_iso": r.started_at.isoformat(),
        "upn": r.principal_label,
        "upn_full": r.principal_upn or r.principal_oid or "—",
        "agent": _agent_label(r.principal_app, r.principal_app_name, in_amap),
        "verb": r.verb,
        "target": _node_label(r.target, r.target_svid, in_names),
        "detail": (r.detail or "")[:400],
    } for r in inflight_rows]
    return JsonResponse({
        "events": events, "max_id": max_id,
        "inflight": inflight, "now": timezone.now().isoformat(),
    })


@require_tier("viewer")
def witchhunt_detail(request, pk):
    """Drill-down on one call: the full command/path, the exact node output
    (stdout/stderr/rc/duration), and the full identity + decision context."""
    e = get_object_or_404(CallEvent.objects.select_related("tenant"), pk=pk)
    # Map the resolved SVID to a friendly node, if it's still a known enrollment.
    node = None
    if e.target_svid:
        nid = e.target_svid.rstrip("/").split("/")[-1]
        node = Enrollment.objects.filter(tenant=e.tenant, id=nid).first()
    # The stored output is the raw RCON response body. For run/jobs it's JSON with
    # stdout/stderr — split those out for readable display; otherwise show raw.
    stdout = stderr = ""
    raw = e.output or ""
    if raw.lstrip().startswith("{"):
        import json as _json
        try:
            d = _json.loads(raw)
            stdout = d.get("stdout", "") or ""
            stderr = d.get("stderr", "") or ""
        except (ValueError, AttributeError):
            pass
    return render(request, "console/witchhunt_detail.html", {
        "operator": _operator(request),
        "e": e,
        "node": node,
        "agent_disp": _agent_label(e.principal_app, e.principal_app_name,
                                   _agent_name_map([e])),
        "stdout": stdout,
        "stderr": stderr,
        "raw_output": raw,
        "structured": bool(stdout or stderr),
    })


@require_tier("viewer")
def agents(request):
    """Agents (harnesses) discovered calling the fabric — the OAuth client apps
    behind the OBO tokens (the `azp`). Auto-recorded PENDING on first call; the
    agent jail denies a pending/denied harness at the perimeter until an operator
    approves it here (and names it so the Witchhunt reads in plain language)."""
    apps = list(AgentApp.objects.all())
    return render(request, "console/agents.html", {
        "operator": _operator(request),
        "apps": apps,
        "n_pending": sum(1 for a in apps if a.state == AgentApp.State.PENDING),
    })


@require_tier("approver")
@require_POST
def agent_edit(request):
    """Rename / describe an agent app. Editable anytime; blank name resets to the
    GUID (the auto-seed default)."""
    a = get_object_or_404(AgentApp, app_id=request.POST.get("app_id", ""))
    a.name = (request.POST.get("name") or a.app_id)[:128]
    a.description = (request.POST.get("description") or "")[:255]
    a.updated_by = _operator(request).get("upn", "operator")
    a.save(update_fields=["name", "description", "updated_by"])
    messages.success(request, f"agent {a.app_id[:8]} → {a.name}")
    return redirect("console:agents")


@require_tier("approver")
@require_POST
def agent_set_state(request):
    """Approve / deny / re-pend an agent — the jail's allow/ban control. Approving
    lets its calls through the perimeter; pending/denied blocks them."""
    a = get_object_or_404(AgentApp, app_id=request.POST.get("app_id", ""))
    state = request.POST.get("state", "")
    if state not in AgentApp.State.values:
        messages.error(request, f"invalid state '{state}'")
        return redirect("console:agents")
    # Approving an un-named agent: take an inline name if provided (approve + name).
    if state == AgentApp.State.APPROVED and request.POST.get("name"):
        a.name = request.POST["name"][:128]
    a.state = state
    a.updated_by = _operator(request).get("upn", "operator")
    a.save(update_fields=["state", "name", "updated_by"])
    messages.success(request, f"agent {a.display_name} → {a.get_state_display()}")
    return redirect("console:agents")


@require_tier("approver")
@require_POST
def mint_join_token(request, slug):
    """Mint a tenant-scoped join token from the console. The raw secret is
    stashed for ONE render (the tenant page shows it once with the install
    one-liner) and never recoverable after — only its sha256 is stored."""
    tenant = get_object_or_404(Tenant, slug=slug)
    label = request.POST.get("label", "").strip()[:200]
    try:
        ttl = int(request.POST.get("ttl_minutes") or 0) or None
    except ValueError:
        ttl = None
    try:
        uses = max(1, min(1000, int(request.POST.get("uses") or 1)))
    except ValueError:
        uses = 1
    op = _operator(request) or {}
    tok, raw = JoinToken.mint(tenant=tenant, ttl_minutes=ttl, max_uses=uses,
                              label=label, created_by=op.get("upn", "console"))
    request.session["minted_token"] = {
        "raw": raw, "tenant": tenant.slug, "label": label,
        "expires": tok.expires_at.isoformat(), "uses": tok.max_uses,
    }
    messages.success(request, "Join token minted — copy it now; it will not be shown again.")
    return redirect("console:tenant", slug=slug)


@require_tier("approver")
@require_POST
def revoke_join_token(request, slug):
    """Revoke a join token so it can no longer enroll a node."""
    tenant = get_object_or_404(Tenant, slug=slug)
    tok = get_object_or_404(JoinToken, id=request.POST.get("token_id"), tenant=tenant)
    if not tok.revoked:
        tok.revoked = True
        tok.save(update_fields=["revoked"])
    messages.success(request, f"Join token '{tok.label or tok.id}' revoked.")
    return redirect("console:tenant", slug=slug)


@require_tier("approver")
@require_POST
def grant_add(request, slug):
    """Assign a discovered principal readonly/full on this tenant (all its nodes).
    Explicit + per-tenant: one principal, one tenant, one verb-class at a time."""
    tenant = get_object_or_404(Tenant, slug=slug)
    principal = get_object_or_404(Principal, id=request.POST.get("principal_id"))
    verb_class = request.POST.get("verb_class")
    if verb_class not in dict(Grant.VerbClass.choices):
        messages.error(request, f"invalid verb-class '{verb_class}'")
        return redirect("console:tenant", slug=slug)
    Grant.objects.update_or_create(
        tenant=tenant, subject_kind=Grant.Kind.USER, principal=principal,
        defaults={"subject": principal.oid, "verb_class": verb_class, "is_active": True,
                  "created_by": _operator(request).get("upn", "operator")},
    )
    messages.success(request, f"granted {principal.upn or principal.oid} → {verb_class} on {tenant.slug}")
    return redirect("console:tenant", slug=slug)


@require_tier("approver")
@require_POST
def grant_set_class(request, slug):
    """Flip an existing grant's verb-class (readonly ⇄ full) in place."""
    g = get_object_or_404(Grant, id=request.POST.get("grant_id"), tenant__slug=slug)
    vc = request.POST.get("verb_class")
    if vc not in dict(Grant.VerbClass.choices):
        messages.error(request, f"invalid verb-class '{vc}'")
        return redirect("console:tenant", slug=slug)
    g.verb_class = vc
    g.save(update_fields=["verb_class"])
    label = (g.principal.upn if g.principal else g.subject)
    messages.success(request, f"{label}: access → {g.get_verb_class_display()} on {slug}")
    return redirect("console:tenant", slug=slug)


@require_tier("approver")
@require_POST
def grant_revoke(request, slug):
    tenant = get_object_or_404(Tenant, slug=slug)
    g = get_object_or_404(Grant, id=request.POST.get("grant_id"), tenant=tenant)
    label = (g.principal.upn if g.principal else g.subject) or g.subject
    g.delete()
    messages.success(request, f"revoked access for {label} on {tenant.slug}")
    return redirect("console:tenant", slug=slug)


@require_tier("approver")
@require_POST
def approve(request, slug):
    e = get_object_or_404(Enrollment, id=request.POST.get("enrollment_id"), tenant__slug=slug)
    name = request.POST.get("name") or e.requested_name or e.spki_fingerprint[:16]
    try:
        # Blank approve-form description => leave any already-saved description
        # intact (don't clobber a description set via the inline edit before approval).
        services.approve(e, bound_name=name, approved_by=_operator(request).get("upn", "operator"),
                         description=(request.POST.get("description") or None))
        messages.success(request, f"approved {e.tenant.slug}/{name}")
    except services.EnrollmentError as exc:
        messages.error(request, str(exc))
    return redirect("console:tenant", slug=slug)


@require_tier("approver")
@require_POST
def set_description(request, slug):
    """Edit a node's human description (intent-mapping for agents). Editable
    anytime, unlike bound_name which is fixed at approval."""
    e = get_object_or_404(Enrollment, id=request.POST.get("enrollment_id"), tenant__slug=slug)
    e.description = (request.POST.get("description") or "")[:255]
    e.save(update_fields=["description"])
    messages.success(request, f"updated description for {e.bound_name or e.spki_fingerprint[:16]}")
    return redirect("console:tenant", slug=slug)


@require_tier("approver")
@require_POST
def node_edit(request, slug):
    """Inline field edit for a node (click-to-edit, auto-save). Both fields are
    display-only relabels — the durable identity is the node UUID + SPKI, never
    bound_name — so editing them post-approval is safe. Returns JSON for the JS."""
    e = get_object_or_404(Enrollment, id=request.POST.get("enrollment_id"), tenant__slug=slug)
    field = request.POST.get("field")
    value = (request.POST.get("value") or "").strip()
    if field == "name":
        if not value:
            return JsonResponse({"ok": False, "error": "name cannot be empty"}, status=400)
        e.bound_name = value[:255]
        e.save(update_fields=["bound_name"])
    elif field == "description":
        e.description = value[:255]
        e.save(update_fields=["description"])
    else:
        return JsonResponse({"ok": False, "error": f"unknown field '{field}'"}, status=400)
    return JsonResponse({"ok": True, "value": value})


@require_tier("approver")
@require_POST
def tenant_edit(request, slug):
    """Inline edit of the tenant's display NAME only. The slug is immutable — it's
    embedded in every node's SPIFFE id and the allow-list — so it is never editable."""
    tenant = get_object_or_404(Tenant, slug=slug)
    field = request.POST.get("field")
    value = (request.POST.get("value") or "").strip()
    if field == "name":
        tenant.name = value[:200]
        tenant.save(update_fields=["name"])
    else:
        return JsonResponse({"ok": False, "error": f"unknown field '{field}'"}, status=400)
    return JsonResponse({"ok": True, "value": value})


def permission_denied(request, exception=None):
    """Friendly 403: distinguish 'not signed in' from 'signed in, no role' and
    tell the operator exactly how to get access. Wired as handler403."""
    op = request.session.get(SESSION_KEY)
    return render(request, "console/403.html", {
        "operator": op,
        "detail": str(exception) if exception else "",
    }, status=403)


@require_tier("approver")
@require_POST
def revoke(request, slug):
    e = get_object_or_404(Enrollment, id=request.POST.get("enrollment_id"), tenant__slug=slug)
    services.revoke(e, revoked_by=_operator(request).get("upn", "operator"))
    messages.success(request, f"revoked {e.bound_name or e.spki_fingerprint[:16]}")
    return redirect("console:tenant", slug=slug)
