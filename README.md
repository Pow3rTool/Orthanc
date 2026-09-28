# Orthanc — management & control plane

The tower that sees everything. AAA + governance for the fabric: who may
cross-connect to which host with which verb, enrollment approval, the CA, and the
audit trail. Because every managed box shares root (and his Windows alter-ego,
"Fredrick Sykes"), **Orthanc's authorization — not the boxes' OS perms — is the
real perimeter.**

## Role
- **AuthN/Z:** OAuth + OBO for Callers; coarse `group → nodes → verb-class`, **default-deny** (evolve to per-verb/per-path/time-boxed later)
- **Enrollment approval ("the LOA"):** approve a pending RCON by **key fingerprint** (never hostname/IP — those are self-asserted), with a join token to gate the queue
- **CA front:** root key on the control plane — plaintext PEM, root-only perms, at-rest via the filer's ZFS dataset encryption (by design). XConnect (data plane) holds no signing key
- **Revocation:** allow-list removal **+ live tunnel termination** (a revoked cert with an open tunnel is still RCE)
- **SSO web app** for operators

## Witchhunt (tab)
The monitoring/audit view lives **inside Orthanc as a tab**, not a separate
service — it rides the same Call-log data and the same SSO/authZ:
- **Call log / CDR:** append-only, tamper-evident — `principal (OBO) + device (cert) + verb + target + args-hash + result + timestamps`
- **Live board:** what's flying through XConnect right now, with a per-call/per-RCON kill switch
- The "show me everything everyone did to every box, searchable" plane (a.k.a. the XKeyscore energy)

## Status (2026-06-23)
**Control plane is live end-to-end** (Django 5.1 + Postgres on `db.example.com`).

Working:
- **Trust spine:** tenant model, tenant-scoped join tokens, enrollment state
  machine (`PENDING → ACTIVE → REVOKED`), dev two-tier CA, SPIFFE leaf certs
  (`spiffe://pow3rtool/<tenant>/node/<id>`), approve-by-fingerprint, key-continuity
  renewal. Tenant isolation + revocation tested.
- **XConnect control link** (`orthanc-control.service`, mTLS HTTP/JSON, `:8443`):
  client-cert → `SystemIdentity` → tenant, every response hard-scoped. Routes:
  `hello`, `allowlist`, `report` (tunnel liveness), `whoami`/`authorize` (OBO),
  `sign` (enroll/renew relay).
- **Authorization (the perimeter):** `Grant` model — `subject → verb_class`,
  **default-deny**, verb-class hierarchy. Evaluated per call via the control link
  for OBO principals. Commands are authorized for the caller’s tenant and
  attributed to the human principal.
- **Operator SSO** (Entra, cert credential) + a **live console**: XConnect/node
  liveness (green/grey freshness), fleet-by-tenant, approve/revoke. (The "Board"
  liveness slice; full per-call event log is next.)
- Nodes carry a human **`description`** (operator-set) surfaced to host discovery
  so agents map intent ("the database box") → an opaque hostname.

Not yet: **fleet bootstrap** (join-token-gated install/enroll ingress + **bulk
approve**), **release signing + binary registry** for signed self-update, cert
**auto-renewal over the tunnel** (renewal logic exists; the scheduled loop is
pending), and the **full tamper-evident Call log** (liveness/report + per-call
`CALL` lines today). See [`../ARCHITECTURE.md`](../ARCHITECTURE.md).

### Dev quickstart
```bash
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
# DB creds live in .env (gitignored), pointing at db.example.com
./venv/bin/python manage.py migrate
./venv/bin/python manage.py init_ca                       # dev root + intermediate -> ca/pki/
./venv/bin/python manage.py create_tenant example --name "example fleet"
./venv/bin/python manage.py mint_join_token example    # prints the raw token ONCE
./venv/bin/python manage.py runserver 127.0.0.1:8099
```
Drive enrollment with the stand-in agent (real client is `RCON/reference`):
```bash
./venv/bin/python scripts/enroll_client.py --tenant example register --token pjt_... --name lab-01
./venv/bin/python manage.py list_enrollments --state pending
./venv/bin/python manage.py approve_enrollment <fingerprint-prefix> --name lab-01   # approve by KEY, never hostname
./venv/bin/python scripts/enroll_client.py --tenant example poll                 # -> ACTIVE, cert verified
```
Operator CLI: `create_tenant`, `mint_join_token`, `list_enrollments`,
`approve_enrollment`, `revoke_enrollment`, `init_ca`. Operators:
`grant_operator <upn> --tier admin`, `revoke_operator`, `list_operators`.
Tests: `manage.py test`. The Django admin (`/admin/`) also has approve/revoke
actions (`createsuperuser`).

### Operator SSO (Entra ID)
Delegated OIDC against `contoso.onmicrosoft.com` via MSAL with a **certificate**
credential (no secret; key in `entra/`). AuthZ = Entra **app role** `orthanc.admin`
(→ admin tier) UNION the local `Operator` table (break-glass), highest wins.
Endpoints: `/oidc/login`, `/oidc/callback`, `/oidc/logout`, `/oidc/me`.

### Tenancy model (by design — read before "fixing" cross-tenant visibility)
Orthanc operators are **enterprise administrators, global across all tenants** —
there is intentionally **no per-operator tenant scoping**. An operator (any tier)
can see every tenant's fleet, grants, and audit/Witchhunt output. This is correct
for the deployment model: **the tenants ("device owners") never touch Orthanc at
all** — they manage their own devices exclusively through XConnect's OBO-gated
Caller (per-principal + per-verb authZ, default-deny). Orthanc is the operator
console for the org that *runs* the fabric; the per-tenant boundary lives at
XConnect, not between Orthanc operators. So cross-tenant Witchhunt visibility is
an intended property of an admin console, **not** a data-isolation defect. (If a
future deployment needs mutually-distrusting operator orgs or need-to-know
partitioning, *that* is when an operator↔tenant binding + audit filtering would be
added — it is explicitly out of scope today.)

### Deployment
Runs as **`orthanc.service`** (systemd → gunicorn on `127.0.0.1:8099`):
```bash
sudo systemctl status orthanc          # gunicorn, 3 workers; logs: /var/log/orthanc.log
sudo systemctl restart orthanc         # after code changes
sudo systemctl status orthanc-control  # mTLS control listener :8443; logs: /var/log/orthanc-control.log
sudo systemctl restart orthanc-control # after control-link / authZ code changes
./venv/bin/python manage.py collectstatic --noinput   # after static changes
```
The control listener (`run_control`) is **XConnect-only** — bind it to a private
interface and firewall `:8443` to XConnect sources.
nginx vhost: `/ai/orthanc/nginx.conf` (serves `orthanc.example.com` +
`pow3rtool.example.com`, self-signed origin cert in `/etc/ssl/orthanc/`, Cloudflare
fronts public TLS in **Full** mode). `/static/` served from `staticfiles/`.
