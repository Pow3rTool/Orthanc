import datetime as dt
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from ca import authority
from enrollment.models import SystemIdentity, Tenant


class Command(BaseCommand):
    help = ("Operator-gated mint of an infrastructure identity (e.g. an XConnect for a "
            "tenant). Writes key+cert+ca-bundle to an output dir and records it (revocable).")

    def add_arguments(self, parser):
        parser.add_argument("--tenant", default=None,
                            help="tenant slug (omit for a tower-global identity like orthanc-control)")
        parser.add_argument("--role", default="xconnect", help="role label (default: xconnect)")
        parser.add_argument("--out", required=True, help="output dir for cert/bundle (and key in lab mode)")
        parser.add_argument("--csr", default=None,
                            help="path to an externally-generated CSR — PROD path: the principal keeps "
                                 "its own private key and Orthanc only signs. Omit for the lab convenience "
                                 "that generates the keypair here.")
        parser.add_argument("--ttl-days", type=int, default=365)
        parser.add_argument("--by", default="cli")

    def handle(self, *args, **opts):
        td = settings.SPIFFE_TRUST_DOMAIN
        tenant = None
        if opts["tenant"]:
            try:
                tenant = Tenant.objects.get(slug=opts["tenant"])
            except Tenant.DoesNotExist:
                raise CommandError(f"no such tenant '{opts['tenant']}'")
            ident = SystemIdentity(tenant=tenant, role=opts["role"])
            spiffe_uri = f"spiffe://{td}/{tenant.slug}/system/{opts['role']}/{ident.id}"
        else:
            ident = SystemIdentity(tenant=None, role=opts["role"])
            spiffe_uri = f"spiffe://{td}/system/{opts['role']}"

        if opts["csr"]:
            # PROD path: principal generated its own key; Orthanc only signs the CSR.
            csr_pem = Path(opts["csr"]).read_text()
            cert_pem, spki = authority.sign_system_csr(csr_pem, spiffe_uri=spiffe_uri, ttl_days=opts["ttl_days"])
            key_pem = None
        else:
            key_pem, cert_pem, spki = authority.issue_system_cert(spiffe_uri, ttl_days=opts["ttl_days"])
        cert = x509.load_pem_x509_certificate(cert_pem.encode())

        ident.spiffe_id = spiffe_uri
        ident.spki_fingerprint = spki
        ident.cert_pem = cert_pem
        ident.cert_not_after = cert.not_valid_after_utc
        ident.created_by = opts["by"]
        ident.save()

        out = Path(opts["out"])
        out.mkdir(parents=True, exist_ok=True)
        if key_pem is not None:  # lab mode only — CSR mode never has the key
            (out / f"{opts['role']}-key.pem").write_text(key_pem)
            (out / f"{opts['role']}-key.pem").chmod(0o600)
        (out / f"{opts['role']}-cert.pem").write_text(cert_pem)
        (out / "ca-bundle.pem").write_text(authority.trust_bundle_pem())

        self.stdout.write(self.style.SUCCESS(f"minted {spiffe_uri}"))
        if key_pem is None:
            self.stdout.write("  (CSR mode — no private key generated/written; the principal holds it)")
        self.stdout.write(f"  spki fingerprint : {spki}")
        self.stdout.write(f"  not_after        : {ident.cert_not_after.isoformat()}")
        self.stdout.write(f"  wrote            : {out}/  (key 0600, cert, ca-bundle)")
