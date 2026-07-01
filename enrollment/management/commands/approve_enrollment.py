from django.core.management.base import BaseCommand, CommandError

from enrollment.models import Enrollment
from enrollment.services import EnrollmentError, approve


class Command(BaseCommand):
    help = ("Approve a PENDING enrollment by key fingerprint (never by hostname/IP). "
            "Binds name<->key and issues the signed cert.")

    def add_arguments(self, parser):
        parser.add_argument("fingerprint", help="full or unique-prefix SPKI fingerprint (or enrollment UUID)")
        parser.add_argument("--name", required=True, help="bound node name (immutable after approval)")
        parser.add_argument("--by", default="cli", help="approver identity (for the audit trail)")
        parser.add_argument("--description", default=None,
                            help="human role/description (intent-mapping for agents)")

    def handle(self, *args, **opts):
        ident = opts["fingerprint"]
        qs = Enrollment.objects.filter(state=Enrollment.State.PENDING)
        if _looks_like_uuid(ident):
            matches = list(qs.filter(id=ident))
        else:
            matches = list(qs.filter(spki_fingerprint__startswith=ident))
        if not matches:
            raise CommandError(f"no PENDING enrollment matching '{ident}'")
        if len(matches) > 1:
            raise CommandError(f"'{ident}' is ambiguous ({len(matches)} matches) — use more characters")
        e = matches[0]
        try:
            e = approve(e, bound_name=opts["name"], approved_by=opts["by"],
                        description=opts["description"])
        except EnrollmentError as exc:
            raise CommandError(str(exc))
        self.stdout.write(self.style.SUCCESS(f"approved {e.tenant.slug}/{e.bound_name}"))
        self.stdout.write(f"  spiffe_id : {e.spiffe_id}")
        self.stdout.write(f"  serial    : {e.cert_serial}")
        self.stdout.write(f"  expires   : {e.cert_not_after.isoformat()}")


def _looks_like_uuid(s: str) -> bool:
    return len(s) == 36 and s.count("-") == 4
