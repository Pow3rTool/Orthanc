from django.core.management.base import BaseCommand, CommandError

from enrollment.models import Enrollment
from enrollment.services import revoke


class Command(BaseCommand):
    help = "Revoke an enrollment (removes it from the allow-list)."

    def add_arguments(self, parser):
        parser.add_argument("fingerprint", help="full or unique-prefix SPKI fingerprint")
        parser.add_argument("--by", default="cli")

    def handle(self, *args, **opts):
        matches = list(Enrollment.objects.filter(spki_fingerprint__startswith=opts["fingerprint"])
                       .exclude(state=Enrollment.State.REVOKED))
        if not matches:
            raise CommandError(f"no active enrollment matching '{opts['fingerprint']}'")
        if len(matches) > 1:
            raise CommandError(f"ambiguous ({len(matches)} matches) — use more characters")
        e = revoke(matches[0], revoked_by=opts["by"])
        self.stdout.write(self.style.SUCCESS(f"revoked {e.tenant.slug}/{e.bound_name or e.spki_fingerprint[:16]}"))
