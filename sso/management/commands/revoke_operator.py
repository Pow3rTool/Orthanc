from django.core.management.base import BaseCommand, CommandError

from sso.models import Operator


class Command(BaseCommand):
    help = "Revoke an operator's access by UPN (deactivates; keeps the audit row)."

    def add_arguments(self, parser):
        parser.add_argument("upn", help="operator UPN / email")

    def handle(self, *args, **opts):
        try:
            op = Operator.objects.get(upn__iexact=opts["upn"].strip())
        except Operator.DoesNotExist:
            raise CommandError(f"no operator '{opts['upn']}'")
        op.is_active = False
        op.save(update_fields=["is_active"])
        self.stdout.write(self.style.SUCCESS(f"revoked {op.upn}"))
