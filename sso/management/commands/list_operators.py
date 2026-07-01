from django.core.management.base import BaseCommand

from sso.models import Operator


class Command(BaseCommand):
    help = "List provisioned operators and their tiers."

    def handle(self, *args, **opts):
        ops = Operator.objects.order_by("-is_active", "tier", "upn")
        if not ops:
            self.stdout.write("(no operators — grant one with grant_operator)")
            return
        for o in ops:
            flag = "" if o.is_active else "  [REVOKED]"
            last = o.last_login.isoformat() if o.last_login else "never"
            self.stdout.write(f"{o.tier:8}  {o.upn:40}  last_login={last}{flag}")
