from django.core.management.base import BaseCommand, CommandError

from sso.models import Operator


class Command(BaseCommand):
    help = ("Grant (or update) an operator tier by UPN/email. Bootstraps the first "
            "admin before anyone has logged in via SSO.")

    def add_arguments(self, parser):
        parser.add_argument("upn", help="operator UPN / email (e.g. you@contoso.onmicrosoft.com)")
        parser.add_argument("--tier", default=Operator.Tier.VIEWER,
                            choices=[t.value for t in Operator.Tier])
        parser.add_argument("--name", default="", help="display name (optional)")
        parser.add_argument("--by", default="cli")

    def handle(self, *args, **opts):
        upn = opts["upn"].strip().lower()
        if "@" not in upn:
            raise CommandError("upn must look like an email/UPN")
        op, created = Operator.objects.update_or_create(
            upn=upn,
            defaults={"tier": opts["tier"], "display_name": opts["name"],
                      "is_active": True, "granted_by": opts["by"]},
        )
        verb = "created" if created else "updated"
        self.stdout.write(self.style.SUCCESS(f"{verb} operator {op.upn} -> {op.tier}"))
