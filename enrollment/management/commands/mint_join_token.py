from django.core.management.base import BaseCommand, CommandError

from enrollment.models import JoinToken, Tenant


class Command(BaseCommand):
    help = "Mint a tenant-scoped join token. The raw secret is printed ONCE."

    def add_arguments(self, parser):
        parser.add_argument("tenant", help="tenant slug")
        parser.add_argument("--ttl-minutes", type=int, default=None)
        parser.add_argument("--uses", type=int, default=1, help="max uses (default 1)")
        parser.add_argument("--label", default="")

    def handle(self, *args, **opts):
        try:
            tenant = Tenant.objects.get(slug=opts["tenant"])
        except Tenant.DoesNotExist:
            raise CommandError(f"no such tenant '{opts['tenant']}'")
        tok, raw = JoinToken.mint(
            tenant=tenant, ttl_minutes=opts["ttl_minutes"],
            max_uses=opts["uses"], label=opts["label"], created_by="cli")
        self.stdout.write(self.style.SUCCESS("join token minted (store it now — not recoverable):"))
        self.stdout.write(f"  token   : {raw}")
        self.stdout.write(f"  tenant  : {tenant.slug}")
        self.stdout.write(f"  expires : {tok.expires_at.isoformat()}")
        self.stdout.write(f"  uses    : 0/{tok.max_uses}")
