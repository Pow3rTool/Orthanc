from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

from enrollment.models import Tenant


class Command(BaseCommand):
    help = "Create a fleet tenant (the <tenant> in the SPIFFE id and registration URL)."

    def add_arguments(self, parser):
        parser.add_argument("slug", help="lowercase slug, e.g. 'example'")
        parser.add_argument("--name", default="", help="human-friendly display name")

    def handle(self, *args, **opts):
        tenant = Tenant(slug=opts["slug"], name=opts["name"])
        try:
            tenant.full_clean()
        except ValidationError as exc:
            raise CommandError("; ".join(f"{k}: {', '.join(v)}" for k, v in exc.message_dict.items()))
        tenant.save()
        self.stdout.write(self.style.SUCCESS(f"created tenant '{tenant.slug}' ({tenant.id})"))
