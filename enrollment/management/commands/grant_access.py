from django.core.management.base import BaseCommand, CommandError

from enrollment.models import Grant, Tenant


class Command(BaseCommand):
    help = "Grant a Caller principal (UPN or group) a verb-class on a tenant's nodes."

    def add_arguments(self, parser):
        parser.add_argument("tenant", help="tenant slug")
        parser.add_argument("subject", help="principal UPN (e.g. you@contoso.onmicrosoft.com) or group name")
        parser.add_argument("--kind", default=Grant.Kind.USER, choices=[k.value for k in Grant.Kind])
        parser.add_argument("--verb-class", default=Grant.VerbClass.READONLY,
                            choices=[v.value for v in Grant.VerbClass])
        parser.add_argument("--require-confirmation", action="store_true",
                            help="high-risk use needs explicit human step-up (not yet enforced end-to-end)")
        parser.add_argument("--by", default="cli")

    def handle(self, *args, **opts):
        try:
            tenant = Tenant.objects.get(slug=opts["tenant"])
        except Tenant.DoesNotExist:
            raise CommandError(f"no such tenant '{opts['tenant']}'")
        g, created = Grant.objects.update_or_create(
            tenant=tenant, subject_kind=opts["kind"], subject=opts["subject"],
            defaults={"verb_class": opts["verb_class"],
                      "require_confirmation": opts["require_confirmation"],
                      "is_active": True, "created_by": opts["by"]},
        )
        verb = "created" if created else "updated"
        self.stdout.write(self.style.SUCCESS(
            f"{verb} grant: {tenant.slug} {g.subject_kind}:{g.subject} -> {g.verb_class}"
            f"{' (confirm-required)' if g.require_confirmation else ''}"))
