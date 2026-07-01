from django.core.management.base import BaseCommand

from enrollment.models import Enrollment


class Command(BaseCommand):
    help = "List enrollments (optionally filtered by tenant/state). Shows fingerprints to approve by."

    def add_arguments(self, parser):
        parser.add_argument("--tenant", default=None, help="filter by tenant slug")
        parser.add_argument("--state", default=None, choices=[s.value for s in Enrollment.State])

    def handle(self, *args, **opts):
        qs = Enrollment.objects.select_related("tenant").order_by("tenant__slug", "-created_at")
        if opts["tenant"]:
            qs = qs.filter(tenant__slug=opts["tenant"])
        if opts["state"]:
            qs = qs.filter(state=opts["state"])
        if not qs:
            self.stdout.write("(no enrollments)")
            return
        for e in qs:
            self.stdout.write(
                f"{e.state:8}  {e.tenant.slug:16}  fp={e.spki_fingerprint}  "
                f"name={e.bound_name or e.requested_name or '-'}  id={e.id}")
