"""Retention for the Witchhunt call-log.

CallEvents accumulate on every fabric call, so trim them out-of-band (cron)
rather than on the hot report path. Deletes events older than --days (default
90), optionally scoped to one tenant. Run e.g. nightly:

    manage.py prune_call_events --days 90
"""
from __future__ import annotations

from django.core.management.base import BaseCommand
from django.utils import timezone

from enrollment.models import CallEvent, Tenant


class Command(BaseCommand):
    help = "Delete call-log (Witchhunt) events older than --days."

    def add_arguments(self, parser):
        parser.add_argument("--days", type=int, default=90,
                            help="Delete events older than this many days (default 90).")
        parser.add_argument("--tenant", default="",
                            help="Limit to one tenant slug (default: all tenants).")

    def handle(self, *args, **opts):
        days = opts["days"]
        cutoff = timezone.now() - timezone.timedelta(days=days)
        qs = CallEvent.objects.filter(occurred_at__lt=cutoff)
        if opts["tenant"]:
            try:
                qs = qs.filter(tenant=Tenant.objects.get(slug=opts["tenant"]))
            except Tenant.DoesNotExist:
                self.stderr.write(f"no such tenant '{opts['tenant']}'")
                return
        n, _ = qs.delete()
        self.stdout.write(f"pruned {n} call event(s) older than {days}d (before {cutoff.isoformat()})")
