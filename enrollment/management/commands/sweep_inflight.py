"""Backstop for the Witchhunt 'running' set (InFlightCall).

A running row is normally cleared the instant its terminal CallEvent arrives, and
a restarted XConnect clears its own prior-incarnation rows on the next report. This
command is the belt-and-suspenders for the remaining case: a call whose terminal
event was simply lost (a control-link blip dropped it, or the node hung past any
sane runtime) while its XConnect kept running — so the instance-epoch reset never
fires. Such rows would otherwise read as "executing" forever.

Rows older than --minutes are aged into an honest 'orphaned' terminal CallEvent
(outcome unknown — recorded, not silently dropped) and removed. Run from cron,
e.g. every minute:

    manage.py sweep_inflight --minutes 60
"""
from __future__ import annotations

from django.core.management.base import BaseCommand
from django.utils import timezone

from enrollment.models import InFlightCall, Tenant


class Command(BaseCommand):
    help = "Orphan + clear InFlightCall ('running') rows older than --minutes."

    def add_arguments(self, parser):
        parser.add_argument("--minutes", type=int, default=60,
                            help="Sweep running rows started more than this many "
                                 "minutes ago (default 60). Set above your longest "
                                 "legitimate command runtime.")
        parser.add_argument("--tenant", default="",
                            help="Limit to one tenant slug (default: all tenants).")

    def handle(self, *args, **opts):
        minutes = opts["minutes"]
        cutoff = timezone.now() - timezone.timedelta(minutes=minutes)
        qs = InFlightCall.objects.filter(started_at__lt=cutoff)
        if opts["tenant"]:
            try:
                qs = qs.filter(tenant=Tenant.objects.get(slug=opts["tenant"]))
            except Tenant.DoesNotExist:
                self.stderr.write(f"no such tenant '{opts['tenant']}'")
                return
        n = InFlightCall.orphan(qs, status="orphaned",
                                reason=f"swept: no terminal event after {minutes}m")
        self.stdout.write(
            f"swept {n} stale running row(s) older than {minutes}m "
            f"(before {cutoff.isoformat()}) into orphaned events")
