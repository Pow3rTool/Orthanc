"""Point an update channel (cohort) at a published release — the scream-test knob.

    promote_release canary --version v0.2.0          # dev/canary boxes converge
    promote_release stable --version v0.2.0          # …once it's proven, everyone

Nodes whose Enrollment.update_channel == <channel> converge to this release;
other channels are untouched.
"""
from django.core.management.base import BaseCommand, CommandError

from enrollment.models import ChannelTarget, Release


class Command(BaseCommand):
    help = "Set a channel's target to a published release (per os/arch)."

    def add_arguments(self, parser):
        parser.add_argument("channel", help="cohort name, e.g. stable / canary / dev")
        parser.add_argument("version", help="released version to point the channel at, e.g. v0.2.0")
        parser.add_argument("--os", default="linux", dest="goos")
        parser.add_argument("--arch", default="amd64", dest="goarch")
        parser.add_argument("--by", default="")

    def handle(self, *args, **o):
        rel = Release.objects.filter(
            version=o["version"], goos=o["goos"], goarch=o["goarch"]).first()
        if rel is None:
            raise CommandError(
                f"no such release {o['version']} ({o['goos']}/{o['goarch']}) — publish_release it first")
        ChannelTarget.objects.update_or_create(
            channel=o["channel"], goos=o["goos"], goarch=o["goarch"],
            defaults=dict(release=rel, updated_by=o["by"]))
        self.stdout.write(self.style.SUCCESS(
            f"channel '{o['channel']}' {o['goos']}/{o['goarch']} -> rcon {rel.version}"))
