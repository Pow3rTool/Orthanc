"""Publish + sign an RCON binary as a Release (version × os × arch)."""
import shutil
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from ca import releases
from enrollment.models import Release


class Command(BaseCommand):
    help = "Hash + Ed25519-sign an RCON binary and register it as a Release."

    def add_arguments(self, parser):
        parser.add_argument("version", help="e.g. v0.2.0")
        parser.add_argument("--binary", required=True, help="path to the built rcon binary")
        parser.add_argument("--os", default="linux", dest="goos")
        parser.add_argument("--arch", default="amd64", dest="goarch")
        parser.add_argument("--notes", default="")
        parser.add_argument("--by", default="")

    def handle(self, *args, **o):
        src = Path(o["binary"])
        if not src.is_file():
            raise CommandError(f"no such binary: {src}")
        data = src.read_bytes()
        sha = releases.sha256_hex(data)
        sig = releases.sign(o["version"], o["goos"], o["goarch"], sha)

        reldir = Path(settings.CA_DIR) / "releases" / o["version"]
        reldir.mkdir(parents=True, exist_ok=True)
        blob = reldir / f"rcon-{o['goos']}-{o['goarch']}"
        shutil.copyfile(src, blob)

        _, created = Release.objects.update_or_create(
            version=o["version"], goos=o["goos"], goarch=o["goarch"],
            defaults=dict(sha256=sha, signature=sig, size=len(data),
                          blob_path=str(blob.relative_to(settings.CA_DIR)),
                          notes=o["notes"], published_by=o["by"]))
        self.stdout.write(self.style.SUCCESS(
            f"{'published' if created else 'updated'} rcon {o['version']} "
            f"({o['goos']}/{o['goarch']}) sha256={sha[:16]}… size={len(data)}B — signed."))
