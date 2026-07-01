"""Print the Ed25519 release-signing public key (raw, base64).

Bake it into RCON at build time so the agent can verify updates offline:
    go build -ldflags "-X main.releasePubKeyB64=$(… export_release_pubkey)" .
"""
from django.core.management.base import BaseCommand

from ca import releases


class Command(BaseCommand):
    help = "Print the raw base64 Ed25519 release-signing public key (to bake into RCON)."

    def handle(self, *args, **opts):
        self.stdout.write(releases.public_key_raw_b64())
