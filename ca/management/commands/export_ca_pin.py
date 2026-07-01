"""Print the out-of-band CA pin for `rcon enroll --ca-pin`.

Hand this to operators enrolling a node over a self-signed origin (or as
defense-in-depth): it lets the agent verify the received trust bundle and reject
an enrollment-time MITM that tries to swap in its own CA.

    rcon enroll --token pjt_… --xconnect https://… --ca-pin "$(manage.py export_ca_pin)"
"""
from django.core.management.base import BaseCommand

from ca import authority


class Command(BaseCommand):
    help = "Print the CA pin (sha256 of the root CA SPKI) to hand to `rcon enroll --ca-pin`."

    def handle(self, *args, **opts):
        self.stdout.write(authority.ca_pin())
