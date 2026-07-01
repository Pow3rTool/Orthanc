from django.core.management.base import BaseCommand

from ca import authority


class Command(BaseCommand):
    help = "Initialize the dev CA (root + intermediate) if absent, and print the trust bundle."

    def add_arguments(self, parser):
        parser.add_argument("--bundle", action="store_true", help="print the PEM trust bundle (root+int)")

    def handle(self, *args, **opts):
        authority.ensure_ca()
        self.stdout.write(self.style.SUCCESS("CA ready (root + issuing intermediate present)"))
        if opts["bundle"]:
            self.stdout.write(authority.trust_bundle_pem())
