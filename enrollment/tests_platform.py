from django.test import TestCase, SimpleTestCase
from django.template.loader import render_to_string
from django.utils import timezone

from ca.management.commands.run_control import _runtime_report_fields
from .models import ChannelTarget, Enrollment, Release, Tenant


class RuntimeReportTests(SimpleTestCase):
    def test_windows_report_and_bounds(self):
        fields = _runtime_report_fields({
            "version": "lab", "goarch": "amd64", "goos": "windows",
            "shell": "powershell", "os_version": "x" * 200,
            "self_update_supported": False,
        }, timezone.now())
        self.assertEqual(fields["running_goos"], "windows")
        self.assertEqual(fields["running_shell"], "powershell")
        self.assertEqual(len(fields["running_os_version"]), 120)
        self.assertIs(fields["self_update_supported"], False)

    def test_legacy_report_does_not_overwrite_platform(self):
        fields = _runtime_report_fields({"version": "old", "goarch": "amd64"}, timezone.now())
        self.assertNotIn("running_goos", fields)
        self.assertNotIn("running_shell", fields)
        self.assertNotIn("self_update_supported", fields)

    def test_non_boolean_capability_is_ignored(self):
        for value in ("false", "true", 0, 1, None, [], {}):
            with self.subTest(value=value):
                fields = _runtime_report_fields({"self_update_supported": value}, timezone.now())
                self.assertNotIn("self_update_supported", fields)


class PlatformTargetTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug="lab")
        for goos in ("linux", "windows"):
            release = Release.objects.create(version=goos + "-new", goos=goos, goarch="amd64",
                                             sha256="0" * 64, signature="test", blob_path="unused")
            ChannelTarget.objects.create(channel="stable", goos=goos, goarch="amd64", release=release)
        self.node = Enrollment.objects.create(tenant=self.tenant, spki_fingerprint="a" * 64,
                                              state=Enrollment.State.ACTIVE,
                                              running_version="old", running_goarch="amd64")

    def test_unknown_os_does_not_get_linux_target(self):
        self.assertIsNone(self.node.target_version())
        self.assertFalse(self.node.is_behind)

    def test_each_os_resolves_its_own_target(self):
        for goos in ("windows", "linux"):
            self.node.running_goos = goos
            self.assertEqual(self.node.target_version(), goos + "-new")

    def test_report_persists_without_legacy_overwrite(self):
        Enrollment.objects.filter(pk=self.node.pk).update(**_runtime_report_fields({
            "version": "lab", "goarch": "amd64", "goos": "windows",
            "shell": "powershell", "self_update_supported": False,
        }, timezone.now()))
        Enrollment.objects.filter(pk=self.node.pk).update(**_runtime_report_fields({
            "version": "lab", "goarch": "amd64",
        }, timezone.now()))
        self.node.refresh_from_db()
        self.assertEqual(self.node.running_goos, "windows")
        self.assertEqual(self.node.running_shell, "powershell")
        self.assertIs(self.node.self_update_supported, False)

    def test_console_shows_platform_and_no_unsupported_update_button(self):
        self.node.running_goos = "windows"
        self.node.running_shell = "powershell"
        self.node.self_update_supported = False
        html = render_to_string("console/tenant.html", {
            "tenant": self.tenant, "nodes": [self.node], "can_act": True,
            "State": Enrollment.State,
            "operator": {"name": "Test operator", "upn": "tester@example.invalid", "tier": "admin"},
        })
        self.assertIn("windows/amd64", html)
        self.assertIn("powershell", html)
        self.assertIn("manual updates", html)
        self.assertNotIn("update now", html)

    def test_reported_platform_is_html_escaped(self):
        payload = '<script>alert("node-metadata")</script>'
        self.node.running_goos = payload
        self.node.running_shell = payload
        self.node.running_os_version = payload
        html = render_to_string("console/tenant.html", {
            "tenant": self.tenant, "nodes": [self.node], "can_act": False,
            "State": Enrollment.State,
            "operator": {"name": "Viewer", "upn": "viewer@example.invalid", "tier": "viewer"},
        })
        self.assertNotIn(payload, html)
        self.assertIn("&lt;script&gt;", html)

    def test_platform_reporting_does_not_activate_or_reassign_node(self):
        self.node.state = Enrollment.State.PENDING
        self.node.save(update_fields=["state"])
        fields = _runtime_report_fields({
            "version": "lab", "goarch": "amd64", "goos": "windows",
            "state": Enrollment.State.ACTIVE, "tenant_id": "untrusted",
            "bound_name": "impersonated-node", "update_channel": "canary",
        }, timezone.now())
        Enrollment.objects.filter(pk=self.node.pk).update(**fields)
        self.node.refresh_from_db()
        self.assertEqual(self.node.state, Enrollment.State.PENDING)
        self.assertEqual(self.node.tenant_id, self.tenant.pk)
        self.assertEqual(self.node.bound_name, "")
        self.assertEqual(self.node.update_channel, "stable")
