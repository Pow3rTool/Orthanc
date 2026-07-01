"""Regression tests for the enrollment trust spine."""
from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID
from django.test import TestCase

from ca import authority
from .models import Enrollment, JoinToken, Tenant
from .services import EnrollmentError, approve, register, revoke


def make_csr() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([])).sign(key, hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.PEM).decode()


class EnrollmentFlowTests(TestCase):
    def setUp(self):
        self.tenant = Tenant.objects.create(slug="acme", name="Acme")
        self.token_obj, self.token = JoinToken.mint(tenant=self.tenant)

    def test_register_then_approve_issues_cert_with_spiffe_san(self):
        e = register(tenant_slug="acme", csr_pem=make_csr(), join_token_raw=self.token)
        self.assertEqual(e.state, Enrollment.State.PENDING)

        e = approve(e, bound_name="node-a", approved_by="tester")
        self.assertEqual(e.state, Enrollment.State.ACTIVE)
        self.assertEqual(e.bound_name, "node-a")

        leaf = x509.load_pem_x509_certificate(e.cert_pem.encode())
        san = leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        uris = san.get_values_for_type(x509.UniformResourceIdentifier)
        self.assertEqual(uris, [f"spiffe://pow3rtool/acme/node/{e.id}"])

        # Chains to the issuing intermediate and root.
        bundle = self._bundle()
        leaf.verify_directly_issued_by(bundle["int"])
        bundle["int"].verify_directly_issued_by(bundle["root"])

    def test_register_is_idempotent_by_key_and_does_not_spend_token(self):
        csr = make_csr()
        first = register(tenant_slug="acme", csr_pem=csr, join_token_raw=self.token)
        # Re-register same key with a junk token: returns same enrollment, no new spend.
        again = register(tenant_slug="acme", csr_pem=csr, join_token_raw="pjt_junk")
        self.assertEqual(first.id, again.id)
        self.token_obj.refresh_from_db()
        self.assertEqual(self.token_obj.uses, 1)

    def test_spent_token_is_rejected(self):
        register(tenant_slug="acme", csr_pem=make_csr(), join_token_raw=self.token)
        with self.assertRaises(EnrollmentError):
            register(tenant_slug="acme", csr_pem=make_csr(), join_token_raw=self.token)

    def test_unknown_tenant_and_bad_token_rejected(self):
        with self.assertRaises(EnrollmentError):
            register(tenant_slug="ghost", csr_pem=make_csr(), join_token_raw=self.token)
        with self.assertRaises(EnrollmentError):
            register(tenant_slug="acme", csr_pem=make_csr(), join_token_raw="pjt_nope")

    def test_token_scoped_to_its_tenant(self):
        other = Tenant.objects.create(slug="other", name="Other")
        with self.assertRaises(EnrollmentError):
            register(tenant_slug="other", csr_pem=make_csr(), join_token_raw=self.token)
        self.assertFalse(other.enrollments.exists())

    def test_revoke_leaves_allow_list(self):
        e = approve(register(tenant_slug="acme", csr_pem=make_csr(), join_token_raw=self.token),
                    bound_name="node-a")
        e = revoke(e)
        self.assertEqual(e.state, Enrollment.State.REVOKED)
        self.assertFalse(
            Enrollment.objects.filter(tenant=self.tenant, state=Enrollment.State.ACTIVE).exists())

    def test_cannot_approve_non_pending(self):
        e = approve(register(tenant_slug="acme", csr_pem=make_csr(), join_token_raw=self.token),
                    bound_name="node-a")
        with self.assertRaises(EnrollmentError):
            approve(e, bound_name="node-a-again")

    def _bundle(self):
        pem = authority.trust_bundle_pem()
        certs, buf = [], []
        for line in pem.splitlines(keepends=True):
            buf.append(line)
            if "END CERTIFICATE" in line:
                certs.append(x509.load_pem_x509_certificate("".join(buf).encode()))
                buf = []
        return {"root": certs[0], "int": certs[1]}
