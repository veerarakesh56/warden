"""The laptop certificate meets IAM Roles Anywhere's documented constraints (trust-model.html)."""

import datetime as dt
import importlib.util
import pathlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

_spec = importlib.util.spec_from_file_location(
    "roles_anywhere_cert", pathlib.Path(__file__).resolve().parents[1] / "scripts" / "roles_anywhere_cert.py")
rac = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rac)

NOW = dt.datetime(2026, 9, 28, 12, 0, tzinfo=dt.UTC)


def _csr(cn=rac.SUBJECT_CN, org=rac.ORG):
    key = ec.generate_private_key(ec.SECP256R1())
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, cn)]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    name = x509.Name(attrs)
    return x509.CertificateSigningRequestBuilder().subject_name(name).sign(key, hashes.SHA256()).public_bytes(
        serialization.Encoding.PEM)


def _issue():
    ca, leaf = rac.issue(_csr(), NOW)
    return x509.load_pem_x509_certificate(ca), x509.load_pem_x509_certificate(leaf)


def test_anchor_is_a_ca_that_may_sign_certificates():
    ca, _ = _issue()
    assert ca.version == x509.Version.v3
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    assert ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign is True
    assert isinstance(ca.signature_hash_algorithm, hashes.SHA256)


def test_leaf_is_an_end_entity_for_digital_signature_signed_by_the_anchor():
    ca, leaf = _issue()
    assert leaf.version == x509.Version.v3
    assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert leaf.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature is True
    assert isinstance(leaf.signature_hash_algorithm, hashes.SHA256)
    assert leaf.issuer == ca.subject
    leaf.verify_directly_issued_by(ca)  # raises if the signature or issuer does not match


def test_leaf_carries_the_subject_the_role_trust_policy_pins():
    _, leaf = _issue()
    assert leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "warden-operator-laptop"


def test_validity_is_one_year_and_the_anchor_outlives_the_leaf():
    ca, leaf = _issue()
    assert leaf.not_valid_after_utc - NOW == dt.timedelta(days=365)
    assert ca.not_valid_after_utc > leaf.not_valid_after_utc


def test_a_csr_for_another_subject_is_refused():
    with pytest.raises(ValueError, match="CN must be exactly"):
        rac.issue(_csr("someone-else"), NOW)


def test_each_issue_makes_a_new_ca():
    (ca1, _), (ca2, _) = _issue(), _issue()
    assert ca1.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo) != \
        ca2.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def test_a_csr_without_the_pinned_organisation_is_refused():
    """The role trust pins x509Subject/O=warden as well as the CN (independent review, 2026-09-28)."""
    with pytest.raises(ValueError, match="O must be exactly"):
        rac.issue(_csr(org=None), NOW)
    with pytest.raises(ValueError, match="O must be exactly"):
        rac.issue(_csr(org="someone"), NOW)


def test_the_key_request_asks_the_tpm_for_a_key_that_cannot_leave_it():
    """Second review (2026-09-30): nothing pinned these, so a change that made the key exportable or
    moved it off the TPM would still pass. The installed certificate was checked the same day
    (certutil: Microsoft Platform Crypto Provider, private key NOT exportable)."""
    fields = dict(line.split(" = ", 1) for line in rac.INF.splitlines() if " = " in line)
    assert fields["ProviderName"] == '"Microsoft Platform Crypto Provider"'
    assert fields["Exportable"] == "FALSE" and fields["MachineKeySet"] == "FALSE"
    assert fields["KeyAlgorithm"] == "ECDSA_P256" and fields["RequestType"] == "PKCS10"
