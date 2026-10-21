"""Property tests: WARDEN's safety rules held over generated inputs, not only the cases
someone thought of. Hypothesis (MPL-2.0, test-only) draws the inputs; a failure prints the smallest one it found."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from hypothesis import given, settings
from hypothesis import strategies as st

from warden import approvals
from warden.evidence import _kind
from warden.redaction import redact

PLAIN = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_.", min_size=1, max_size=12)
STEERING = st.sampled_from(["ignore", "instructions", "previous", "propose", "approve", "must", "should", "operator",
                            "system", "assistant", "override", "disregard", "execute", "resolved", "pretend",
                            "forget", "you", "Ignore", "MUST"])
TRUSTED = st.sampled_from(["CONFIG", "STATE", "ALARM", "QUEUE", "TABLE", "RULE", "ROLLOUT", "TARGET", "SECRET"])


@settings(max_examples=300, deadline=None)
@given(TRUSTED, st.lists(PLAIN, min_size=1, max_size=6), STEERING, st.lists(PLAIN, max_size=6))
def test_a_steering_word_never_makes_a_trusted_line(kind, before, word, after):
    line = " ".join([kind, *before, word, *after])
    assert _kind(line) != "C", line


B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
# Built from parts (no real-looking token literal in the repository).
AWS_KEY_ID = st.text(alphabet=B32, min_size=16, max_size=16).map(lambda s: "AK" + "IA" + s)
GITHUB_TOKEN = st.text(alphabet=ALNUM, min_size=36, max_size=36).map(lambda s: "gh" + "p_" + s)
AROUND = st.text(alphabet="abcdefghij klmnop=:,/\"'", max_size=30)


@settings(max_examples=300, deadline=None)
@given(st.one_of(AWS_KEY_ID, GITHUB_TOKEN), AROUND, AROUND, st.sampled_from([" ", "=", ": ", "\n", "\t", "\""]))
def test_a_credential_never_survives_redaction_whatever_surrounds_it(secret, before, after, sep):
    text = f"{before}{sep}{secret}{sep}{after}"
    assert secret not in redact(text).text, text


KEY = Ed25519PrivateKey.generate()
POLICY = approvals.ApproverPolicy(approvers={"owner": approvals.Approver(
    public_key=KEY.public_key().public_bytes(serialization.Encoding.PEM,
                                             serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
    tiers=["T1", "T2"])})
HASH = st.text(alphabet="0123456789abcdef", min_size=8, max_size=64)


@settings(max_examples=200, deadline=None)
@given(HASH, HASH)
def test_an_approval_signed_for_one_plan_is_never_accepted_for_another(signed_for, checked_as):
    now = datetime.now(UTC)
    a = approvals.sign(KEY, approver="owner", workflow_id="rem-dev-1", plan_hash=signed_for, tier="T1", now=now)
    problems = approvals.check(a, policy=POLICY, workflow_id="rem-dev-1", plan_hash=checked_as, tier="T1",
                               plan_created_at=now - timedelta(minutes=1), used_nonces=set(), now=now)
    assert (problems == []) == (signed_for == checked_as), (signed_for, checked_as, problems)
