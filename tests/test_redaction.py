import pytest

from aegis.redaction import RedactionLeak, redact, redact_many


def test_scrubs_the_obvious_identifiers():
    text = (
        "user alice@corp.io hit 10.4.12.9 for tenant_id=acme-42 "
        "trace 3f2504e0-4f89-11d3-9a0c-0305e82c3301 acct 123456789012"
    )
    r = redact(text)
    assert "alice@corp.io" not in r.text
    assert "10.4.12.9" not in r.text
    assert "acme-42" not in r.text
    assert "3f2504e0-4f89-11d3-9a0c-0305e82c3301" not in r.text
    assert "123456789012" not in r.text
    assert r.size == 5


def test_same_value_gets_the_same_placeholder():
    """The model must still be able to tell that two lines refer to one host."""
    lines = ["conn from 10.0.0.7 failed", "retry from 10.0.0.7 failed"]
    out, mapping = redact_many(lines)
    assert out[0].split()[-2] == out[1].split()[-2]
    assert len(mapping) == 1


def test_arn_is_taken_whole_not_piecemeal():
    text = "role arn:aws:iam::123456789012:role/payments-exec denied"
    r = redact(text)
    assert "arn:aws:iam::123456789012:role/payments-exec" not in r.text
    assert "123456789012" not in r.text


def test_restore_round_trips():
    text = "alice@corp.io paged for 10.4.12.9"
    r = redact(text)
    assert r.restore(r.text) == text


def test_leak_is_fatal_not_a_warning():
    """The guard has to be able to fail, or it is not a guard.

    Force the failure case: claim a mapping for a value that redact() will not substitute, so the
    original is still present in the output when the check runs.
    """
    with pytest.raises(RedactionLeak):
        redact("plain text with no secrets", mapping={"<EMAIL_1>": "text"})


def test_clean_text_is_untouched():
    text = "checkout latency rose after the deploy"
    r = redact(text)
    assert r.text == text
    assert r.size == 0
