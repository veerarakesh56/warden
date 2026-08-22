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
    """The WHOLE ARN must become one placeholder, not just the account number masked while the
    `arn:aws:iam::` prefix and the role path leak. Asserting only that the account digits are gone
    is not enough - the AWSACCT pattern alone satisfies that, so the test would pass even with the
    ARN pattern deleted. These assertions fail unless the ARN pattern took the whole token.
    """
    text = "role arn:aws:iam::123456789012:role/payments-exec denied"
    r = redact(text)
    assert "arn:aws:iam::" not in r.text, "the ARN prefix leaked - masked piecemeal, not whole"
    assert "role/payments-exec" not in r.text, "the role path leaked - masked piecemeal, not whole"
    assert "123456789012" not in r.text
    assert r.text == "role <ARN_1> denied", "the whole ARN should collapse to a single placeholder"


def test_credentials_are_masked_jwt_and_api_keys():
    """These two patterns had NO test, so deleting the JWT row or breaking the APIKEY regex kept the
    whole suite green while a real GitHub token or JWT flowed unredacted into the model prompt - and
    the MCP redact_text tool advertises masking exactly these. redact() only raises on a MATCHED
    value that survives, so a pattern that silently stops matching is invisible without this."""
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    assert jwt not in redact(f"authorization bearer {jwt}").text
    for key in ("sk-ant-api03-AbCdEf12345678", "sk-proj-abcdef123456", "ghp_AbCdEf1234567890abcd",
                "AKIAIOSFODNN7EXAMPLE"):
        assert key not in redact(f"leaked {key} in a log line").text, f"{key} was not masked"


def test_ipv6_addresses_are_masked_like_ipv4():
    """We redact IPv4, so IPv6 (common in dual-stack k8s logs) is the same identifier. But a time
    (10:02:11) and a MAC (00:1a:2b:3c:4d:5e) - colons without a `::` or 8 groups - must survive."""
    assert "2001:db8:85a3::8a2e:370:7334" not in redact("from 2001:db8:85a3::8a2e:370:7334").text
    assert "fe80::1" not in redact("gw fe80::1").text
    assert redact("event at 10:02:11 today").size == 0, "a time was masked as an IPv6 address"
    assert redact("nic 00:1a:2b:3c:4d:5e up").size == 0, "a MAC was masked as an IPv6 address"


def test_iso_date_is_not_mistaken_for_a_phone_number():
    """Regression: the PHONE pattern matched YYYY-MM-DD, so every log line's timestamp was masked as
    a phone and the temporal evidence was lost. A real phone must still be masked."""
    r = redact("2026-08-21T10:02:11Z checkout ERROR 500 after deploy")
    assert "2026-08-21" in r.text, "the date was masked as a phone number"
    assert redact("2026-08-21").size == 0
    # a genuine phone number is still caught
    assert "+1 415-555-0142" not in redact("oncall +1 415-555-0142 paged").text


def test_restore_round_trips():
    text = "alice@corp.io paged for 10.4.12.9"
    r = redact(text)
    assert r.restore(r.text) == text


def test_leak_guard_can_fire():
    """The guard has to be able to fail, or it is not a guard.

    `redact()` itself can no longer produce a leak - a final literal sweep replaces every mapped
    original before the check (see `test_survives_a_value_embedded_in_a_larger_token`). So the guard
    is tested directly: hand `_assert_clean` an output where a mapped original survived, and it must
    raise. This is the invariant the sweep upholds; the test proves the check that backs it works.
    """
    from aegis.redaction import _assert_clean

    with pytest.raises(RedactionLeak):
        _assert_clean("the secret alice@corp.io is still here", {"<EMAIL_1>": "alice@corp.io"})


def test_survives_a_value_embedded_in_a_larger_token():
    """Live-cluster regression: a Kubernetes event embeds the pod UID inside a longer token
    (`..._default_<uid>_0`) where a trailing-`\\b` regex misses one of two occurrences. The final
    literal sweep must catch the copy the pattern skipped."""
    uid = "534e3098-a21e-415b-8010-24ae0fb955bb"
    text = f"reserve name checkout_default_{uid}_0 pod=({uid})"
    r = redact(text)
    assert uid not in r.text
    assert r.text.count("<UUID_1>") == 2, "both occurrences masked, same placeholder"


def test_clean_text_is_untouched():
    text = "checkout latency rose after the deploy"
    r = redact(text)
    assert r.text == text
    assert r.size == 0


def test_a_secret_that_looks_like_a_placeholder_token_does_not_corrupt():
    """Pathological collision: a tenant value literally equal to another placeholder's internal text.

    `tenant_id=UUID_1` maps to `<TENANT_1>`, while a real UUID nearby maps to `<UUID_1>`. A naive
    literal sweep would rewrite the `UUID_1` inside `<UUID_1>` to `<TENANT_1>`, producing the mangled
    `<<TENANT_1>>` - two distinct secrets collapsed onto one label, and a broken restore. The sweep
    must leave existing placeholders alone, and the leak guard must not false-alarm on the coincidence.
    """
    text = "tenant_id=UUID_1 trace 3f2504e0-4f89-11d3-9a0c-0305e82c3301"
    r = redact(text)  # must not raise RedactionLeak
    assert "<<" not in r.text and ">>" not in r.text, f"corrupted placeholder: {r.text!r}"
    assert r.text.count("<UUID_1>") == 1
    assert r.text.count("<TENANT_1>") == 1
    assert r.restore(r.text) == text, "restore must reproduce the original exactly"


def test_redaction_round_trips_through_restore():
    text = (
        "user bob@corp.io on 192.168.1.7 tenant_id=acme-9 "
        "trace 9f8b7c6d-1234-4a5b-8c9d-0e1f2a3b4c5d twice: 192.168.1.7"
    )
    r = redact(text)
    assert r.restore(r.text) == text
