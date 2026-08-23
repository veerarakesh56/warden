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
    is not enough - the ACCOUNTID pattern alone satisfies that, so the test would pass even with the
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


def test_non_aws_cloud_secrets_are_masked_gcp_and_azure():
    """AEGIS runs on any cloud, so redaction must cover GCP and Azure credentials too, not only AWS.
    GCP OAuth tokens, Azure storage AccountKeys (bare and in connection strings) and Azure SAS
    signatures all realistically appear in incident logs on those platforms."""
    secrets = [
        ("bearer ya29.a0AfH6SMBx7longGcpOAuthTokenValue1234567890", "ya29.a0AfH6SMBx7longGcpOAuthTokenValue1234567890"),
        ("DefaultEndpointsProtocol=https;AccountName=st;AccountKey=YmFzZTY0QXp1cmVLZXlWYWx1ZTk5==;x",
         "YmFzZTY0QXp1cmVLZXlWYWx1ZTk5=="),
        ("AccountKey=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFi==", "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFi=="),
        ("https://s.blob.core.windows.net/c?sv=2021&sig=abcDEF123SasSignatureXyz789", "abcDEF123SasSignatureXyz789"),
    ]
    for text, secret in secrets:
        assert secret not in redact(text).text, f"{secret!r} (non-AWS cloud secret) leaked"


def test_session_cookies_npm_and_github_pat_are_masked():
    """Session cookies are live bearer credentials (theft = account takeover); npm _authToken and
    GitHub fine-grained PATs (github_pat_) are publish credentials that flood CI/build logs. Token
    literals are split so this file does not itself trip a secret scanner."""
    assert "8f9a7b6c5d4e3f2a" not in redact("Set-Cookie: sessionid=8f9a7b6c5d4e3f2a; Path=/").text
    assert "a1b2c3d4e5f6a7b8" not in redact("Cookie: PHPSESSID=a1b2c3d4e5f6a7b8").text
    assert "0000abcd1234efgh" not in redact("Set-Cookie: JSESSIONID=0000abcd1234efgh; Secure").text
    npm_token = "npm_" + "aB3dE5fG7hI9jK1lM3nO5pQ7"
    assert npm_token not in redact(f"//registry.npmjs.org/:_authToken={npm_token}").text
    pat = "github_pat_" + "11ABCDE0aZ9wKfN3pQrLxYbVzTmEs"
    assert pat not in redact(f"remote: invalid credentials for {pat}").text


def test_http_basic_auth_and_kubeconfig_secrets_are_masked():
    """HTTP Basic auth (base64 of user:pass) and a kubeconfig's client-key-data / certificate-data
    are credentials that appear in incident logs on any platform - Basic follows the same shape as
    Bearer, and the kube data keys are keyed base64 values."""
    assert "dXNlcjpzM2NyM3RwYXNz" not in redact("Authorization: Basic dXNlcjpzM2NyM3RwYXNz").text
    assert "cHJpdmF0ZWtleWRhdGE" not in redact("client-key-data: cHJpdmF0ZWtleWRhdGE=").text
    assert "LS0tQ0VSVGRhdGE" not in redact("client-certificate-data: LS0tQ0VSVGRhdGE=").text
    # a benign word "basic" is not a credential
    assert "plan" in redact("the basic plan is free").text


def test_query_param_credentials_are_masked():
    """URLs with ?password= / &token= / ?api_key= are ubiquitous in HTTP access logs and webhook
    configs; the leading ? or & is a real delimiter, and the value must stop at the next &param."""
    assert "SuperSecretPw99" not in redact("https://x.io/cb?password=SuperSecretPw99&next=/home").text
    assert "abc123def456ghi789" not in redact("GET /reset?access_token=abc123def456ghi789 HTTP/1.1").text
    assert "/home" in redact("https://x.io/cb?password=SuperSecretPw99&next=/home").text, "over-masked past &"


def test_a_comma_bearing_secret_is_masked_whole_not_just_the_head():
    """A secret containing a comma was leaking its tail (only the part before the comma was masked).
    Now the whole value is masked - but a comma that begins a NEW key=value pair still stops it, so
    an ordinary `k=v1,k2=v2` config pair is not gobbled."""
    assert "defSECRET" not in redact("password: abc,defSECRET").text
    assert "Zq9mK" not in redact("password=aB3xy,Zq9mK").text
    assert "key2=v2" in redact("password=v1,key2=v2 next").text, "gobbled the next pair"


def test_webhook_urls_with_a_token_in_the_path_are_masked():
    """Slack/Discord/Teams incoming-webhook URLs carry the credential in the PATH - the whole URL is
    the secret. No key=value, no vendor prefix, so only a dedicated pattern catches them."""
    # Built from split literals so this test file does not itself contain a complete webhook URL
    # that a secret scanner (GitHub push protection) would flag as a live credential.
    slack = "https://hooks.slack.com/services" + "/T00000000/B00000000/abcdEFGHijklMNOPqrstUVWX"
    disc = "https://discord.com/api/webhooks" + "/123456789/tokenABCdef_123"
    assert "abcdEFGHijklMNOPqrstUVWX" not in redact(f"alert to {slack} sent").text
    assert "tokenABCdef_123" not in redact(f"posted {disc}").text


def test_secrets_in_json_values_are_masked():
    """Structured (JSON) logs are ubiquitous, and a credential there has the key's closing quote
    between the keyword and the colon (`\"password\": \"x\"`) - which the keyed-value pattern missed.
    A non-credential JSON value must NOT be over-masked."""
    assert "s3cr3tJsonValue" not in redact('{"password": "s3cr3tJsonValue"}').text
    assert "AbCdEf123456key" not in redact('{"api_key":"AbCdEf123456key"}').text
    assert "value42" in redact('{"config": "value42"}').text, "benign JSON value over-masked"


def test_url_encoded_email_is_masked():
    """A URL-encoded email (`%40` for `@`, normal in HTTP access logs) reads as the email to both
    the model and an operator, so the encoding must not be a redaction bypass. A plain email stays
    masked too."""
    assert "admin%40corp.example.com" not in redact("user=admin%40corp.example.com hit /login").text
    assert "bob@corp.io" not in redact("bob@corp.io paged").text


def test_high_value_credentials_in_logs_are_masked():
    """The classes an adversarial review found leaking into the model in the clear: DB
    connection-string passwords, PEM private keys, bearer tokens, the AWS secret access key (the
    credential paired with the AKIA id), and password=/secret= assignments. These are realistic in
    a misconfig/credential-leak incident log - the exact input this tool exists to handle."""
    secrets = [
        ("postgres://svc:S3cretPass@10.0.0.5:5432/orders", "S3cretPass"),
        ("mysql://root:hunter2xyz@dbhost/app", "hunter2xyz"),
        ("redis://:my-redis-pass1@cache:6379", "my-redis-pass1"),
        ("Authorization: Bearer abc123def456ghi789jkl", "abc123def456ghi789jkl"),
        ("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA7f8v2n\n-----END RSA PRIVATE KEY-----",
         "MIIEpAIBAAKCAQEA7f8v2n"),
        ("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
         "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
        ("db_password=SuperSecret123", "SuperSecret123"),
        ("client_secret: my-oauth-secret-value", "my-oauth-secret-value"),
        ("token xoxb-123456789-abcdefABCDEF", "xoxb-123456789-abcdefABCDEF"),
        ("deploy key glpat-abcDEF1234567890", "glpat-abcDEF1234567890"),
    ]
    for text, secret in secrets:
        assert secret not in redact(text).text, f"{secret!r} leaked to the model"


def test_credential_patterns_do_not_over_mask_benign_config():
    """The credential patterns must not eat ordinary evidence: a path, a date, a plain word, a
    non-secret key=value. Over-redaction destroys the very evidence the model reasons about."""
    for text, benign in [
        ("access_log=/var/log/app.log", "/var/log/app.log"),
        ("the password policy requires rotation", "policy"),
        ("broker_topic=orders.v2", "orders.v2"),
        ("retry_count=5 attempts", "retry_count"),
        ("see https://github.com/org/repo", "github.com"),
    ]:
        assert benign in redact(text).text, f"{benign!r} was over-masked"


def test_ipv6_addresses_are_masked_like_ipv4():
    """We redact IPv4, so IPv6 (common in dual-stack k8s logs) is the same identifier. A time
    (10:02:11) - colons without a `::` or 8 groups - must survive as evidence."""
    assert "2001:db8:85a3::8a2e:370:7334" not in redact("from 2001:db8:85a3::8a2e:370:7334").text
    assert "fe80::1" not in redact("gw fe80::1").text
    assert redact("event at 10:02:11 today").size == 0, "a time was masked as an IPv6/MAC address"


def test_mac_addresses_are_masked_as_device_reidentifiers():
    """A MAC is a persistent device re-identifier (like an IP), so it is masked - in colon, dash and
    Cisco-dotted forms - but as MAC, never as IPv6, and a time is still left alone."""
    for text, mac in [("nic 00:1a:2b:3c:4d:5e up", "00:1a:2b:3c:4d:5e"),
                      ("arp 00-1A-2B-3C-4D-5E", "00-1A-2B-3C-4D-5E"),
                      ("switch 001a.2b3c.4d5e", "001a.2b3c.4d5e")]:
        r = redact(text)
        assert mac not in r.text, f"MAC {mac} leaked"
        assert "<MAC_" in r.text and "<IPV6_" not in r.text, "masked as MAC, not IPv6"
    assert redact("event at 10:02:11 today").size == 0, "a time must not be masked as a MAC"


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
