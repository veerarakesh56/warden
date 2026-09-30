"""The redaction cases the independent review of 2026-09-28 found (A-C-4, A-C-5, A-C-22).

Each case is a value a pattern found in one place that must not survive in another, a credential
shape that passed, or an ordinary word the first fix wrongly masked.
"""

from __future__ import annotations

import pytest

from warden.graph import node_redact
from warden.models import Alert, ContextBundle
from warden.redaction import redact

ALERT = Alert(alert_id="r", name="n", severity="high", service="orders", environment="staging",
              summary="s", started_at="2026-09-28T10:00:00Z")


@pytest.mark.parametrize("found, elsewhere, value", [
    ("db_password=Tr0ub4dor", "msg=auth%20failed%20Tr0ub4dor", "Tr0ub4dor"),  # URL-encoded
    ("password=Tr0ub4dor", '{"m": "x\\nTr0ub4dor"}', "Tr0ub4dor"),              # JSON-escaped newline
    ("token=Zq81kLm02", "Zq81kLm02Zq81kLm02", "Zq81kLm02"),                     # repeated back to back
    ("secret=AbC123xyz", "raw=xAbC123xyz", "AbC123xyz"),                         # glued
    ('api_key="k9Xq2"', "retrying with key k9Xq2", "k9Xq2"),                     # short
    ("postgres://app:pw123@db", "tried pw123", "pw123"),                         # URL credential
    ("user_id=u8812", "payload for u8812", "u8812"),                             # short identifier
    ("client 10.0.3.22 ok", "retry 10.0.3.22", "10.0.3.22"),                     # short IP
])
def test_a_value_found_once_is_masked_everywhere(found, elsewhere, value):
    """A-C-4: the thresholds of the first fix let each of these survive in the second line."""
    out = redact(found + "\n" + elsewhere)
    assert value not in out.text, out.text


def test_status_codes_and_common_words_are_not_rewritten():
    out = redact("user_id=500 tenant_id=prod GET /cart HTTP 500 in prod")
    assert "HTTP 500 in prod" in out.text


def test_a_found_value_reaches_a_trusted_config_item_masked():
    ctx = ContextBundle(logs=["orders INFO user_id=u8812 logged in", "CONFIG lambda orders env=[PILOT_USER=u8812]"])
    out = node_redact({"alert": ALERT, "context": ctx})
    assert "u8812" not in " ".join(out["context"].logs)


@pytest.mark.parametrize("text, secret", [
    ('run --password "hunter2 x" now', "hunter2 x"),
    ("run --password 'hunter2'", "hunter2"),
    ('argv ["--password","pw4411"]', "pw4411"),
    ("redis-cli -h db -a Redis5ecret ping", "Redis5ecret"),
    ("curl -u admin:Curl5ecret https://x", "Curl5ecret"),
    ("sshpass -p Ssh5ecret ssh host", "Ssh5ecret"),
    ("docker login -u me -p Dock5ecret reg", "Dock5ecret"),
    ("whsec_abcdef+b5sSYspob7oD/xyz", "b5sSYspob7oD"),
    ("host ec2-54-12-34-56.compute-1.amazonaws.com", "54-12-34-56"),
    ("pod 10-0-3-22.default.pod.cluster.local", "10-0-3-22"),
    ("-----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC",  # split: the publish check
     "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"),                                   # refuses the literal
    ("Private-Lines: 2\nAAAAgQDputtybody\nAAAAsecond\nPrivate-MAC: ab", "AAAAgQDputtybody"),
])
def test_credential_shapes_that_still_passed(text, secret):
    """A-C-22, second round."""
    assert secret not in redact(text).text


@pytest.mark.parametrize("text", [
    "aws secretsmanager get-secret-value --secret-name orders-db-creds",
    "kubelet --service-account-token-ttl 3600",
    "vault login --token-file /var/run/token",
    "retry -token refresh failed",
    "gateway --api-key-header X-Api-Key",
    "sshd --passwordless enabled",
    "run --secrets-provider aws",
])
def test_ordinary_flags_are_not_masked(text):
    """A-C-22: the first flag pattern masked resource names - `orders-db-creds` then vanished from
    the evidence and from the P14 inventory."""
    assert redact(text).text == text


def test_mcp_context_lookup_returns_tool_errors_redacted_with_the_logs(monkeypatch):
    """A-C-5: the MCP handler returned raw tool errors next to redacted logs."""
    from warden import mcp_server, tools

    class _Leaky(tools.FixtureBackend):
        def metrics(self, alert):
            raise RuntimeError("could not connect to 10.0.3.22 as admin@corp.io")

    monkeypatch.setattr(mcp_server, "FixtureBackend", _Leaky)
    result = mcp_server.call_tool("gather_incident_context", {"alert_id": "inc-001"})
    payload = result.structured_content
    joined = " ".join(payload["tool_errors"])
    assert "10.0.3.22" not in joined and "admin@corp.io" not in joined, joined


def test_a_database_line_and_a_log_line_never_share_a_placeholder_for_different_hosts():
    """A-C-5: database.py pre-redacted query text with its own map, so its <IPV4_1> meant 10.9.9.9
    while the run's <IPV4_1> meant 10.0.0.5 - and the report revealed the wrong host."""
    from test_database import _Postgres, _SqlStub

    conn = _SqlStub({"pg_stat_activity": [(101, "idle in transaction", 900, "SELECT 1 -- from host='10.9.9.9'")]})
    db_lines = _Postgres.problem_ops(conn, 300)
    out = node_redact({"alert": ALERT, "context": ContextBundle(logs=["conn 10.0.0.5 ok", *db_lines])})
    mapping = out["redaction_map"]
    db_placeholder = next(p for p, v in mapping.items() if v == "10.9.9.9")
    assert db_placeholder in out["context"].logs[1]
    assert mapping[db_placeholder] == "10.9.9.9"
