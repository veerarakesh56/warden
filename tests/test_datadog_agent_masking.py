"""The lab's Datadog agent masks what it sends (owner, 2026-10-21: "the shop's logs leave unmasked"): logs stay on -
they are WARDEN's Datadog evidence - and every line, a container's or an OpenTelemetry one, passes the agent's global
mask_sequences first. The rules are held to the same corpus as WARDEN's own patterns (test_redaction_classes).

The agent runs them as RE2, and they are applied here with Python's `re` under re.ASCII, so the digit, word,
space and word-boundary classes are ASCII-only in both (review, PR 130). What still differs, and why it does not
matter here: Python's end-of-text anchor also matches before a trailing newline, and the private-key rule ends
with one - a log line here carries no trailing newline; and RE2 has no lookaround or backreferences, which
test_the_rules_are_well_formed_mask_sequences_in_re2 refuses in every rule."""

from __future__ import annotations

import json
import pathlib
import re
import sys

import pytest
import yaml

from fakes import HUNTER2
from privacy_corpus import KEPT, MASKED

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import deploy_fullstack_apps as tool  # after the sys.path line above

VALUES = yaml.safe_load(tool.DATADOG_VALUES.read_text(encoding="utf-8"))
[ENV] = [e for e in VALUES["datadog"]["env"] if e["name"] == "DD_LOGS_CONFIG_PROCESSING_RULES"]
RULES = json.loads(ENV["value"])
# Classes the agent does not mask, and why (the values file says it too): host names under `.local`/`.internal` are a
# Kubernetes service's and AWS's own, everywhere in these logs, and RE2 cannot leave those out selectively.
NOT_AT_THE_AGENT = {("HOSTNAME", "printer.local offline")}


def _mask(text: str) -> str:
    for rule in RULES:
        text = re.sub(rule["pattern"], rule["replace_placeholder"], text, flags=re.ASCII)
    return text


def test_the_rules_are_well_formed_mask_sequences_in_re2():
    assert RULES
    for rule in RULES:
        assert rule["type"] == "mask_sequences"
        assert rule["name"]
        assert rule["replace_placeholder"].startswith(("[masked:", "://[masked]"))
        # RE2: no lookaround, no backreference, no possessive or atomic group; flags only scoped or leading.
        assert not re.search(r"\(\?[=!<>]|\(\?<[=!]|\\[1-9]|[*+?}]\+|\(\?>", rule["pattern"]), rule["name"]
        re.compile(rule["pattern"], re.ASCII)


@pytest.mark.parametrize(("kind", "text"), [(k, t) for k, texts in MASKED.items() for t in texts
                                            if (k, t) not in NOT_AT_THE_AGENT])
def test_every_class_is_masked_by_the_agent(kind, text):
    out = _mask(text)
    assert "[masked:" in out, (kind, text, out)


def test_the_agent_masks_a_whole_traceback_line():
    line = ("ERROR orders-api GET /orders failed: OperationalError: connection to postgresql://shop:" + HUNTER2 + "x" +
            "@10.0.4.21:5432 refused for user " + "priya" + "@" + "corp.example")
    out = _mask(line)
    assert HUNTER2 not in out
    assert "10.0.4.21" not in out
    assert "corp.example" not in out


@pytest.mark.parametrize("text", KEPT)
def test_the_evidence_reaches_datadog_as_it_is(text):
    assert _mask(text) == text


def test_the_deploy_installs_the_agent_with_the_masking_values():
    src = (ROOT / "scripts" / "deploy_fullstack_apps.py").read_text(encoding="utf-8")
    block = src[src.index("def deploy_datadog"):src.index("def ", src.index("def deploy_datadog") + 10)]
    assert '"--values", str(DATADOG_VALUES)' in block
    assert "datadog.logs.enabled=true" in block  # logs on: they are WARDEN's evidence


def test_span_tags_are_masked_by_the_same_rules():
    [apm] = [e for e in VALUES["datadog"]["env"] if e["name"] == "DD_APM_REPLACE_TAGS"]
    tags = json.loads(apm["value"])
    assert [(t["pattern"], t["repl"]) for t in tags] == [(r["pattern"], r["replace_placeholder"]) for r in RULES]
    assert {t["name"] for t in tags} == {"*"}  # every tag


def test_no_address_attribute_is_ever_only_hashed():
    """Review (PR 130): an address attribute added to the hashed list would be as good as clear - every IPv4
    address can be hashed and matched. Any key naming an address or an IP is dropped, never hashed."""
    hashed = set(tool.OTEL_HASHED)
    assert not {k for k in hashed if any(w in k for w in ("address", "addr", "ip", "peer"))}, hashed


def test_the_collector_hashes_who_and_drops_url_queries_before_any_exporter():
    for datadog in (True, False):
        config = tool.otel_config("ap-south-2", datadog=datadog)
        actions = {a["key"]: a["action"] for a in config["processors"]["attributes/privacy"]["actions"]}
        assert actions["user.email"] == "hash"
        assert actions["url.query"] == "delete"
        for client in ("client.address", "http.client_ip", "net.peer.ip", "net.sock.peer.addr", "source.address",
                       "network.peer.address"):
            assert actions[client] == "delete", client  # an unsalted hash of an IPv4 address is reversible
        resource = {a["key"]: a["action"] for a in config["processors"]["resource/privacy"]["attributes"]}
        assert resource["k8s.pod.ip"] == "hash"
        assert resource["host.ip"] == "hash"
        assert resource["client.address"] == "delete"
        for name, pipeline in config["service"]["pipelines"].items():  # traces, metrics and logs alike
            assert "attributes/privacy" in pipeline["processors"], name
            assert "resource/privacy" in pipeline["processors"], name
            assert pipeline["processors"][-1] == "batch", name  # before the exporters, after the privacy processors
    assert "metrics" in tool.otel_config("ap-south-2", datadog=True)["service"]["pipelines"]
