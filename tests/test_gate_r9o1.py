"""Register R9-O1: a key a renderer joins is withheld, and a withheld report's stub names its alert by a hash only."""

from __future__ import annotations

import hashlib

import pytest

from warden import gate

KEY = "AKIA" + "IOSFODNN7EXAMPLE"
PW = "Tr0ub4dor" + "-x9q"


@pytest.mark.parametrize("text", [
    "key AKIA**IOSFODNN7EXAMPLE**", "key AKIA*IOSFODNN7EXAMPLE*", "key AKIA~IOSFODNN7EXAMPLE~",
    "key AKIA`IOSFODNN7EXAMPLE`", "key AKIA&#73;OSFODNN7EXAMPLE", "key AKIA_IOSFODNN7EXAMPLE_",
])
def test_a_key_a_renderer_shows_joined_is_withheld(text):
    """Slack and Markdown consume emphasis, strike and code markers and decode entities: these show the key whole."""
    assert gate.enforce(text).verdict == "BLOCK", text


@pytest.mark.parametrize("text", ["**bold** report _ok_ `code`", "`secret_changed_age_s` = **1.36e+04**",
                                  "`alb_healthy_hosts` = **2** | `secrets_manager_calls` = **4**",
                                  "If it is credentials: <SECRET_1> the node role. _(Image cannot be pulled)_"])
def test_ordinary_markdown_and_wardens_own_metrics_still_pass(text):
    assert gate.enforce(text).verdict != "BLOCK", text


# The ninth review's probe (review9r/A/probe_stub9.py): ids that overlap a withheld value or vary it.
STUB_CASES = [
    ("overlap, not contained", "password=" + PW, None, "b4dor-x9q-prod"),
    ("upper-cased copy", "password=" + PW, None, PW.upper()),
    ("key minus its first char", f"key {KEY}", None, KEY[1:] + "-7"),
    ("secret only in a data key", "report", {"labels": {f"--password {PW}": "1"}}, PW),
    ("NBSP inside", "password=" + PW, None, PW[:4] + chr(0xA0) + PW[4:]),
    ("fullwidth digits", "password=" + PW, None, PW.replace("0", chr(0xFF10)).replace("4", chr(0xFF14))),
    ("reversed halves", "password=" + PW, None, PW[7:] + PW[:7]),
]


@pytest.mark.parametrize("name, before, data, ident", STUB_CASES, ids=[c[0] for c in STUB_CASES])
def test_an_id_that_could_be_part_of_a_withheld_value_is_named_by_a_hash(name, before, data, ident):
    r = gate.enforce("report", before_redaction=before, data_before_redaction=data, alert_id=ident)
    assert r.verdict == "BLOCK", name
    ref = "ref-" + hashlib.sha256(ident.encode("utf-8")).hexdigest()[:12]
    assert f"for alert {ref} " in r.text, r.text
    for part in (ident, PW, KEY, PW[:5], PW[-5:], ident[:6]):
        assert part not in r.text, (name, part)


def test_an_id_clear_of_every_withheld_value_is_still_named():
    """Audit A-C-24: the notice names its alert, so a person can find the report."""
    r = gate.enforce("report", before_redaction="password=" + PW, alert_id="inc-7")
    assert r.verdict == "BLOCK" and "for alert inc-7 " in r.text, r.text
