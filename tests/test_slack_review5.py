"""The gate and the Slack conversion after the fifth independent review (2026-10-01), area A: fences after a
list or quote marker, `~~~` blocks, full-width dots, and the alert id in the stub of a withheld report."""
from __future__ import annotations

import pytest

from warden import chatops, gate
from warden.redaction import redact

SECRET = "AKIA" + "IOSFODNN7EXAMPLE"


# Markers long enough that a check of the line's first 12 characters misses the fence (seventh review: it passed
# every marker here up to 9 characters).
@pytest.mark.parametrize("marker", ["- ", "> ", "1. ", "1) ", "- - - ", "  > - 1. ", "- - - - 1. ", "> > > - - 10. "])
def test_a_fence_after_a_list_or_quote_marker_stays_code(marker):
    """The A-2 tests used a two-space indent only; `line.lstrip().startswith("```")` passed them, and a URL
    after a `- ```` marker became Slack prose once split."""
    body = "\n".join(f"  https://evil.example/{i}" for i in range(400))
    md = f"{marker}```\n{body}\n  ```\n**after**"
    assert chatops.to_slack_mrkdwn(md).endswith("\n  ```\n*after*")
    parts = chatops.split_for_slack(md, limit=2000)
    assert len(parts) > 1
    for part in parts:
        assert sum("```" in line for line in part.split("\n")) % 2 == 0, part[:80]


def test_a_heading_in_a_tilde_block_is_not_made_bold():
    """CommonMark shows a `~~~` block as code; the converter only tracked backticks and bolded its heading."""
    text = gate.enforce("~~~\n# Fix - approved\n~~~\n# Real").text
    assert chatops.to_slack_mrkdwn(text) == "~~~\n# Fix - approved\n~~~\n*Real*"


def test_backticks_inside_a_tilde_block_do_not_end_it():
    assert chatops.to_slack_mrkdwn("~~~\n```\n# in\n~~~\n# out") == "~~~\n```\n# in\n~~~\n*out*"


@pytest.mark.parametrize("dot", [chr(0x3002), chr(0xFF0E), chr(0xFF61)])
def test_a_full_width_dot_does_not_keep_a_domain_whole(dot):
    """A browser opens `evil<U+3002>com` as evil.com; only ASCII dots were defanged."""
    out = gate.enforce(f"see evil{dot}com/x?d=1 and www{dot}evil{dot}com").text
    assert "evil[.]com" in out and "www[.]evil[.]com" in out and dot not in out


def test_the_stub_of_a_withheld_report_cleans_the_alert_id():
    """`click.evil.example` is a valid alert id; the stub put it in raw while a passing report defanged it."""
    result = gate.enforce(f"key {SECRET}", alert_id="click.evil.example")
    assert result.verdict == "BLOCK"
    assert "click[.]evil[.]example" in result.text and "click.evil.example" not in result.text


def test_the_stub_of_a_withheld_report_redacts_a_key_shaped_alert_id():
    """Sixth review (2026-10-01): the stub cleaned the id's links but never checked it for secrets."""
    result = gate.enforce(f"key {SECRET}", alert_id=SECRET)
    assert result.verdict == "BLOCK" and SECRET not in result.text, result.text


@pytest.mark.parametrize("mark", [chr(0x200B), chr(0x2060), chr(0xFEFF), chr(0x00AD), chr(0x034F), chr(0x180B),
                                  chr(0xFE0F), chr(0x2064), chr(0x1BCA0), chr(0xE0100)])
def test_an_invisible_character_at_a_dot_does_not_keep_a_domain_whole(mark):
    """Sixth review (2026-10-01): `evil.<ZWSP>com` passed whole."""
    out = gate.enforce(f"see evil.{mark}com/x and www{mark}.evil.com and evil.c{mark}om/y").text
    assert "evil[.]com/x" in out and "www[.]evil[.]com" in out and "evil[.]com/y" in out, out


def test_zwnj_and_zwj_are_left_in_prose():
    """Seventh review: a WHATWG URL parser keeps U+200C and U+200D, so removing them bought nothing and rewrote
    Persian text (`mi<ZWNJ>khaham`) - the gate answered REWRITE with its spelling changed."""
    text = "user wrote: " + "".join(map(chr, (0x645, 0x6CC, 0x200C, 0x62E, 0x648, 0x627, 0x647, 0x645)))
    result = gate.enforce(text)
    assert result.verdict == "PASS" and result.text == text, result


@pytest.mark.parametrize("before", ["password=Tr0ub4dor-x9q", "curl --token Tr0ub4dor-x9q", "Authorization: Tr0ub4dor-x9q"])
def test_the_stub_masks_an_alert_id_that_is_a_secret_in_the_blocked_text(before):
    """Seventh review (2026-10-01): the id was redacted on its own - `Tr0ub4dor-x9q` alone is no secret - so the
    gate blocked a value and then sent it in the stub."""
    result = gate.enforce(redact(before).text, before_redaction=before, alert_id="Tr0ub4dor-x9q")
    assert result.verdict == "BLOCK" and "Tr0ub4dor" not in result.text, result.text


# Every code point a WHATWG URL parser drops from a host (Node 22, all 1.1M code points; seventh review). The test
# named 10 of the 270, and a class narrowed to those 10 passed (eighth review).
_WHATWG = [0x00AD, 0x034F, *range(0x180B, 0x180E), 0x180F, 0x200B, 0x2060, 0x2064, *range(0xFE00, 0xFE10), 0xFEFF,
           *range(0x1BCA0, 0x1BCA4), *range(0xE0100, 0xE01F0)]


def test_every_code_point_a_url_parser_drops_is_looked_past():
    assert len(_WHATWG) == 270
    missed = [hex(cp) for cp in _WHATWG if "evil[.]com" not in gate.enforce(f"see evil.{chr(cp)}com/x").text]
    assert not missed, missed
