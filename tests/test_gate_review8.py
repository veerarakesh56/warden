"""The outbound gate after the eighth independent review (2026-10-01), area A: the gate normalises first - control
characters and the code points a URL parser drops are removed before the leak check and before links are removed."""
from __future__ import annotations

import pytest

from warden import gate

KEY = "AKIA" + "IOSFODNN7EXAMPLE"
MARKS = [0x00AD, 0x200B, 0x034F, 0xFE0F, 0x180B, 0xE0100, 0x2060, 0x200E, 0x0007, 0x202E, 0x2066]


@pytest.mark.parametrize("cp", MARKS)
def test_a_link_hidden_by_an_invisible_is_removed_not_assembled(cp):
    """Removing invisibles AFTER the links let `htt<SHY>p://evil.com/x` hide from link removal - and the gate then
    joined it into a live link itself (a regression from d5763ff, widened by d40fc9a)."""
    for text in (f"see htt{chr(cp)}p://evil.com/x", f"see 192.168.1{chr(cp)}.1/admin", f"<https{chr(cp)}://evil.com>"):
        out = gate.enforce(text).text
        assert "://evil.com" not in out and "192.168.1.1/admin" not in out, (hex(cp), out)


@pytest.mark.parametrize("cp", MARKS)
def test_a_key_split_by_an_invisible_or_a_control_is_withheld_everywhere(cp):
    """G5 ran on the text before it was normalised, so `AKIA<ZWSP>...` passed and went out whole - from enforce,
    the terminal, structured data (MCP, webhooks)."""
    split = KEY[:4] + chr(cp) + KEY[4:]
    assert gate.enforce(f"found {split} in the log").verdict == "BLOCK"
    assert KEY not in gate.for_terminal(split) and "withheld" in gate.for_terminal(split)
    assert gate.outbound_data({"evidence": [split]})[0] == "BLOCK"


def test_the_cli_withholds_a_key_split_by_a_control(capsys):
    """71790df's argparse fix, undone by a BEL inside the key."""
    from warden import cli

    assert cli.main(["demo", KEY[:4] + chr(7) + KEY[4:]]) == 2
    assert KEY not in capsys.readouterr().err


@pytest.mark.parametrize("alert_id, data", [
    ("Tr0ub4dor-x9q", {"alert": {"labels": {"cmd": "deploy --password Tr0ub4dor-x9q"}}}),  # context in the data
    ("Tr0ub4dor", None),  # a prefix of the withheld secret
    ("Tr0u" + chr(0x200B) + "b4dor-x9q", None),  # an invisible inside the id
])
def test_the_stub_never_shows_a_withheld_value(alert_id, data):
    before = "" if data else "password=Tr0ub4dor-x9q"
    result = gate.enforce("report", before_redaction=before or None, data_before_redaction=data, alert_id=alert_id)
    assert result.verdict == "BLOCK" and "Tr0ub4dor" not in result.text and "b4dor" not in result.text, result.text


ESC = chr(27)
TOKENS = {"aws": "AKIA" + "IOSFODNN7EXAMPLE", "npm": "npm_" + "abcdefghijklmnopqrstuvwxyz0123456789",
          "anthropic": "sk-ant-" + "api03-" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0"}


@pytest.mark.parametrize("name", list(TOKENS))
def test_a_coloured_key_is_withheld_on_every_path(name):
    """Ninth review (2026-10-01, HIGH, pre-existing): a terminal colour code glued to a key (`ESC[1m<key>`) hid it
    from every pattern needing a word boundary - sent by the terminal, the gate, MCP data and the log."""
    import logging

    from warden.observability import GatedFormatter

    key = TOKENS[name]
    line = f"login ok {ESC}[1m{key}{ESC}[0m done"  # no key name: `token=` masked the value with or without the fix
    assert key not in gate.for_terminal(line)
    assert gate.enforce(line).verdict == "BLOCK" or key not in gate.enforce(line).text
    assert gate.outbound_data({"log": [line]})[0] == "BLOCK"
    record = logging.LogRecord("x", logging.INFO, __file__, 1, line, None, None)
    assert key not in GatedFormatter("%(message)s").format(record)


@pytest.mark.parametrize("cp", [0x0007, 0x200B, 0x00AD, 0xFE0F, 0x200E])
def test_a_key_glued_to_a_letter_by_a_removed_character_is_still_found(cp):
    """Ninth review (a regression from c52f6db): G5 ran on the normalised text only, so `x<BEL>AKIA...` became
    `xAKIA...` - no boundary - and the key went out whole (the CLI's argument error, MCP's unknown-tool error)."""
    from warden import mcp_server

    key = TOKENS["aws"]
    text = f"x{chr(cp)}{key}"
    assert gate.enforce(text).verdict == "BLOCK"
    assert key not in gate.for_terminal(text)
    assert key not in str(mcp_server._err(f"unknown tool: {text}").content)


@pytest.mark.parametrize("glue", ["<b></b>", "<i>", "<br/>", "<!here>", "<@U123>", "<!-- c -->"])
def test_a_key_assembled_by_removing_a_tag_is_withheld(glue):
    """Ninth review (MED, pre-existing): G3 removed a tag from inside a key after G5 had passed the text - the key
    G5 never saw went out whole. G5 now checks what G3 makes of the text too."""
    key = TOKENS["aws"]
    split = key[:6] + glue + key[6:]
    result = gate.enforce(f"see {split} here")
    assert result.verdict == "BLOCK" and key not in result.text, result
    assert gate.outbound_data({"x": split})[0] == "BLOCK"


def test_a_key_written_after_an_escape_written_out_is_withheld(capsys):
    """Ninth review: argparse prints `repr()` - `'\\x1b[2JAKIA...'` - and the literal escape glued `J` to the key."""
    from warden import cli

    key = TOKENS["aws"]
    cli.main([f"{ESC}[2J{key}"])
    assert key not in capsys.readouterr().err


@pytest.mark.parametrize("text", ["warning \u26a0\ufe0f disk", "keycap 1\ufe0f\u20e3", "CJK \u845b\U000e0100 x"])
def test_emoji_and_variation_selectors_pass_unchanged(text):
    """Ninth review (from c52f6db): removing every variation selector broke emoji and lost a CJK selector."""
    result = gate.enforce(text)
    assert result.verdict == "PASS" and result.text == text, result


@pytest.mark.parametrize("text", ["see p://evil.com/x", "see htt\tp://evil.com/x", "see ://evil.com/x"])
def test_a_one_letter_or_bare_scheme_is_still_a_link(text):
    """Ninth review: `x://evil.com` (one letter) passed unchanged, and so did a scheme broken by a tab."""
    out = gate.enforce(text.replace("\\t", "\t")).text
    assert "evil.com" not in out, out
