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
