"""The kill switch is turned ON where the audit is.

`warden killswitch on` on a workstation wrote that machine's own audit file and printed "kill switch: ON" while the cloud
runtime kept applying fixes - and the approval page could only reset the switch, so no person could stop WARDEN. Now
an approver opens a stop link their own key signed (`warden killswitch on --approver ... --key ...`), types why, and
any of their passkeys signs exactly that reason; the trip names them. Stopping is the safe direction, so it is T1's
rules; resetting stays T3's."""

from __future__ import annotations

import json
import pathlib

from test_killswitch_reset_g10m import World
from warden import bounds, cli
from warden.approval_page import RESET_INVITE, STOP_INVITE

ROOT = pathlib.Path(__file__).resolve().parents[1]
WHY = "orders is flapping after every fix; stop until we look"


def _stop(w, token, reason=WHY, sent=None):
    asked = w.page.handle("POST", f"/x/{token}/options", json.dumps({"reason": reason}))
    assert asked.status == 200, asked.body
    answer = w.device.assert_(json.dumps(json.loads(asked.body)["options"]))
    return w.page.handle("POST", f"/x/{token}/on", json.dumps({"reason": sent or reason, "response": answer}))


def _off(w):
    """The World starts with a trip; a reset row turns it off (its own path is tested in the reset tests)."""
    w.log.append("operator", bounds.RESET, {"approver": "owner", "method": "test", "trips": []})


def test_an_approvers_passkey_turns_the_switch_on_with_the_reason_it_signed(tmp_path):
    w = World(tmp_path, tiers=("T1",), synced=True)  # any approver, any passkey: stopping is the safe direction
    _off(w)
    assert bounds.killswitch(w.log) is None
    token = w.link(STOP_INVITE)
    assert w.page.handle("GET", f"/x/{token}").status == 200
    done = _stop(w, token)
    assert done.status == 200
    assert json.loads(done.body) == {"on": True}
    assert bounds.killswitch(w.log) is not None
    [row] = [r["body"]["reason"] for r in bounds.trips(w.log)]
    assert row == f"turned on by owner with their passkey: {WHY}"
    assert w.page.handle("GET", f"/x/{token}").status == 404  # used once


def test_the_reason_recorded_is_the_one_the_passkey_signed(tmp_path):
    w = World(tmp_path)
    _off(w)
    done = _stop(w, w.link(STOP_INVITE), sent="something else entirely")
    assert done.status == 403
    assert bounds.killswitch(w.log) is None


def test_a_stop_needs_a_reason_and_its_own_link(tmp_path):
    w = World(tmp_path)
    token = w.link(STOP_INVITE)
    assert w.page.handle("POST", f"/x/{token}/options", json.dumps({"reason": "  "})).status == 400
    assert w.page.handle("POST", f"/x/{token}/options", json.dumps({"reason": "x" * 301})).status == 400
    assert w.page.handle("GET", f"/x/{w.link(RESET_INVITE)}").status == 404  # a reset link stops nothing
    assert w.page.handle("GET", f"/k/{token}").status == 404  # and a stop link resets nothing


def test_the_cli_never_says_on_for_a_switch_it_did_not_reach(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("WARDEN_APPROVAL_RP_ID", "approve.example.test")
    monkeypatch.delenv("WARDEN_AUDIT_DSN", raising=False)
    monkeypatch.setenv("WARDEN_AUDIT_DB", str(tmp_path / "local.db"))
    opened = []
    monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url) or True)
    for argv in (["killswitch", "status"], ["killswitch", "reset", "--approver", "owner", "--key", "k", "--trips", "1"]):
        assert cli.main(argv) == 1
        assert "does not reach the cloud runtime's audit" in capsys.readouterr().err
    assert cli.main(["killswitch", "on", "--reason", "x"]) == 1
    assert "--approver and --key" in capsys.readouterr().err
    assert not (tmp_path / "local.db").exists()  # nothing written on this machine
    w = World(tmp_path)
    key = tmp_path / "k.pem"
    from cryptography.hazmat.primitives import serialization

    key.write_bytes(w.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption()))
    assert cli.main(["killswitch", "on", "--approver", "owner", "--key", str(key)]) == 0
    assert len(opened) == 1
    assert opened[0].startswith("https://approve.example.test/x/")
    assert not (tmp_path / "local.db").exists()
    assert "kill switch: ON" not in capsys.readouterr().out


def test_the_front_door_routes_the_stop():
    tf = (ROOT / "terraform" / "modules" / "warden-runtime" / "frontdoor.tf").read_text(encoding="utf-8")
    assert '"GET /x/{token}", "POST /x/{token}/{step}"' in tf
