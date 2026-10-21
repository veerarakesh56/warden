"""Register N8 / audit A-N-8: the prompt, a policy or the catalogue changed through a pull request. Three layers:
the pinned hashes make every such change also change docs/safety-pins.sha256; CODEOWNERS routes those paths to a
named reviewer; and the running WARDEN binds the code hash into every plan and every model call's audit row."""

from __future__ import annotations

import importlib.util
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("safety_pins", ROOT / "scripts" / "safety_pins.py")
pins = importlib.util.module_from_spec(_spec)
sys.modules["safety_pins"] = pins
_spec.loader.exec_module(pins)

_POLICY_ID = re.compile(r'"P\d{1,2}[- ][A-Z]')


def test_the_pinned_hashes_match_the_files():
    committed = pins.PINS.read_text(encoding="utf-8")
    assert committed == pins.render(), ("a pinned file changed without docs/safety-pins.sha256: re-render it with "
                                        "`python scripts/safety_pins.py` so the change is visible to its reviewer")


def test_every_module_that_names_a_policy_or_holds_the_prompt_is_pinned():
    pinned = set(pins.files())
    for f in sorted((ROOT / "src" / "warden").glob("*.py")):
        text = f.read_text(encoding="utf-8")
        if _POLICY_ID.search(text) or re.search(r"^SYSTEM_", text, re.MULTILINE):
            assert f"src/warden/{f.name}" in pinned, f"{f.name} decides or describes policy and is not pinned"
    assert any(p.startswith("src/warden/data/") for p in pinned)


def test_codeowners_names_a_reviewer_for_every_pinned_path():
    rules = [line.split() for line in (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8").splitlines()
             if line.strip() and not line.startswith("#")]
    owned = {r[0].lstrip("/") for r in rules if len(r) > 1 and r[1].startswith("@")}
    for f in [*pins.files(), "docs/safety-pins.sha256", "scripts/safety_pins.py"]:
        assert f in owned or any(o.endswith("/") and f.startswith(o) for o in owned), f"no code owner for {f}"


def test_a_change_to_a_pinned_file_breaks_the_pins(tmp_path, monkeypatch):
    (tmp_path / "src" / "warden" / "data").mkdir(parents=True)
    for f in pins.files():
        (tmp_path / f).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / f).write_bytes((ROOT / f).read_bytes())
    monkeypatch.setattr(pins, "ROOT", tmp_path)
    before = pins.render()
    (tmp_path / "src" / "warden" / "verifier.py").write_bytes(b"# relaxed\n" + (ROOT / "src/warden/verifier.py").read_bytes())
    assert pins.render() != before
