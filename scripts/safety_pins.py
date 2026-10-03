"""The files that decide what WARDEN may do, pinned by hash (register N8): the model's instructions (graph.py), the
policies (verifier, gate, grounding, quarantine, tripwire, bounds, freeze), the approval and remediation rules
(approvals, catalog, activities, workflows) and every data file. A pull request that changes one must also change
docs/safety-pins.sha256, which CODEOWNERS routes to a named reviewer - a quiet edit to a policy cannot hide in a
large diff. Regenerate after a reviewed change: `python scripts/safety_pins.py`."""

from __future__ import annotations

import hashlib
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
PINS = ROOT / "docs" / "safety-pins.sha256"
PACKAGE = "src/warden"
PINNED = ("activities.py", "approval_page.py", "approvals.py", "bounds.py", "catalog.py", "decide.py", "evidence.py", "freeze.py", "gate.py",
          "graph.py", "grounding.py", "mcp_server.py", "passkeys.py", "quarantine.py", "redaction.py", "reporting.py", "tripwire.py",
          "verifier.py", "workflows.py")


def files() -> list[str]:
    data = sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / PACKAGE / "data").rglob("*") if p.is_file())
    return [f"{PACKAGE}/{name}" for name in PINNED] + data


def render() -> str:
    # sha256sum's format, over the bytes with line endings normalised (a checkout's autocrlf must not matter).
    return "".join(f"{hashlib.sha256((ROOT / f).read_bytes().replace(b'\r\n', b'\n')).hexdigest()}  {f}\n"
                   for f in files())


def main() -> None:
    PINS.write_text(render(), encoding="utf-8", newline="\n")
    print(f"wrote {PINS.relative_to(ROOT)}: {len(files())} files")


if __name__ == "__main__":
    main()
