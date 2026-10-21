"""Every third-party action in the workflows and the composite action is pinned to a commit SHA.

A tag (`@v4`) can be moved to other code by whoever controls the action's repository.
    python -m unittest discover -s scripts
"""

from __future__ import annotations

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
# Inside the WARDEN repository (since 2026-10-21) Helios's CI is the root workflow helios-ci.yml, which runs the
# composite actions in .github/actions; split out on its own, the workflow is back in .github/workflows.
FILES = (sorted((ROOT / ".github" / "workflows").glob("*.yml"))
         + sorted((ROOT / ".github" / "actions").glob("*/action.yml"))
         + sorted(ROOT.parent.glob(".github/workflows/helios-*.yml"))
         + [ROOT / "action" / "action.yml"])
USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)", re.M)


def unpinned(text: str) -> list[str]:
    return [
        ref for ref in USES.findall(text)
        if not ref.startswith(("./", "$/")) and not re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", ref)
    ]


class ActionsArePinned(unittest.TestCase):
    def test_every_uses_is_a_full_commit_sha(self):
        found = 0
        for f in FILES:
            text = f.read_text(encoding="utf-8")
            found += len(USES.findall(text))
            self.assertEqual(unpinned(text), [], f.name)
        self.assertGreater(found, 10, "the scan found the uses: lines")

    def test_a_tag_is_caught(self):
        self.assertEqual(unpinned("      - uses: actions/checkout@v4\n"), ["actions/checkout@v4"])


if __name__ == "__main__":
    unittest.main()
