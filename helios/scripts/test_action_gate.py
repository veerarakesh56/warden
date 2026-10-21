"""The Action's gate (action/scripts/run-scenarios.sh) judges the real plan, never a fix file.

Runs the script against a stub `helios` that reports a failure for the plan and a clean verify for
the committed fix: the scenario must still fail the gate. Needs bash and jq (as the Action does);
without them the tests skip locally and FAIL in CI (`CI` set), so they cannot pass by not running.
    python -m unittest discover -s scripts
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "action" / "scripts" / "run-scenarios.sh"
BASH = shutil.which("bash")
JQ = shutil.which("jq")
MISSING = [name for name, path in (("bash", BASH), ("jq", JQ)) if path is None]

STUB = """#!/usr/bin/env bash
# inspect: the plan's chain, from $STUB_FAILURES. verify: the fix "resolves" everything.
case "$1" in
  inspect) printf '{"chain":{"scenario":"lose-a","failures":%s}}' "$STUB_FAILURES" ;;
  verify) echo "Verdict: RESOLVED"; exit 0 ;;
  *) exit 2 ;;
esac
"""

FAILURE = '[{"id":"aws_instance.web","kind":"Instance","reason":"zone down"}]'


@unittest.skipIf(MISSING and not os.environ.get("CI"), f"needs {', '.join(MISSING)}")
class GateJudgesThePlan(unittest.TestCase):
    def run_gate(self, failures: str, with_fix: bool) -> tuple[str, pathlib.Path]:
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        stub = tmp / "helios"
        stub.write_text(STUB, newline="\n")
        stub.chmod(0o755)
        (tmp / "scenarios").mkdir()
        (tmp / "scenarios" / "az.yaml").write_text("name: lose-a\n")
        (tmp / "fixes").mkdir()
        if with_fix:
            (tmp / "fixes" / "az.json").write_text('{"scenario_name":"lose-a"}')
        env = {
            **os.environ,
            "HELIOS_BIN": stub.as_posix(),
            "STUB_FAILURES": failures,
            "SCENARIOS_GLOB": (tmp / "scenarios").as_posix() + "/*.yaml",
            "FIXES_DIR": (tmp / "fixes").as_posix(),
            "TERRAFORM_JSON": "plan.json",
            "ARTIFACT_DIR": (tmp / "out").as_posix(),
            "GATE_FILE": (tmp / "gate.txt").as_posix(),
            "GITHUB_OUTPUT": (tmp / "gh-output").as_posix(),
        }
        r = subprocess.run(
            [BASH or "bash", SCRIPT.as_posix()],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return (tmp / "gate.txt").read_text().split(), tmp / "out"

    def test_a_fix_file_that_verifies_does_not_pass_a_failing_plan(self):
        gate, out = self.run_gate(FAILURE, with_fix=True)
        self.assertEqual(gate, ["az"])
        self.assertTrue((out / "az.verify.txt").is_file(), "the advisory report is still written")

    def test_a_failing_plan_without_a_fix_fails(self):
        gate, _ = self.run_gate(FAILURE, with_fix=False)
        self.assertEqual(gate, ["az"])

    def test_a_clean_plan_passes(self):
        gate, _ = self.run_gate("[]", with_fix=True)
        self.assertEqual(gate, [])


COMMENT = ROOT / "action" / "scripts" / "build-comment.sh"


@unittest.skipIf(MISSING and not os.environ.get("CI"), f"needs {', '.join(MISSING)}")
class CommentEscapesWhatThePrControls(unittest.TestCase):
    def test_names_ids_and_reasons_cannot_inject_markup(self):
        tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        art = tmp / "art"
        art.mkdir()
        evil = '<img src=x onerror=alert(1)>'
        doc = {
            "chain": {
                "scenario": f"s</code></summary>{evil}",
                "failures": [{"id": "aws_x.a|b`c", "kind": "K*", "reason": f"r\n# {evil} | x"}],
            },
            "skipped": [{"type": f"t{evil}", "count": 1, "addresses": ["t.a"]}],
        }
        (art / "az.json").write_text(json.dumps(doc))
        (art / "az.verify.txt").write_text(f"```\n{evil}\n")
        (art / "nat.inconclusive.txt").write_text(f"helios: INCONCLUSIVE {evil}\n")
        out = tmp / "c.md"
        env = {
            **os.environ, "ARTIFACT_DIR": art.as_posix(), "COMMENT_PATH": out.as_posix(),
            "ARTIFACT_NAME": "a", "RUN_ID": "1", "SERVER_URL": "https://github.com",
            "REPOSITORY": "o/r", "GITHUB_OUTPUT": (tmp / "gh-output").as_posix(),
        }
        r = subprocess.run([BASH or "bash", COMMENT.as_posix()], env=env, capture_output=True,
                           encoding="utf-8", errors="replace", check=False)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        body = out.read_text(encoding="utf-8")
        self.assertNotIn("<img", body)
        self.assertNotIn("</code></summary><", body)
        outside_pre = re.sub(r"<pre>.*?</pre>", "", body, flags=re.S)
        self.assertNotIn("```", outside_pre, "captured text must stay inside <pre>")
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", body)
        [row] = [line for line in body.splitlines() if line.startswith("| aws")]
        unescaped = len(re.findall(r"(?<!\\)\|", row))
        self.assertEqual(unescaped, 4, row)
        self.assertIn(r"aws\_x.a\|b\`c", row)


if __name__ == "__main__":
    unittest.main()
