"""Mutation check: does the test suite actually CATCH bugs, or does it only pass?

A green suite proves the tests ran. It does not prove they would notice if the code were wrong.
This deliberately breaks the code in specific, meaningful ways and asserts the suite goes RED for
each one. A mutation that survives is a hole in the tests, reported by name.

Run:  python scripts/mutation_check.py
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "aegis"

# (label, file, find, replace, why this mutation matters)
MUTATIONS = [
    (
        "P5 rollback guard removed",
        "verifier.py",
        "if proposal.action is ActionKind.rollback_deploy and not context.recent_deploys:",
        "if False and proposal.action is ActionKind.rollback_deploy:",
        "the classic confident hallucination - rolling back a deploy that is not in the evidence",
    ),
    (
        "P2 irreversible-in-prod removed",
        "verifier.py",
        'if alert.environment == "prod" and not proposal.reversible:',
        "if False:",
        "an irreversible action would become executable in production",
    ),
    (
        "redaction leak check disabled",
        "redaction.py",
        "        if original and original in free_text:",
        "        if False:",
        "a secret surviving redaction would be silently sent to the model",
    ),
    (
        "redaction sweep stops protecting existing placeholders",
        "redaction.py",
        "    for i in range(0, len(parts), 2):",
        "    for i in range(0, len(parts), 1):",
        "sweeping the placeholder segments too collapses two distinct secrets onto one label "
        "(<UUID_1> -> <<TENANT_1>>) and breaks restore",
    ),
    (
        "fixtures path reverted to the packaging bug",
        "tools.py",
        'FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"',
        'FIXTURES = pathlib.Path(__file__).resolve().parents[2] / "fixtures"',
        "the exact bug that made the container return wrong verdicts while CI stayed green",
    ),
    (
        "gen_ai attribute name typo",
        "observability.py",
        'GEN_AI_INPUT_TOKENS = "gen_ai.usage.input_tokens"',
        'GEN_AI_INPUT_TOKENS = "gen_ai.usage.input_token"',
        "traces would export an attribute no backend queries, and nothing would look broken",
    ),
    (
        "budget ceiling never fires",
        "llm.py",
        "if self.cost.usd > self.max_usd:",
        "if False:",
        "a runaway retry loop could spend without limit",
    ),
    (
        "k8s backend gains a write call",
        "k8s_backend.py",
        "        items = self._core.list_namespaced_pod(",
        "        self._core.delete_namespaced_pod('x', 'y', _request_timeout=1)\n        items = self._core.list_namespaced_pod(",
        "the read-only-by-construction invariant - a backend that can delete is no longer evidence-only",
    ),
    (
        "k8s backend stops detecting OOMKilled",
        "k8s_backend.py",
        'if (last is not None and last.reason == "OOMKilled") or (',
        'if (last is not None and last.reason == "NEVER") or (',
        "a real OOM-killed pod would report zero OOM kills and the OOM branch would never fire",
    ),
    (
        "RBAC gains a delete verb",
        "../../k8s/rbac.yaml",
        '    resources: ["pods"]\n    verbs: ["list"]',
        '    resources: ["pods"]\n    verbs: ["list", "delete"]',
        "the ServiceAccount could delete pods - RBAC would no longer be the boundary",
    ),
    (
        "RBAC binding points at cluster-admin",
        "../../k8s/rbac.yaml",
        "  name: aegis-readonly\n  apiGroup: rbac.authorization.k8s.io",
        "  name: cluster-admin\n  apiGroup: rbac.authorization.k8s.io",
        "review finding: the old grep-based test passed this - zero write verbs in the file, full admin granted",
    ),
    (
        "RBAC gains an unused watch verb",
        "../../k8s/rbac.yaml",
        '    resources: ["pods"]\n    verbs: ["list"]',
        '    resources: ["pods"]\n    verbs: ["list", "watch"]',
        "'minimal' means exactly what the code calls; a granted-but-unused verb must fail",
    ),
    (
        "k8s backend reports a rollout restart as a deploy",
        "k8s_backend.py",
        "        if previous is not None and _images(previous) == current_images:\n            return []",
        "        if False:\n            return []",
        "policy P5 would accept a rollback that re-applies the identical template",
    ),
    (
        "k8s backend treats zero pods as healthy",
        "k8s_backend.py",
        "        if not live:\n            # Zero matches",
        "        if False:\n            # Zero matches",
        "a mistyped namespace would read as an inspected, healthy cluster",
    ),
    (
        "Job loses its deadline",
        "../../k8s/job.yaml",
        "  activeDeadlineSeconds: 300",
        "  # activeDeadlineSeconds removed",
        "a stalled run keeps the Job active forever with a token mounted - reproduced live",
    ),
]


def run_suite() -> bool:
    """True if the suite passes."""
    # check=False on purpose: a NON-ZERO exit is the expected, desirable outcome for a mutated
    # build. Raising on it would abort the very thing this script measures.
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-x", "--no-header", "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True, check=False,
        env={**os.environ, "AEGIS_MOCK": "1", "AEGIS_TRACE": "0"},
    )
    return r.returncode == 0


def main() -> int:
    print("Baseline: running the suite unmodified...")
    if not run_suite():
        print("BASELINE IS RED. Fix the suite before mutation testing means anything.")
        return 2
    print("Baseline GREEN.\n")

    survived: list[str] = []
    for label, filename, find, replace, why in MUTATIONS:
        path = SRC / filename
        original = path.read_text(encoding="utf-8")
        if find not in original:
            print(f"[SKIP] {label}: anchor not found in {filename} (code moved - update this script)")
            survived.append(f"{label} (anchor missing)")
            continue
        try:
            path.write_text(original.replace(find, replace, 1), encoding="utf-8")
            caught = not run_suite()
            status = "CAUGHT" if caught else "*** SURVIVED ***"
            print(f"[{status}] {label}\n          why it matters: {why}")
            if not caught:
                survived.append(label)
        finally:
            path.write_text(original, encoding="utf-8")  # always restore

    print("\n" + "=" * 70)
    if survived:
        print(f"{len(survived)} MUTATION(S) SURVIVED - these are holes in the test suite:")
        for s in survived:
            print(f"  - {s}")
        return 1
    print(f"All {len(MUTATIONS)} mutations were caught. The suite can detect these failures.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
