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
SRC = ROOT / "src" / "warden"

# (label, file, find, replace, why this mutation matters)
MUTATIONS = [
    (
        "P11 action-contradicts-evidence removed",
        "verifier.py",
        "    contradiction = _contradiction(proposal, context)",
        "    contradiction = None",
        ("scale_up against OOM-killed pods that never became ready - the exact shape of the EKS runs the "
        "gate wrongly let through - would be approved for a human again with no warning"),
    ),
    (
        "P12 no-action-with-symptoms removed",
        "verifier.py",
        "        found = symptoms(context)",
        "        found = []",
        ("a confident 'nothing to do' over evidence showing OOM kills or unready pods would go out "
        "auto_safe - Wave 1's worst failure, caught since then only when confidence happened to be low"),
    ),
    (
        "P5 rollback guard removed",
        "verifier.py",
        "if proposal.action is ActionKind.rollback_deploy and not _deploy_of_target(alert, context, proposal.target):",
        "if False and proposal.action is ActionKind.rollback_deploy:",
        "the classic confident hallucination - rolling back a deploy that is not in the evidence",
    ),
    (
        "P2 irreversible-in-prod removed",
        "verifier.py",
        'if env.tier == "prod" and not proposal.table_reversible:',
        "if False:",
        "an irreversible action would become executable in production",
    ),
    (
        "the action table calls a database failover reversible",
        "models.py",
        'ActionKind.failover_replica: (False, "multi_service"),',
        'ActionKind.failover_replica: (True, "multi_service"),',
        (
            "P2 reads this table and nothing else, so one flipped tuple silently makes the only "
            "irreversible action P2 can reach in prod executable again - with every policy still "
            "present and every other test green"
        ),
    ),
    (
        "the ECS evidence stops counting failed tasks",
        "aws_backend.py",
        'sum(int(d.get("failedTasks") or 0) for d in deployments)',
        "sum(0 for d in deployments)",
        (
            "the signal a live account proved was missing: without it a service whose tasks crash "
            "and are replaced forever reports desired-count-reached, nothing pending and no failed "
            "deployment - evidence that reads as healthy while the service is broken"
        ),
    ),
    (
        "redaction one-text pass disabled",
        "redaction.py",
        "    found = [r.find(item) for item in items]\n    return [r.sweep(text) for text in found], r.mapping",
        "    return [r.sweep(r.find(item)) for item in items], r.mapping",
        "a secret found in a later line would stay in clear in the earlier ones",
    ),
    (
        "redaction sweep stops protecting existing placeholders",
        "redaction.py",
        "    for i in range(0, len(parts), 2):",
        "    for i in range(0, len(parts), 1):",
        (
            "sweeping the placeholder segments too collapses two distinct secrets onto one label "
            "(<UUID_1> -> <<TENANT_1>>) and breaks restore"
        ),
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
        "  name: warden-readonly\n  apiGroup: rbac.authorization.k8s.io",
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
    (
        "prod becomes auto-remediable",
        "data/environments.yaml",
        "  prod:\n    tier: prod\n    auto_remediate: false",
        "  prod:\n    tier: prod\n    auto_remediate: true",
        "the whole promise - production must NEVER auto-apply a fix without a human",
    ),
    (
        "remediation skips the authorization gate",
        "remediation.py",
        "    if not env.authorizes(request.principal):",
        "    if False and not env.authorizes(request.principal):",
        "an unauthorised principal could apply a fix - authorization is the who-may-act boundary",
    ),
    (
        "remediation skips the approval gate",
        "remediation.py",
        "    if request.approval != digest:",
        "    if False and request.approval != digest:",
        ("a fix would apply with nobody having approved THIS proposal - the last human checkpoint "
         "(this anchor went stale when approval became a digest on 2026-09-27, and the mutation "
         "silently stopped running until tests/test_mutation_anchors.py was added)"),
    ),
    (
        "report stops redacting its data",
        "reporting.py",
        "    data, mapping = _scrub(data, dict(redaction_map or {}))",
        "    mapping = dict(redaction_map or {})",
        ("the report's structured data - summary, evidence, the model's text - would leave unredacted in "
        "the JSON a webhook sends (the anchor moved when the report was rebuilt on 2026-09-24, and for a "
        "day this mutation could not be applied at all)"),
    ),
    (
        "chatops stops redacting the transmitted payload",
        "chatops.py",
        "    safe_text, mapping = final.text, final.mapping",
        "    safe_text, mapping = report.markdown, final.mapping",
        "the last redaction before data leaves the org - removing it is a direct external leak",
    ),
    (
        "live k8s backend lies that it is dry-run",
        "remediation_k8s.py",
        "    live = True",
        "    live = False",
        "the gate would record a real cluster change as a harmless dry_run - the honesty flag IS the audit",
    ),
    (
        "scale_down loses its floor of 1",
        "remediation_k8s.py",
        "            target = max(current - SCALE_STEP, 1)",
        "            target = current - SCALE_STEP",
        "scaling a Deployment to zero replicas is an OUTAGE dressed as a remediation",
    ),
    (
        "live backend stops refusing unsupported actions",
        "remediation_k8s.py",
        "        if action not in _SUPPORTED:",
        "        if False:",
        "the write backend would attempt rollback/failover/clear_cache it has no safe way to perform",
    ),
    (
        "the gate stops catching a backend fault",
        "remediation.py",
        "    except Exception as exc:  # noqa: BLE001 - a backend fault is a result, not a crash",
        "    except ValueError as exc:  # noqa: BLE001 - a backend fault is a result, not a crash",
        "a live-backend API error (403, unreachable) would crash the pipeline instead of a failed result",
    ),
    (
        "database terminator lies about being a dry run",
        "database_remediation.py",
        "        self.live = not self._dry_run",
        "        self.live = True",
        (
            "the honesty flag IS the audit: a dry run recorded as `applied` would tell an operator "
            "connections were terminated when nothing was touched "
            "(NB the class attribute is not the guard here - __init__ sets the instance flag)"
        ),
    ),
    (
        "database terminate loses its python-side ceiling",
        "database_remediation.py",
        "        candidates = candidates[:MAX_TERMINATE]",
        "        candidates = list(candidates)",
        "one broken WHERE clause away from terminating every connection on the server at once",
    ),
    (
        "database terminate stops sparing its OWN connection",
        "database_remediation.py",
        '                "AND pid <> pg_backend_pid() "',
        '                "AND 1 = 1 "',
        "it would terminate the very connection it is issuing the terminate from - the classic self-kill",
    ),
    (
        "dry run actually terminates",
        "database_remediation.py",
        "        if self._dry_run:",
        "        if False:",
        "the safe way to try this against a real database would silently become the dangerous way",
    ),
    (
        "the read-only database backend gains a write statement",
        "database.py",
        '"SELECT count(*) FROM pg_locks WHERE NOT granted"',
        '"DELETE FROM pg_locks WHERE NOT granted"',
        "read-only BY CONSTRUCTION: the evidence backend must never be able to change a database",
    ),
    (
        "terminate_connections dropped from the production allow-list",
        "data/environments.yaml",
        "    allow_actions: [restart_pods, scale_up, rollback_deploy, failover_replica, clear_cache, terminate_connections]",
        "    allow_actions: [restart_pods, scale_up, rollback_deploy, failover_replica, clear_cache]",
        "policy P1 would reject the action in prod, and the eval row for inc-005 must notice",
    ),
    (
        "the cluster CI job swallows the database suite again",
        "../../.github/workflows/ci-tool.yml",
        "          pytest tests/integration/test_live_cluster.py tests/integration/test_live_remediation.py -q -rs | tee it.txt",
        "          pytest tests/integration -q -rs | tee it.txt",
        (
            "the exact regression that broke CI: the cluster job collects the database suite, which "
            "skips for want of service containers and trips its own zero-skips guard"
        ),
    ),
]


def mutate(original: bytes, find: str, replace: str) -> bytes | None:
    """The file with its first `find` replaced, in the file's own line endings - or None.

    Anchors are written with "\\n". A Windows checkout has "\\r\\n", so every multi-line anchor was
    reported "missing" there (6 of them, 2026-09-28) while CI, on "\\n", found them."""
    text = original.decode("utf-8")
    crlf = "\r\n" in text
    text = text.replace("\r\n", "\n")
    if find not in text:
        return None
    text = text.replace(find, replace, 1)
    return (text.replace("\n", "\r\n") if crlf else text).encode("utf-8")


def run_suite() -> bool:
    """True if the suite passes."""
    # check=False on purpose: a NON-ZERO exit is the expected, desirable outcome for a mutated
    # build. Raising on it would abort the very thing this script measures.
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-x", "--no-header", "-p", "no:cacheprovider"],
        cwd=ROOT, capture_output=True, text=True, check=False,
        env={**os.environ, "WARDEN_MOCK": "1", "WARDEN_TRACE": "0"},
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
        original = path.read_bytes()  # bytes: the restore must be exact, line endings included
        mutated = mutate(original, find, replace)
        if mutated is None:
            print(f"[SKIP] {label}: anchor not found in {filename} (code moved - update this script)")
            survived.append(f"{label} (anchor missing)")
            continue
        try:
            path.write_bytes(mutated)
            caught = not run_suite()
            status = "CAUGHT" if caught else "*** SURVIVED ***"
            print(f"[{status}] {label}\n          why it matters: {why}")
            if not caught:
                survived.append(label)
        finally:
            path.write_bytes(original)  # always restore, byte for byte

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
