"""Mutation check: does the test suite actually CATCH bugs, or does it only pass?

A green suite proves the tests ran. It does not prove they would notice if the code were wrong.
This deliberately breaks the code in specific, meaningful ways and asserts the suite goes RED for
each one. A mutation that survives is a hole in the tests, reported by name.

Run:  python scripts/mutation_check.py
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import shutil
import signal
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "warden"

# The files and the one replacement the Eldane and autonomy mutations below name, each once.
_AUTONOMY, _ELDANE, _ACTIVITIES = "autonomy.py", "eldane.py", "activities.py"
_NEVER = "    if False:"

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
        "        if not changed:\n            return []",
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
        "the k8s platform stops refusing entries it does not do",
        "platforms/k8s.py",
        "        if entry not in _ENTRIES:\n            raise KubernetesPlatformRefused(",
        "        if False:\n            raise KubernetesPlatformRefused(",
        "the write path would attempt a rollout undo or anything else it has no safe way to perform",
    ),
    (
        "a k8s scale loses its bound",
        "platforms/k8s.py",
        "                or not (current < replicas <= min(current + 2, self._max)) or replicas < 1:",
        "                or False:",
        "an approved '+1' could become any count, zero included - an outage dressed as a remediation",
    ),
    (
        "a k8s scale writes without checking the count it read",
        "platforms/k8s.py",
        '        patch = [{"op": "test", "path": "/spec/replicas", "value": expect},',
        "        patch = [",
        "a count something else changed since the approval would be overwritten",
    ),
    (
        "the k8s platform acts in another namespace",
        "platforms/k8s.py",
        '        if params.get("namespace") != self._ns:',
        "        if False:",
        "a plan could name kube-system; the platform serves one namespace",
    ),
    (
        "the database platform loses its python-side ceiling",
        "platforms/db.py",
        "            ids = self._sql.candidates(conn, idle, limit, self._users)[:limit]",
        "            ids = list(self._sql.candidates(conn, idle, limit, self._users))",
        "one broken LIMIT away from closing every session on the server at once",
    ),
    (
        "the database platform stops sparing its OWN session",
        "platforms/db.py",
        '"AND pid <> pg_backend_pid() ORDER BY state_change LIMIT %s",',
        '"AND 1 = 1 ORDER BY state_change LIMIT %s",',
        "it would close the very session it is issuing the close from - the classic self-kill",
    ),
    (
        "the database platform crosses databases",
        "platforms/db.py",
        """"WHERE state = 'idle in transaction' AND datname = current_database() \"""",
        """"WHERE state = 'idle in transaction' \"""",
        "audit A-B-H1: the old selection closed sessions of every database on the server",
    ),
    (
        "the database platform closes sessions with no application login named",
        "platforms/db.py",
        "        if entry not in _ENTRIES or not self._users or (entry == _BLOCKER and self._engine != \"postgres\"):",
        "        if entry not in _ENTRIES or (entry == _BLOCKER and self._engine != \"postgres\"):",
        "with no allowlist every login's sessions - an admin's included - would be candidates",
    ),
    (
        "the router asks platforms that do not know the service",
        "platforms/__init__.py",
        "if p.knows(service)]",
        "]",
        "a database platform would call every Kubernetes fix a failure and roll it back",
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
        ("    allow_actions: [restart_pods, scale_up, rollback_deploy, failover_replica, clear_cache, terminate_connections,\n"
         "                    revert_config,"),
        ("    allow_actions: [restart_pods, scale_up, rollback_deploy, failover_replica, clear_cache,\n"
         "                    revert_config,"),
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
    # Eldane, the AI critic, and dev autonomy (owner, 2026-10-16/17): every guard, planted (tests/test_eldane_autonomy.py).
    (
        "Eldane's approval no longer needs both of its passes",
        _AUTONOMY,
        '    if verdict is None or verdict.get("agree") is not True or not verdict.get("second_pass"):',
        '    if verdict is None or verdict.get("agree") is not True:',
        "a blind yes alone would approve: WARDEN's reasoning would never be weighed by the critic",
    ),
    (
        'an AI approval counts in prod',
        _AUTONOMY,
        '    if pol.tier == "prod" or ceiling(plan.environment) != L2:',
        _NEVER,
        "prod must always need a person's passkey (owner, 2026-10-16)",
    ),
    (
        'a prod environment may be configured autonomous',
        'environments.py',
        '    if value == "L2" and (raw.get("tier") == "prod" or name == "default"):',
        _NEVER,
        'a one-line edit of environments.yaml would make prod autonomous',
    ),
    (
        'a failed fix no longer demotes',
        _AUTONOMY,
        '        if b.get("failed"):\n            out.append((e["seq"], f"`{b.get(\'entry\')}` ended',
        '        if False:\n            out.append((e["seq"], f"`{b.get(\'entry\')}` ended',
        "demote at once: a rolled-back or relapsed fix must end its class's autonomy until a person re-enables it",
    ),
    (
        "a person's veto of an Eldane-approved plan no longer demotes",
        _AUTONOMY,
        '        elif b.get("harmful"):',
        '        elif False:',
        'Eldane said yes to what a person said no to: dev must wait for a person',
    ),
    (
        'a model or prompt change no longer demotes',
        _AUTONOMY,
        '    if changed is not None:\n        out.append((changed,',
        '    if False:\n        out.append((changed,',
        'register R3: a new model or prompt is not the one that was running',
    ),
    (
        "a missed catch trial no longer stops Eldane's approvals",
        _AUTONOMY,
        '            for e in log.entries(kinds=(TRIAL,)) if e["seq"] > after and e["body"].get("caught") is False]',
        '            for e in log.entries(kinds=(TRIAL,)) if e["seq"] > after and e["body"].get("caught") is None]',
        'register R11: a critic that waves a planted bad plan through must lose its approvals',
    ),
    (
        'Eldane may re-enable its own autonomy',
        _AUTONOMY,
        '    if policy.is_ai(approval.approver):\n        return [',
        '    if False:\n        return [',
        'after a demotion only a person turns autonomy back on (owner, 2026-10-17)',
    ),
    (
        'a re-enable is not bound to the demotions it was shown',
        _AUTONOMY,
        'plan_hash=enable_hash(log, environment), tier="T3"',
        'plan_hash=approval.plan_hash, tier="T3"',
        'a person could re-enable past a demotion added after they read the list',
    ),
    (
        "an Eldane-approved plan is applied without a person's chance to say no",
        'workflows.py',
        '                await workflow.wait_condition(lambda: self._vetoed(wid, plan) is not None, timeout=VETO)',
        '                pass',
        "a person's decision always overrides Eldane's (owner, 2026-10-17)",
    ),
    (
        'the kill switch no longer stops autonomous approvals',
        _AUTONOMY,
        '    if (row := bounds.killswitch(log)) is not None:\n        problems.append(',
        '    if (row := None) is not None:\n        problems.append(',
        'the Red Button must stop Eldane too',
    ),
    (
        'an AI may approve a plan on WARDEN itself',
        _AUTONOMY,
        '    problems += self_guard(plan)\n',
        '',
        "register R6 / P22: WARDEN's runtime and guardrails are a person's to change",
    ),
    (
        "the self-guard no longer sees WARDEN's guardrails",
        _AUTONOMY,
        '    hits = sorted({hit for v in values if (hit := touches_protected(v))})',
        '    hits = []',
        'a plan naming CI workflows, IAM, the approvers or environments.yaml would pass for an AI',
    ),
    (
        'Eldane may read any audit row, the discussion included',
        _ELDANE,
        '    if kind not in READS:  # register R12: nothing else reaches Eldane',
        _NEVER,
        'register R12: anyone can write in the discussion channel; it must never reach the approver',
    ),
    (
        "Eldane's first pass sees WARDEN's reasoning",
        _ELDANE,
        '    first = ask(log, plan.incident_id, asked, blind, ids, **row, purpose="blind")',
        '    first = ask(log, plan.incident_id, asked, blind + "\\n\\n" + _reasoning(diagnosis), ids, **row, purpose="blind")',
        "register R10: an anchored critic re-reads WARDEN's conclusion instead of the evidence",
    ),
    (
        'Eldane may review with the very model that diagnosed',
        _ELDANE,
        '    if model == prov.get("model"):',
        _NEVER,
        'owner, 2026-10-17: the same family, never the same model - else the diagnosis agrees with itself',
    ),
    (
        'Eldane no longer picks the model the diagnosis did not use',
        _ELDANE,
        '    model = next((m for m in models if m != diagnosed_by), "")',
        '    model = models[0]',
        'a Sonnet diagnosis reviewed by Sonnet, an Opus one by Opus: no second model at all',
    ),
    (
        'an answer citing evidence that does not exist is accepted',
        _ELDANE,
        '    if cited - ids:',
        _NEVER,
        'a verdict must rest on the record, never on invented evidence',
    ),
    (
        'check_approval no longer applies the AI rules',
        _ACTIVITIES,
        '        if ai and not problems:',
        '        if False:',
        "an Eldane-signed approval would count like a person's, with no earned level or recorded agreement",
    ),
    # PR 42 review fixes, planted (tests/test_eldane_autonomy.py).
    (
        'Eldane reviews a plan whose diagnosis does not say which model made it',
        _ELDANE,
        '    if not diagnosis or not prov:',
        _NEVER,
        'PR 42 review, CWE-636: an unknown diagnoser family must be refused, never reviewed as independent',
    ),
    (
        'a catch trial with no valid answer is scored a catch',
        _ELDANE,
        '    elif yes is False and verdict._grounded:',
        '    elif yes is False:',
        "PR 42 review: a provider outage or an unreadable reply would raise Eldane's catch rate",
    ),
    (
        'unscored catch trials count as answered',
        _AUTONOMY,
        '            and e["body"].get("caught") in (True, False)]',
        '            ]',
        'PR 42 review: non-answers would count towards the trials and the rate',
    ),
    (
        "an approval recorded as an AI's passes as a person's at apply",
        _ACTIVITIES,
        'if any(e["body"].get("ai") is True or self.policy.is_ai(str(e["body"].get("approver"))) for e in approved)',
        'if any(self.policy.is_ai(str(e["body"].get("approver"))) for e in approved)',
        'PR 42 review, CWE-863: a changed approver list would let an AI approval skip the AI rules at apply',
    ),
    (
        "an AI's recorded approval scores as a person's decision",
        _AUTONOMY,
        '    people = [a for a in approvers if a not in ai and not policy.is_ai(a)]',
        '    people = [a for a in approvers if not policy.is_ai(a)]',
        "Eldane's own approvals would count as a person agreeing with it",
    ),
    (
        'a retried end no longer scores its run',
        _ACTIVITIES,
        '            self._score(incident_id, workflow_id, run, outcome)\n            self.audit.checkpoint()\n            return',
        '            self.audit.checkpoint()\n            return',
        'PR 42 review: a failed fix whose scoring failed once would never demote its class',
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


def related_tests(filename: str) -> list[str]:
    """The test and eval files whose text names the mutated file - the ones expected to catch it. Their
    failing proves the mutation is caught; their passing proves nothing, so a survivor is re-run against
    the whole suite before it is reported."""
    stem = pathlib.Path(filename).stem
    found = [str(f.relative_to(ROOT)) for d in ("tests", "evals") for f in sorted((ROOT / d).rglob("*.py"))
             if f.name.startswith(("test_", "eval")) and stem in f.read_text(encoding="utf-8", errors="replace")]
    return found or ["tests", "evals"]


TIMED_OUT = "timed out"


def run_suite(paths: list[str] | None = None, limit: int = 1800) -> bool | str:
    """True if the suite (or the given test paths) passes, False if it fails, TIMED_OUT if it runs past
    `limit` seconds - then the run and every worker it started are stopped."""
    # Non-zero is the expected, desirable outcome for a mutated build; it is not an error here.
    # On parallel workers, as CI runs it: serially one run took 17 minutes (2026-10-01). -x still stops
    # at the first failure, but waits for tests already running - hence the limit.
    proc = subprocess.Popen(
        [sys.executable, "-m", "pytest", "-q", "-x", "-n", "auto", "--no-header", "-p", "no:cacheprovider",
         *(paths or [])],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={**os.environ, "WARDEN_MOCK": "1", "WARDEN_TRACE": "0"},
        # Its own process group on POSIX, so a time limit stops the xdist workers too.
        start_new_session=os.name != "nt",
    )
    try:
        return proc.wait(timeout=limit) == 0
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        return TIMED_OUT
    except BaseException:
        # Ctrl-C: the run is in its own session on POSIX, so the terminal's signal never reaches its workers
        # (sixth review, 2026-10-01) - stop them before the mutated file is restored.
        _kill_tree(proc)
        raise


def _kill_tree(proc: subprocess.Popen) -> None:
    """Stop the run and its workers: killing only pytest leaves xdist workers running on Windows."""
    taskkill = shutil.which("taskkill") if os.name == "nt" else None
    if os.name == "nt" and not taskkill:
        proc.kill()  # no taskkill found: pytest itself at least
    elif taskkill:
        subprocess.run([taskkill, "/T", "/F", "/PID", str(proc.pid)],  # nosec B603  # a fixed argv, no shell
                       capture_output=True, check=False)
    else:
        import signal

        os.killpg(proc.pid, signal.SIGKILL)
    proc.wait()


# The file a run is mutating, with its original bytes: written before the change, removed after the restore. A run
# killed outright (TerminateProcess, SIGKILL) never reaches its `finally`; the next run restores from this first
# (register R7-O4). Workers of such a run are not stopped: their ids could by then belong to other processes.
JOURNAL = ROOT / ".mutation-restore.json"


def recover() -> str | None:
    """Put back the file a killed run left mutated. Returns its name, or None if nothing was left."""
    if not JOURNAL.exists():
        return None
    entry = json.loads(JOURNAL.read_text(encoding="utf-8"))
    (ROOT / entry["path"]).write_bytes(base64.b64decode(entry["original"]))
    JOURNAL.unlink()
    return entry["path"]


def _terminate_like_ctrl_c(*_):
    raise KeyboardInterrupt("SIGTERM")


def main() -> int:
    if os.name != "nt":
        # SIGTERM (a CI cancel, `kill`) ends the run like Ctrl-C: the workers stopped, the file restored.
        signal.signal(signal.SIGTERM, _terminate_like_ctrl_c)
    if left := recover():
        print(f"restored {left}, left mutated by a run that was killed")
    print("Baseline: running the suite unmodified...")
    if run_suite() is not True:
        print("BASELINE IS RED (or ran past its limit). Fix the suite before mutation testing means anything.")
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
        JOURNAL.write_text(json.dumps({"path": path.relative_to(ROOT).as_posix(),
                                       "original": base64.b64encode(original).decode()}), encoding="utf-8")
        try:
            path.write_bytes(mutated)
            # The files that name it first (seconds to minutes); the whole suite only if they all pass.
            result = run_suite(related_tests(filename), limit=600)
            if result is True:
                result = run_suite()
            caught = result is not True
            status = ("CAUGHT (the suite ran past its limit)" if result == TIMED_OUT else "CAUGHT") if caught \
                else "*** SURVIVED ***"
            print(f"[{status}] {label}\n          why it matters: {why}")
            if not caught:
                survived.append(label)
        finally:
            path.write_bytes(original)  # always restore, byte for byte
            JOURNAL.unlink(missing_ok=True)

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
