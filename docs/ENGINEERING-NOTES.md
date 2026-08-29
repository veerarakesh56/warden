# Engineering notes — what building this actually cost

A record of the defects this project found in **itself**, kept because each one changed how the code
works, and because they nearly all share one shape: *a check that passed because nothing ran, or
because it asked an easier question than the one that mattered.*

None of this is needed to use WARDEN — the [README](../README.md) covers that. This is for anyone who
wants to know what the guarantees on the front page actually cost, and why each is tested the way it is.

---

## Bugs the live cluster found that no fake could

**The OOM workload wasn't OOMing.** The first command was `head -c 300M /dev/zero | tail; echo
unreachable`. busybox's `head` rejects the `M` suffix — `invalid number '300M'` — so nothing was
allocated, the `echo` ran, and the container exited **0**. The Deployment restarted it on a loop:
restart count climbing, status `Completed`, zero OOM kills. **It looked exactly like the OOM test
was working.** Caught by reading the container log instead of the restart counter.

**A 40-line log tail arrived as one line.** With the client's default deserialisation,
`read_namespaced_pod_log` returned the *repr* of bytes as a string — `b'2026-…\n2026-…'` — with
literal backslash-n inside. `_log_text()` now reads the raw response and decodes it, and a test
feeds it every shape the client has been seen to return.

**Redaction left a copy of a UUID behind — and the guard refused the run.** A `CrashLoopBackOff`
event embeds the pod UID twice: bare as `(534e3098-…)` and inside a longer token
`…_default_534e3098-…-24ae0fb955bb_0`. The UUID regex ends in `\b`, and `b` followed by `_` is not a
word boundary, so one copy was masked and one was not. `_assert_clean` saw the survivor and raised
`RedactionLeak` rather than send it to a model. The redactor now runs a **final literal sweep**;
⭐ the failure was loud and safe, which is the guard working as designed.

## Then an adversarial review found nine more

Four independent reviewers each tried to refute one claim about the Kubernetes work; every finding
was attacked by a second reviewer, and the upheld ones were fixed, not noted:

- **RBAC was read-only but not minimal** — 12 of 16 granted verb/resource pairs had no caller. Cut
  to the exact five the code makes; CI now asserts `watch pods` and `get pods` are *denied*.
- **The RBAC unit test passed with `roleRef: cluster-admin`.** Now a structural check, not a grep.
- **The Job could hang forever** (no deadline; a stalled read left a thread joined at exit —
  reproduced live) and **deleted its own evidence** after an hour. Fixed with socket timeouts, a Job
  deadline, and a seven-day TTL.
- **`rollout restart` was reported as a deploy**, so P5 would allow a no-op "rollback".
  `deploys()` now compares ReplicaSet images.
- **Init-container OOMs, dead pods, and other workloads' events** were mis-handled — all fixed.
- **The write-verb tripwire was bypassable** by `getattr`/`call_api`/`subprocess`. Now an AST walk.

## What running it against a real model taught us

Every test here runs in mock mode. That is correct for CI — but it means the design was, until it
was actually run, an argument rather than a result. Running all four incidents against a live
**Gemini** model produced three findings the mocks could never have surfaced.

**1. ⚠ The model's self-reported confidence is not calibrated — and that breaks a policy.**
It returned **confidence 0.85 on all four incidents**, including `inc-004`, whose entire evidence is
two vague log lines. Policy `P4` escalates below 0.55, so with this model **P4 would essentially
never fire.** A gate that depends on a number the model has no ability to get right is not a gate.

⭐ **This is why `P9-THIN-EVIDENCE` exists.** It counts what was actually gathered — log lines,
distinct metrics, deploys — and escalates when two independent kinds of evidence are missing.
**Ours to measure, not the model's to claim.** It cannot be talked around by a confident tone.

**2. The live model chose a different action from the mock.** On `inc-003` (saturated replica) the
mock proposes `failover_replica`; the live model proposed `restart_pods` — more conservative, and
arguably wrong for the actual cause. ⛔ **So the eval suite encodes the mock's behaviour, not a
correctness standard.** It is a regression gate for routing and policy, and it was already
documented as such — this is the proof.

**3. Model identifiers expire.** `gemini-2.0-flash` was the hardcoded default; the API replied
*"no longer available … use models/gemini-3.6-flash"*. A pinned model id is a dated assumption,
which is why `WARDEN_MODEL` overrides it without touching code.

⭐ The live run also confirmed the parts that matter: **7 identifiers masked before anything left the
process**, cost tracked per call (~$0.009 per incident), and on the thin-evidence incident the model
proposed `no_action` rather than inventing a fix.

## Bugs worth keeping on the record

Each was found by **running** the thing, not by reading it, and each is now guarded. (The Kubernetes bugs
— the OOM workload that wasn't OOMing, and the log tail that arrived as one line — are in the
Kubernetes section above; both needed a real cluster to surface.)

**0. ⭐ The container produced wrong answers and CI was green.** Fixtures lived at the repo root and
were resolved with `Path(__file__).parents[2] / "fixtures"`. That works from a source checkout and
breaks silently once pip-installed — the path lands outside site-packages. Inside the container
every context tool failed, the evidence came back empty, and **all four incidents returned
`AUTO_SAFE`**: wrong verdicts, exit code 0.

⛔ **The CI docker job never noticed, because it ran `docker run … demo` and checked only the exit
code.** It asked *"did it run?"* when the question was *"was it right?"* Fixtures are now package
data, and **both CI jobs assert on the output** — the exact verdicts and that `P6` fires.

**1. Every incident produced the same hypothesis.** The mock reasoner branched on substrings of the
rendered prompt — which contains field labels like `RECENT DEPLOYS:` and metric keys like
`error_rate`. So the "bad deploy" branch always matched, **and the demo still looked like it
worked.** The instrument was asking whether a *word appeared* when the question was whether a
*deploy existed*. Guarded by `test_hypotheses_are_not_all_the_same`.

**2. The audit trail contradicted the verdict.** `auto_safe` and `approved_for_human` shared a
route, so an inert action carrying `requires_approval=False` still logged that it was waiting on an
operator. Guarded by `test_terminal_node_matches_the_verdict`.

**3. The tool timeout was cosmetic.** `ThreadPoolExecutor` used as a context manager calls
`shutdown(wait=True)` on exit — so the deadline fired at 0.3s and the caller then **blocked for the
full 6 seconds anyway**. The docstring said "each tool has a timeout" while the timeout did nothing.
Guarded by `test_a_hanging_tool_does_not_hang_the_run`, which asserts wall-clock, not just the
exception.

⭐ The pattern in all three: **the code claimed something the code did not do, and everything looked
green.** That is why every guard here is written to be *proven able to fail* before it is trusted.

## Three bugs real databases found that no stub would have

Stubs agree with whatever you assumed. Each of these came from pointing the code at a real server.

**1 · A stuck connection that is invisible forever.** Ten rounds of three deliberately-stuck
PostgreSQL connections: **two rounds missed one**, and the server explained why — it reported that
connection's age as **minus 115 seconds**. A host clock step (NTP correction, VM pause/resume) had
stamped `state_change` in the *future*, and such a connection can never satisfy
`state_change < now() - interval`. Invisible to both the read and the terminator, permanently and
silently. Declining to terminate what cannot be aged is right — it might be one second old. Doing it
**silently** is not: those are now reported with the `TOOL-PARTIAL` prefix, which lands them in
`tool_errors`, fires policy **P8** and sends the incident to a human.

**2 · The terminator was about to kill the monitoring, not the problem.** MongoDB's `currentOp` lists
the server's own awaitable `hello` heartbeats, which sit *active* for seconds by design. A plain
`secs_running >= threshold` filter selected them — so `terminate_connections` would have killed the
drivers' monitoring connections (**WARDEN's own included**) while never touching the stuck query
somebody called about. Selection is now an **allow-list** of real user operations: killing is
destructive, so under-selecting is the safe direction to be wrong in.

**3 · An idle server reporting an emergency.** A freshly started, completely idle SQL Server reported
**28 long-running queries** — `sys.dm_exec_requests` also lists the instance's own background tasks
(LAZY WRITER, CHECKPOINT, XE TIMER), which have been running since startup. That number would have
gone into the evidence as though the database were in trouble. Now joined to `dm_exec_sessions` on
`is_user_process = 1`; a quiet server reads as quiet, and a test asserts it.

**ChatOps.** `--emit-chatops` pushes the redacted report to Slack, Teams or a generic webhook
(`WARDEN_SLACK_WEBHOOK` / `WARDEN_TEAMS_WEBHOOK` / `WARDEN_WEBHOOK_URL`). It is **dry-run unless
`WARDEN_CHATOPS_LIVE=1`**, re-redacts the exact payload before transmit, and a failed post is a status,
never a crash.

## How the Kubernetes support was proven

CI creates a **k3d** cluster on every push and:

1. Validates every manifest with `kubectl apply --dry-run=server` — schema-checked by a real API.
2. Asks the API server **both ways**: `kubectl auth can-i list pods` → must be `yes`;
   `get pods` (only `list` is granted), `delete pods`, `patch deployments`, `get secrets`,
   `list pods -n kube-system`, `get nodes` → must each be **`no`**. A check that only confirmed the
   reads would pass a `*`-verb ClusterRoleBinding.
3. Deploys `k8s/test/oom-workload.yaml` — a pod that **actually OOM-kills itself** (300 MiB into a
   48Mi limit) — and waits for the kubelet to record `lastState.terminated.reason: OOMKilled`.
4. Runs WARDEN against it from outside and asserts the *output*: `"backend": "kubernetes"`,
   `scale_up`, `APPROVED_FOR_HUMAN`, `"tool_errors": []`.
5. Imports the image and runs WARDEN **inside** the cluster as the Job, under the read-only
   ServiceAccount, and asserts the same verdict from its logs — plus that it ran as `user=10001`
   with `readOnlyRootFilesystem`.
