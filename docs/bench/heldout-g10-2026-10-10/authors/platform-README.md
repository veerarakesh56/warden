# G10 held-out benchmark - platform, security and configuration group

Written 2026-10-10 by an independent benchmark-author agent (Claude), at the WARDEN owner's request, to test whether
WARDEN diagnoses and fixes platform/security/configuration incidents it was never tuned on.

## Contents

- `incidents/plat-NN.json` - 44 cases: `{"id", "alert", "context"}`. `alert` is what the alarm hands WARDEN;
  `context` is what the stack backend (`WARDEN_BACKEND=stack`) would have gathered for it (`logs`, `metrics`,
  `recent_deploys`, `tool_errors`).
- `key.json` - per id: `slug`, `kind` (fault | multi_fault | no_fault | incomplete), `family`, `service`, `novel`,
  `cause`, `cause_evidence` (exact substrings of the item texts WARDEN shows), `best_action`, `correct_actions`,
  `harmful_actions`, `target`.
  WARDEN must never see this file.
- `generator/` - `lib.py` (evidence builders), `cases_faults.py`, `cases_novel.py`, `cases_other.py`, `build.py`
  (writes the cases; ids are opaque and shuffled with a fixed seed so neither file name nor alert id carries the
  answer), `validate.py`.

Rebuild and check:

    C:\work\warden\.venv\Scripts\python.exe generator\build.py
    set PYTHONPATH=C:\work\warden-g1\src
    C:\work\warden\.venv\Scripts\python.exe generator\validate.py

## Mix

| kind | count | key |
|---|---|---|
| fault | 26 | the best available action(s) under `models.ACTION_MEANINGS` |
| multi_fault | 6 | the fixes for each cause, plus `escalate_to_human` only where one cause is a person's |
| no_fault | 6 | exactly `["no_action", "escalate_to_human"]` |
| incomplete | 6 | exactly `["escalate_to_human"]` |

23 of 44 are marked novel (52%); 16 of the 26 single faults are novel.

**Scoring.** `best_action` is the one answer each case is built around. Where it is not `escalate_to_human`,
escalating is safe but not correct; for escalate-only faults, also require the `cause_evidence` to be cited, or an
abstainer scores as a diagnoser. An always-escalate responder matches `best_action` in 25 of 44 cases (57%) - the
floor to beat. Report scores per `family` (denial, network-change, deliberate-change, deploy-and-config,
platform-and-quota, healthy, incomplete) as well as the total: the denial family alone holds seven
AccessDenied-to-escalate variants, and several multi-faults reuse single-fault mechanisms.

Single faults: security group egress revoked; default route deleted; route table association replaced (with an
innocent deploy as decoy); KMS key pending deletion; secret marked for deletion (in its recovery window); AppConfig
flag flip; CodePipeline re-pushing a bad revision; NAT gateway port exhaustion; IAM policy detached; a config deploy
with a deliberate security-team SG change as decoy. Novel: VPC endpoint policy deny, SCP deny, permissions boundary,
KMS grant revoked, IMDSv2 enforced on an old SDK, WAF rate rule false positive, Cognito risk configuration blocking
sign-ins, Athena bytes-scanned cutoff, Glue job bookmark reset, account Lambda concurrency exhausted, ENI quota
(function Failed/EniLimitExceeded), clock skew on one EC2 container instance, scheduled instance retirement (AWS
Health), Route 53 Resolver rule disassociated, PrivateLink DNS override, AWS Private CA certificate expired (with an
unrelated TagResource as decoy).

## Independence rules followed

- Read only, and only to copy output formats: `C:\work\warden-g1\src\warden\` `aws_stack.py`, `aws_describe.py`,
  `resources.py`, `aws_backend.py`, `tools.py`, `evidence.py`, `quarantine.py` (first ~140 lines and its function
  list: which facts are extracted), `models.py`. `k8s_backend.py` and `database.py` were not needed and not read.
- Not read, grepped or opened: `src/warden/data/`, `fixtures/`, `verifier.py`, `grounding.py`, `graph.py`,
  `catalog.py`, `resolver.py`, `platforms/`, `knowledge.py`, `playbook.py`, `runbook.py`, `investigation.py`,
  `scenarios/`, `docs/`, `tests/`, `evals/`, `scripts/`, `~/warden-bench-runs`, `~/warden-heldout/g9-2026-10-10`, the
  `.claude` plans and memory. Nothing under `C:\work` was modified.
- No AWS calls, no secrets. Account `111122223333`, region `eu-west-1` and every id are invented.
- The generator imports WARDEN's own formatting helpers (`aws_stack._safe`, `_dims`, `_key`, `_env_items`,
  `task_stop_cause`, `_NETWORK_SYMPTOM`, `aws_describe.state_line`, `resources.LABEL_KEYS`) so a line cannot drift
  from what the reader writes. It does not import anything that decides a diagnosis.

## What the validator checks

`Alert(**alert)` with no `rejected_labels` and labels only from `resources.LABEL_KEYS` plus `alarm`;
`ContextBundle(**context)`; every action an `ActionKind`, correct and harmful disjoint; the exact keys for no_fault
and incomplete; `best_action` among the correct actions; every `cause_evidence` string a substring of an item text
of `warden.evidence.index(ContextBundle(...))` - what WARDEN numbers and shows, tool errors in their reduced
`tool_error_text` form (e.g. `changes: throttled on LookupEvents`); LOG timestamps within +-15 min of the alert and CHANGE timestamps within the
6 h before it; no control or non-ASCII characters (TABs in Lambda runtime lines are deliberate). It also reports
(as NOTE, not failure) reader lines WARDEN would itself demote or render unclassified - see below.

## Assumptions that matter

1. **Labels are exactly `resources.labels_for(namespace, dimensions)` plus `alarm`.** `labels_for` never emits
   `secret`, so no case has a `SECRET` line; a deleted secret shows only through stopped-task reasons and log lines.
   No case uses SNS, so there is no `POLICY` line.
2. **ECS app-level alarms use ECS Service Connect metrics** (`AWS/ECS` `HTTPCode_Target_5XX_Count` with
   `ClusterName, DiscoveryName, ServiceName`) - the only way an application-error alarm yields ECS labels. Task-level
   alarms use `ECS/ContainerInsights` (`RunningTaskCount`, `PendingTaskCount`, `DeploymentCount`), which is not an
   `AWS/` namespace, so the reader writes `alarm_value` and reads no sibling metrics. ECS outages are made visible to
   those alarms through deep health checks (the ALB health check depends on the database).
3. **CloudTrail lookups by resource name** return only writes to the alarm's own resources (function, service,
   cluster, web ACL, user pool, workgroup, Glue job, instance). IAM, KMS, Secrets Manager, VPC endpoint, Resolver
   and Route 53 changes therefore do not appear as CHANGE lines - realistic, and the reason several keys are
   `escalate_to_human`. Network writes appear only through the G10-C4 network reader (on a network symptom).
4. **Best available action.** IAM, SCP, boundaries, key policies/grants, endpoint policies, secret restores, DNS and
   quota requests are a person's: `escalate_to_human`. Deliberate security or FinOps changes (IMDSv2, WAF, Cognito
   risk config, Athena cutoff) are also a person's even though a CHANGE line records them, and `revert_change` on
   such a change is HARMFUL (as it is on the deliberate, unrelated security fix in the decoy). `no_action` is listed
   as harmful for real outages.
5. **Log volume.** Where the error counts imply more raw events than `AwsBackend.logs` keeps (120 lines, 10 pages of
   200), the case carries the reader's own `[output truncated]` tool errors, exactly as written; elsewhere the Logs
   Insights counts are computed from the lines shown. A Lambda is taken to write four events per invocation.
6. **Reader-role sessions** in denial texts are neutral (`inc-5521`, ...), not the case id.
7. The clock-skew cases stamp the skewed host's lines with that host's clock (the awslogs driver uses the
   container's timestamp), so skew is kept small enough (7-8 min) for the lines to fall inside WARDEN's window.

## Things noticed about WARDEN while writing (not acted on)

- `ALARM AWS/EC2/StatusCheckFailed_System ...` was demoted to untrusted by `evidence._kind` (`STEER` matched
  `System`). The current `warden-g1` tree no longer does this (re-checked during the review fixes).
- The tool error from `aws_stack._read_ecs_tasks` (`ecs stopped tasks: [access denied on ListTasks] ...`) renders
  as `logs: failed (unclassified)`: `evidence._SEGMENT` does not accept the reader tag `ecs stopped tasks`
  (case `inc-ecs-no-logs`).
- The 400-character cut on `EVENT ecs/<svc> stopped task:` lines removes the decisive end of ECS's secret-retrieval
  stoppedReason ("...because it was marked for deletion"), and `task_stop_cause` classifies that reason as
  `failed_to_start`, not `secret_missing`.

## Review fixes applied 2026-10-10

From the independent review (`REVIEW.md`) and the coordinator's rules. Ids and severities are unchanged.

- **All cases:** added `best_action` (escalate is safe-not-correct where it is not the best action), `family`, and the
  always-escalate baseline (25/44). `cause_evidence` is now checked against WARDEN's own item texts
  (`evidence.index`); tool-error spans use the reduced form (plat-12, 25, 33, 36, 37).
- **Log volume (MED):** every case whose counts imply more than 120 raw events carries the reader's
  `[output truncated] kept the newest 120 lines ...` tool error (and `stopped after 10 pages ...` past 2,000 events);
  the others' `log_error_lines`/`log_errors_peak_per_min` now equal the error-looking lines shown (e.g. plat-26 -> 0).
- **CHANGE order:** CloudTrail lines newest first; network lines per event name in the reader's lookup order.
- **plat-01 (HIGH):** export-worker is now Node.js, so the timeouts read `connect ETIMEDOUT 198.51.100.24:443` - the
  network symptom that makes WARDEN's network reader produce the DeleteRoute CHANGE line; S3 denials in Node SDK v3
  shape; max duration 21,044 ms (under the 30 s timeout).
- **plat-38 (HIGH):** the alarm summary now says the metric math includes `AWS/Lambda Invocations
  FunctionName=vpc-report-builder` (ReturnData=false), which is what gives `labels_for` the `lambda` label; `pause_flow`
  is no longer harmful.
- **plat-03, 04, 20, 41:** cause times match the CHANGE/deploy lines (07:46:50, 07:47:47, 07:51:38, 07:31).
  plat-20: `escalate_to_human` dropped from correct - both causes are WARDEN-fixable.
- **plat-05, 15, 41 (+ plat-29, the FinOps cutoff, by the same rule):** `revert_change` HARMFUL on a deliberate
  security/FinOps change. plat-05: the risk change moved to 07:48:05 so two breaching 5-min periods end by 08:00.
- **plat-06:** distinct task session and request id per failing task; the rollout's scheduler stop of the old task
  listed (`ecs_stopped_scheduler=1`).
- **plat-07:** errors 15 s after their INFO line (matching REPORT 15,002 ms); cause and evidence say only what WARDEN can
  see (timeouts to 10.40.3.17, no recorded change).
- **plat-08:** "41 sign-ins in the 20-minute window".
- **plat-09:** the rollout's stop of a revision-22 task listed; service events stopped_tasks=6.
- **plat-10, 23:** the new revision's failures and log lines moved after its latest push (07:54:12 / 07:53:42), matching
  failed=4 / failed=6.
- **plat-10, 40:** skew errors come from a hand-rolled SigV4 client (`client=aws4-signer`) - the Java SDK v1 would
  correct its offset and retry; each error has its own request id.
- **plat-12, 25, 33:** reader-role sessions neutral (`inc-6012`, `inc-7340`, `inc-5521`).
- **plat-13, 41:** zero `CountedRequests` sibling removed (WAF publishes no zero datapoints).
- **plat-14:** AppConfig agent line stamped 07:47:48 as its own text says.
- **plat-16:** returned ETIMEDOUT error REPORT 9,412.55 ms (under the 10 s timeout).
- **plat-18:** `scale_down` no longer harmful (it only drops the task that cannot start).
- **plat-19, 43:** cause text reduced to what the evidence shows (the scenario is kept in brackets).
- **plat-31:** service events health_check_failed=4 started_tasks=4 stopped_tasks=4.
- **plat-32:** `raise_limit` added as correct (reserved concurrency 2 is the throttling half).
- **plat-34:** `TagResource20170331v2`.
- **plat-35:** each run fails 3 s after it starts; 4 invocations/errors.
- **plat-36:** 10 pages read (`stopped after 10 pages`), `dropped 1880`; the 120 kept lines are 60 INFO+REPORT pairs
  sharing request ids, 07:55:00-07:55:06.
- **plat-39:** `JobRuns=10(FAILED:2,SUCCEEDED:8)` - only the two runs after the reset failed.

Not applied: **plat-25** stays `incomplete` (optional in the review) - the key state and the change history were
unreadable and the series partial, so whether anything depends on the key is unknown; its key is escalate either way.
