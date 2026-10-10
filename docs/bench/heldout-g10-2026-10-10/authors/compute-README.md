# G10 held-out benchmark: COMPUTE group

**Who and when.** A Claude agent acting as an independent benchmark author wrote these cases on 2026-10-10, between
about 10:00 and 11:00 UTC (15:30 to 16:30 IST). Every alert starts at `2026-10-10T08:00:00+00:00`, which is 08:00 UTC
or 13:30 IST.

**Scope.** The cases cover Amazon ECS (Fargate and EC2), Amazon EKS / Kubernetes, AWS Lambda, Amazon EC2 with Auto
Scaling groups, and AWS App Runner.

## Contents

| Path | What it is |
|---|---|
| `incidents/<id>.json` | 45 cases. Each one is `{id, alert, context}`. `context` is `{logs, metrics, recent_deploys, tool_errors}` exactly as WARDEN's stack backend would gather it. |
| `key.json` | The answer key, one entry per case: `kind`, `service`, `novel`, `cause`, `cause_evidence`, `correct_actions`, `harmful_actions` and `target`. |
| `generator/lib.py` | Builders that emit each reader's lines, in reader order. |
| `generator/cases_*.py` | The cases, one file per service family. |
| `generator/gen.py` | Writes the incidents and the key. Its output is deterministic. |
| `generator/validate.py` | Checks every case. |

To regenerate and validate:

```
cd generator
set PYTHONPATH=C:\work\warden-g1\src;.
C:\work\warden\.venv\Scripts\python.exe gen.py
C:\work\warden\.venv\Scripts\python.exe validate.py
```

`validate.py` checks the following:

- `Alert(**alert)` builds with no `rejected_labels`.
- `ContextBundle(**context)` builds.
- Every action is an `ActionKind`.
- No action is both correct and harmful.
- `no_fault` keys are exactly `["no_action","escalate_to_human"]`, and `incomplete` keys are exactly `["escalate_to_human"]`.
- Every `cause_evidence` string is an exact substring of an item text from `warden.evidence.index(ContextBundle(...))`, so it is checked against what WARDEN shows. Tool errors are checked in their reduced `tool_error_text` form, for example `logs changes: throttled on LookupEvents`, not as raw text.
- The case id does not appear anywhere inside the evidence.
- The target is named in the evidence or the labels.
- Every `LOG` timestamp is within ±15 minutes of the alert.
- No line contains invisible characters.

Current result: 45 cases, 0 failures.

## Mix

| Kind | Count |
|---|---|
| fault (one action fixes it) | 25 (56%) |
| multi_fault | 6 (13%) |
| no_fault (healthy control) | 7 (16%) |
| incomplete (unreadable evidence) | 7 (16%) |
| **novel** | **17 (38%)** |

By service: ECS 14 (11 Fargate, 3 EC2-backed), EKS/Kubernetes 10, Lambda 10, Auto Scaling 5, App Runner 4, standalone
EC2 2.

### Change-caused faults and decoys

**Faults caused by a CHANGE**, where `revert_change` is right:

- ECS desired count set to 0.
- Security-group egress revoked, using the network-change line form.
- Lambda reserved concurrency cut.
- Lambda provisioned concurrency lowered.
- Event source mapping disabled.
- Auto Scaling processes suspended.
- Launch-template update.
- App Runner `UpdateService`.

**Decoys**, where an unrelated change is present but did not cause the incident. When the decoy and the real cause
are both CHANGE lines on the same resource, `revert_change` cannot tell them apart by action kind alone. Those key
entries therefore carry `cause_change` and `decoy_change` (CloudTrail event names), so a scorer can judge which CHANGE
a proposal cites:

- `cmp-ecs-secret-decoy`: `TagResource`. The cause is the deploy's `UpdateService`, and reverting it equals the rollback.
- `cmp-lambda-code-decoy`: a reserved-concurrency increase. The cause is `UpdateAlias20150331`, and reverting it equals the rollback.
- `cmp-asg-launch-template-decoy`: `CreateOrUpdateTags`. The cause is `UpdateAutoScalingGroup`.
- `cmp-ecs-desired-zero`: an image deploy 5 hours earlier that was serving fine.
- `cmp-ecs-ec2-eni-limit`: an autoscaler's `UpdateService`. Reverting it is listed as harmful.

**Novel kinds:**

- CPU-architecture mismatch, in two cases: an ECS image and a Lambda layer.
- Lowered Fargate ephemeral storage.
- A Fargate retirement that re-pulled a mutable `:latest` tag.
- ENI limit on awsvpc tasks running on EC2.
- Clock skew on one container instance.
- HPA flapping.
- Init-container deadlock.
- DNS failures from a musl base image combined with `ndots:5`.
- cgroup v2 memory accounting with Java 8u181.
- Subnet IP exhaustion together with ENI-bound max-pods.
- IMDS hop limit hit after a move to SDK v2.
- Auto Scaling processes left suspended.
- SnapStart restore failures.
- Provisioned-concurrency spillover.
- A clean Fargate retirement, as a healthy control.

## Independence rules followed

**Read, only to copy the output formats:** these files under `C:\work\warden-g1\src\warden\`:

- `aws_stack.py`
- `aws_describe.py`
- `resources.py`
- `aws_backend.py`
- `k8s_backend.py`
- `tools.py`
- `quarantine.py`
- `evidence.py`
- `models.py`
- `database.py`, partly, through a grep of its function signatures and f-strings. No compute case uses it.

**Not read, grepped or opened:**

- `src/warden/data/`, `fixtures/`, `verifier.py`, `grounding.py`, `graph.py`, `catalog.py`, `resolver.py`, `platforms/`, `knowledge.py`, `playbook.py`, `runbook.py`, `investigation.py`, `scenarios/`, `docs/`, `tests/`, `evals/`, `scripts/`
- `~/warden-bench-runs`, `~/warden-heldout/g9-2026-10-10`, `~/.claude`

**Other constraints:**

- Nothing under `C:\work` was modified.
- No AWS calls and no other network calls were made.
- No secrets are used.

**Executed but not read.** The generator imports WARDEN's own formatting helpers from the allowed modules, so that a line
cannot drift from its reader by a typo. Those helpers are:

- `_safe`, `_key`, `_dims`, `_env_items`, `task_stop_cause`, `_ASG_CAUSES`, `_CAPACITY_CHANGE`, `_NETWORK_SYMPTOM` and `_NOT_RESOURCES` from `aws_stack`.
- `state_line` from `aws_describe`.
- `labels_for` and `LABEL_KEYS` from `resources`.
- `INTERESTING_EVENT_REASONS` from `k8s_backend`.
- `_ERRORISH`, `LOG_MAX_LINES`, `LOG_MAX_PAGES`, `LOG_EVENT_LIMIT` and `LOG_ERROR_EXTRA` from `aws_backend`, used to reproduce the log reader's own truncation.
- `index` from `evidence`, used in `validate.py` to check `cause_evidence` against what WARDEN shows.

Importing them also loads `environments.py`, `observability.py` and `tools.py` transitively. That code was run, not read.

`validate.py` imports `warden.models` as the task asked. `warden.evidence._kind` was run once, from the command line
rather than from either script, to count trust classes. That run found 42 of the 149 `cause_evidence` strings only in
quarantined L/E lines, so WARDEN's model sees them only as typed F facts. It also found no trusted-prefix line demoted.

## Assumptions that matter

1. **Key semantics.**
   - `correct_actions` lists every acceptable best answer. For example, `revert_change` and `scale_up` both fix "desired count set to 0".
   - For `multi_fault`, `correct_actions` holds the fix for each fault plus `escalate_to_human`, because one proposal cannot fix both faults.
   - `harmful_actions` holds the actions that worsen the incident or hide it. For every fault, `no_action` is listed as harmful. An action that is merely ineffective is left neutral.
   - In decoy cases where the decoy and the cause share a target, `revert_change` is neutral. The optional `cause_change` and `decoy_change` fields name the CloudTrail events, so a scorer can judge which CHANGE a proposal cites.
2. **Services without a log reader.** WARDEN has no log reader for Auto Scaling, standalone EC2 or App Runner. Their evidence is only ALARM, CHANGE, STATE and ASG activity lines. In `cmp-apprunner-vpc-egress`, for example, the evidence shows only that an `UpdateService` came right before the 5xx errors and 30-second latency. The VPC-egress detail in `cause` is the author's ground truth; the evidence does not show it.
3. **The ENI cause is invisible in `cmp-ecs-ec2-eni-limit`.** WARDEN turns ECS service events into counts, so the `RESOURCE:ENI` placement text never reaches the evidence. The case shows `unable_to_place=9`, desired 12 and running 4. The correct answer is still `escalate_to_human`.
4. **Approximated AWS texts.** These texts are plausible but I could not confirm them word for word:
   - The Fargate retirement stop reason and its `TerminationNotice` stop code.
   - The SnapStart `afterRestore` and `RESTORE_REPORT` lines.
   - The 400 message the Kubernetes API returns when asked for an unscheduled pod's logs.
   - That CloudTrail indexes `UpdateEventSourceMapping` under the function name and `UpdateNodegroupVersion` under the cluster name. Both are assumed found by WARDEN's resource-name lookup.
   - The App Runner `StartDeployment` principal.

   All other texts follow AWS's documented formats: ECS stop reasons, `CannotStartContainerError`, `ResourceInitializationError`, Auto Scaling activity causes, EKS `InsufficientFreeAddresses`, Lambda `INIT_REPORT` and `REPORT`, and the Go SDK v2 IMDS error.
5. **No real-looking identifiers.** The account is AWS's documentation example account, assembled from parts in `lib.py`. The region `eu-west-1` appears only in data strings. Request IDs, task IDs and pod suffixes come from a per-case seeded RNG.
6. **Reader timing.** Kubernetes events are filtered against "now minus 15 minutes" by the k8s reader, so every event is placed within that window, as if WARDEN read the incident shortly after it fired. Alarm metric values follow `_cw_read`: a `Sum` is totalled over the ±10-minute window, and every other statistic is the maximum. The alarm reader reads sibling metrics with `Maximum`, which gives these values:
   - Lambda's per-invocation metrics (`Invocations`, `Errors`, `Throttles`, and the provisioned-concurrency invocation counts) read as 1 or 0.
   - App Runner's count siblings are one-minute peaks, while its `Sum` alarm value is a window total.

   Lambda log volume agrees with the invocation metrics in one of two ways:
   - Low-traffic functions show every invocation of the window, which stays under the 120-line cap.
   - `cmp-lambda-pc-spillover` and `cmp-ok-lambda-single-error` show what `AwsBackend.logs` keeps of a window past its 10-page budget: the newest 120 events of the first 2000. They also carry the reader's two `[output truncated]` tool errors.
7. **The skewed host stamps its own logs.** In `cmp-ecs-ec2-clock-skew`, the lines from the bad host carry its own fast clock. The awslogs driver stamps lines with the container host's time, so those lines interleave out of real order.
8. **Built against the `warden-g1` working tree as it stood on 2026-10-10.** By the time the review was applied, the tree held uncommitted reader changes made by someone else, not by me. Those changes tag incomplete-series partials `[<outcome> on GetMetricData]`, tag the Logs Insights timeout `[timed out on GetQueryResults]`, and add `DescribeScalingActivities` to the read operations. The cases follow those current formats. Regenerate if the change is reverted.

## Review fixes applied 2026-10-10

These fixes apply the independent review in `REVIEW.md`. After rebuilding, `validate.py` reports 0 failures against `warden.evidence.index`.

**All cases**

- Tool errors no longer carry the case id as the reader-role session name. They now use a neutral `inc-<n>`.
- `validate.py` now checks `cause_evidence` against WARDEN's rendered item texts, and fails if a case id appears in the evidence.
- Logs Insights counts (`log_error_lines`, `log_errors_peak_per_min`) are now computed from the visible events with WARDEN's own filter. They no longer disagree with the logs.

**ECS**

| Case | Change | Why |
|---|---|---|
| `cmp-ecs-arch-mismatch` | Removed the app log line `exec format error` and the `deployments_failed` metric. | runc never starts the process, so it writes no log. The circuit breaker is off, so WARDEN omits the metric. |
| `cmp-ecs-ec2-bad-image` | Removed `deployments_failed`. Added the old revision's two scheduler-stopped tasks. | The counters now match the listed tasks. |
| `cmp-ecs-secret-decoy` | Removed `revert_change` from harmful. Added `cause_change` and `decoy_change`. Set PRIMARY `failed=5` to match the listed failures. Added two scheduler stops of `:62`. Removed `deployments_failed`. | Reverting the deploy's `UpdateService` is the rollback. |
| `cmp-multi-ecs-deploy-and-egress` | Removed `deployments_failed`. Set PRIMARY `failed=4` to match the listed tasks. | The counters now match. |
| `cmp-ecs-desired-zero` | Removed CPU and memory utilisation. | No task ran in the metric window. |
| `cmp-ecs-sg-egress-revoked` | Removed the "ready ... pool=pg" line. | It came after the revoke. The suggested re-stamp to 07:43:30 would fall outside the reader's ±15-minute window, so the line was dropped instead. |
| `cmp-ecs-ephemeral-storage` | Changed the alarm to `RunningTaskCount < 3`, renamed it `render-worker-running-tasks-low`, and replaced the cause_evidence with `cause=exit exit=1`. | The storage alarm would have fired before the change, and its name revealed the failure domain. |
| `cmp-ecs-retirement-latest-tag` | The retired task now logs a 6-day-uptime heartbeat. Events are now `started_tasks=4`. | A task 3 minutes old is not retired for platform patching. |
| `cmp-ecs-ec2-clock-skew` | Skew raised to +17:52, past S3's 15-minute tolerance, with the bad host's stamps shifted to match. The alert name now matches its alarm, and the summary describes the CPU alarm. The host `chronyd` line was replaced by an app-level warning. The cause_evidence was updated. | The old skew was within S3's tolerance, and the chronyd line stated the answer. |
| `cmp-ok-ecs-fargate-retirement` | The swap now happens at 07:58 to 07:59. | A 1-of-1 alarm fires at 08:00. |
| `cmp-inc-ecs-describe-denied` | Spans now use the rendered form. | WARDEN shows tool errors only in that form. |

**Lambda**

| Case | Change | Why |
|---|---|---|
| All Lambda cases | `alias_live=<live version>`. Per-invocation siblings are now 1 or 0. One request id per invocation. Invocation and error counts now match the visible invocations, with alarm thresholds lowered to suit. | These now match what the readers produce. |
| `cmp-lambda-pc-spillover` | `scale_up` added to correct. Cold invocations now take 3.4 to 4.1 s inside the handler, alarm p99 is 4105. Logs show the reader's truncated read. The cause_evidence now uses `lambda_concurrent_executions=58` and the lazy-initialisation line. | `Duration` excludes init time, so a slow cold start alone could not raise it. |
| `cmp-lambda-arm-layer` | Added a `UpdateFunctionCode20150331v2` CHANGE. Removed `revert_config` from harmful. | Only that API call sets the architecture. Reverting the config is ineffective, not harmful. |
| `cmp-lambda-code-decoy` | `revert_change` is no longer harmful. Added `cause_change` and `decoy_change`. 6 of 10 invocations error, and the cause text says so. | Reverting the alias move is the rollback. |
| `cmp-lambda-reserved-cut` | The cause now says "hundreds of times a minute". | `lambda_throttles` is a total over the window. |
| `cmp-lambda-snapstart` | The `afterRestore failed` and `RESTORE_REPORT` lines now come 10 s after `RESTORE_START`. | That matches the restore-limit story. |
| `cmp-lambda-esm-disabled` | Mapping disabled at 07:49:27. Added the last three batches before it. | A 10-of-10 breaching alarm fires at 08:00. |
| `cmp-ok-lambda-single-error` | At about 40 invocations a second, the reader keeps only the first seconds of the window. Added its two truncation errors. The error line is no longer among the kept lines. | That is what the reader would keep at this traffic. |
| `cmp-inc-lambda-throttled-reads` | Spans now use the rendered form. | WARDEN shows tool errors only in that form. |

**EKS**

| Case | Change | Why |
|---|---|---|
| All EKS cases | Pod suffixes and ReplicaSet hashes are drawn from Kubernetes' own alphabet. | The previous suffixes used characters Kubernetes never generates. |
| `cmp-eks-hpa-flapping` | Scale-ups now step 3→7→14 and 3→7→12. | The default policy allows at most +100% per step. |
| `cmp-eks-cgroupv2-jvm` | Snapshot sizes are now 0.62 or 0.31 of 0.70 GiB. Every restarted container has its `(previous)` block. Pods are listed newest first. | The old sizes could not fit a 1 GiB container. |
| `cmp-eks-dns-musl-ndots` | The cause wording now says musl aborts the search-list walk on the first timeout. Added the full rolling-update events. Every restarted container has its `(previous)` block. The startup line no longer prints `resolv.conf`. | musl falls back to TCP on truncation since 1.2.4, so the old wording was wrong. The startup line spelled out the answer. |
| `cmp-eks-ip-exhaustion` | The scale event is now "to 18 from 9". | It now matches the 9 scheduled pods. |
| `cmp-eks-imds-hop-limit` | The pod UID is consistent across lines. Each pod has a `(previous)` block. | A UID differed between two lines. |
| `cmp-multi-eks-oom-and-ip` | The restart count and alarm value now match the listed statuses. Each restarted pod has a `(previous)` block. | The counts disagreed. |
| `cmp-ok-eks-rollout-restart` | The restart now starts at 07:57:48. | A 1-of-1 alarm fires at 08:00. |
| `cmp-inc-eks-*` | Spans now use the rendered form. | WARDEN shows tool errors only in that form. |

**Auto Scaling, EC2 and App Runner**

| Case | Change | Why |
|---|---|---|
| `cmp-multi-asg-spot-and-scheduled` | The failed launches now carry only their Cause (`cause=other capacity=1->2`). The alarm threshold is now 2. The interruption and launches moved to 07:57 to 07:59. Six scale-in activities replace the single one. `revert_change` is now neutral rather than correct. | Deleting the schedule does not restore the capacity it removed. |
| `cmp-asg-launch-template-decoy` | Added `cause_change` and `decoy_change`. | A scorer can now judge which CHANGE a proposal cites. |
| `cmp-ok-asg-scheduled-scale-in` | Five scale-in activities, one per instance. | AWS records one activity per instance. |
| `cmp-ok-ec2-status-transient` | No `Events` field. | `DescribeInstanceStatus` omits it when there are none. |
| `cmp-apprunner-vpc-egress` | `escalate_to_human` added to correct. The alarm Sum is now a window total (22488). | The VPC detail is invisible in the evidence. |
| `cmp-apprunner-bad-deploy` | The alarm Sum is now a window total (11280). | It now matches how the reader totals `Sum` alarms. |
| `cmp-inc-ec2-denied` | `restart_pods` is no longer harmful. Spans now use the rendered form. | Rebooting or replacing the instance is a documented first response, so calling it harmful is debatable. |
| `cmp-inc-apprunner-partial` | The status is now `InternalError`. Spans now use the rendered form. | `PartialData` is implausible for one short series. |
| `cmp-inc-asg-alarm-gone` | Spans now use the rendered form. | WARDEN shows tool errors only in that form. |

**Not applied**

- REVIEW HIGH 1, changing `alert_id` and severity: per the coordinator, those are made opaque and uniform at merge. Only the case id inside the evidence was removed.
