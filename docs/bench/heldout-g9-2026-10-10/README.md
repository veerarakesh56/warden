# WARDEN held-out set G9 (2026-10-10)

48 incident cases for testing whether WARDEN generalises to every main AWS service and to kinds of failure it was
not tuned on. The cases are in `incidents/`, one JSON file each. The grading key is in `key.json`. Keep the key away
from anything that runs WARDEN.

## Who made it, and when

- **Author:** an independent benchmark-author agent (Claude Opus 5.5), spawned from the owner's G9 session on
  2026-10-10. Nobody edited the cases after it wrote them.
- **Date:** 2026-10-10. Every alert starts at `2026-10-10T08:00:00+00:00` (13:30 IST).

## Independence rules the author followed

The author did **not** read, grep or open any of these:

- `src/warden/data/` (incident signatures, knowledge files, providers, environments, decider)
- `src/warden/fixtures/`
- `verifier.py`, `grounding.py`, `graph.py`, `knowledge.py`, `playbook.py`, `runbook.py`
- `scenarios/` (rubrics and scoring), `docs/bench/`, `tests/`, `evals/`
- `~\warden-bench-runs`
- `docs/FAILURE-MODES.md` and the plan folders

The only files it read were these, in `C:\work\warden-g1\src\warden\`, and only to copy the exact text formats WARDEN's
AWS readers produce:

- `aws_stack.py`, `aws_describe.py`, `resources.py`, `aws_backend.py`, `k8s_backend.py`, `database.py` and `tools.py`
- `evidence.py`, for the line-prefix conventions only
- `models.py`, for the Alert and ContextBundle shapes, `ActionKind` and `ACTION_MEANINGS`

Nothing in `C:\work\warden-g1` or `C:\work\warden` was changed. The generator imported `warden.models` and
`warden.resources` read-only, to check each case against WARDEN's own schema.

## How the cases were made

`generator/` holds the scripts. They contain the key, so never pass them to WARDEN.

- `common.py` copies each reader's line format: `ALARM`, `CHANGE`, `STATE`, `CONFIG lambda`, `CONFIG appconfig`, `CONFIG alb`, `ESM`, `QUEUE`, `TABLE`, `CLUSTER`, `TARGETGROUP`, `TARGET`, `APPSG`, `TASKROLE`, `POLICY`, `RULE`, `CODE`, `SOURCE`, `EVENT aurora`, `LOG lambda/…`, `LOG ecs/…`, `LOG k8s/<ns>/<dep> …` (with the k8s `EVENT`, `STATUS`, `ROLLOUT` and `(previous)` forms), `postgres stuck connection:` and `[reader] postgres …`.
- It also copies the metric-key rules: `alarm_<metric>` and `alarm_sibling_<ns>_<metric>` (aws_stack `_key`), `alarm_value` for namespaces not owned by AWS, and the per-reader keys.
- `cases_a.py`, `cases_b.py` and `cases_c.py` hold one `add(...)` per case.
- `python gen.py <out_dir> C:\work\warden-g1\src` writes the files after these checks. It refuses to write if any fails:
  - each alert passes `warden.models.Alert`, with no rejected labels;
  - each context passes `ContextBundle`;
  - each label key is in `resources.LABEL_KEYS`, plus `alarm`;
  - each action is an `ActionKind`;
  - each `cause_evidence` string is an exact substring of the case's evidence. Evidence means the log lines, metrics rendered as `key=value` the way `evidence.index` renders them, deploys and tool errors;
  - no-fault keys are exactly `["no_action", "escalate_to_human"]` and incomplete keys are exactly `["escalate_to_human"]`.

How the readers were followed:

- Labels are the ones `resources.labels_for` derives from the alarm's namespace and dimensions, plus `"alarm"`.
- Evidence lines come in the order and shape the stack backend emits them:
  - the alarm reader first: AppConfig `CONFIG`, then `ALARM`, then `CHANGE` lines, newest first, the way CloudTrail returns them;
  - then the `STATE` table readers, then each per-service reader.
- Log lines are sorted by timestamp and fall inside the reader's ±15 min window.
- Metrics are read over ±10 min at a 60 s period:
  - `Sum` series are summed;
  - every other statistic keeps the window's maximum;
  - a series with no datapoint is absent, not 0.
- Tool errors use gather's `<tool>: <reader chain>: [<outcome> on <Operation>] <first 200 chars>` form.

## Assumptions (where reality had to be chosen)

- **Account and region.** The dev environment is in `ap-south-1` and the account is `111122223333`, the AWS
  documentation example. Resource names start with `warden-dev-`. Where an alarm dimension is an AWS-assigned ID, it is
  ID-shaped instead: instance, EFS, NAT gateway, CloudFront distribution, Route 53 health check, Cognito pool, KMS key,
  ACM certificate and HTTP API ID.
- **Metric-math alarms.** Three cases use a metric-math alarm across two resources (`sqs-dlq-broken-consumer`,
  `sqs-dlq-redrive-after-rollback` and `sqs-fifo-poison-message`), so the alarm names both the consumer function and the
  queue. A single-metric alarm on a queue names only the queue, and WARDEN would then read no consumer logs.
- **CloudTrail lookups by name.** `CHANGE` lines assume CloudTrail's ResourceName lookup finds a write by the resource
  name in the labels, which is how `_read_changes` asks.
  - Where a service's events are not usually indexed by name, the case shows `CHANGE none`. API Gateway is the main
    example.
  - Writes to resources the alarm does not name never appear. Examples are an IAM policy edit, a queue policy, a VPC DNS
    attribute and a security group.
  - This is WARDEN's real view, and several cases test it.
- **Maximum statistic on sibling metrics.** The sibling-metric read uses `Maximum` for every metric. For per-request
  metrics, such as API Gateway Count and 4XXError, S3 AllRequests and Cognito SignInSuccesses, that reads `1`. The cases
  keep this quirk. It is noise, not a signal.
- **CloudFront and Route 53.** Their metrics, and so their alarms, exist only in us-east-1. The stack backend reads one
  region, so WARDEN finds no alarm and reads nothing. Both cases are therefore `incomplete` with empty evidence.
- **Daily metrics.** ACM `DaysToExpiry` is published daily, so a ±10 min read at a 60 s period usually finds no
  datapoint. That case has no metrics and records `empty_reads: ["metrics"]`.
- **Short evidence.** Several cases have fewer than 8 evidence lines. For an alarm on a resource that only the alarm
  reader and the `STATE` table read, three lines plus metrics is all WARDEN gets, and no lines were invented to pad
  them.

## Counts

- **By kind:**
  - 29 `fault`
  - 6 `multi_fault`
  - 8 `no_fault`
  - 5 `incomplete`
- **Novel failure kinds:** 11.

## Case format

Each case follows the brief: `{"id", "alert": {...}, "context": {"logs", "metrics", "recent_deploys",
"tool_errors", "empty_reads"}}`. Feed `alert` and `context` to WARDEN as the alert and the gathered ContextBundle.

## Key format

`key.json` maps each case id to these fields:

- `kind`
- `service`
- `novel`
- `cause`: one sentence, for humans.
- `cause_evidence`: exact substrings. A correct diagnosis cites at least one of them.
- `correct_actions`
- `harmful_actions`
- `target`

When no ActionKind fits a case, its correct action is `escalate_to_human`.
