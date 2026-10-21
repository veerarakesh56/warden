# WARDEN held-out set G9 (2026-10-10)

48 synthetic incident cases for testing whether WARDEN generalises to the main AWS services and to kinds of failure
it was not tuned on. The cases are in `incidents/`, one JSON file each. The grading key is in `answer-key.json`. Keep
the key away from anything that runs WARDEN.

Results: [docs/BENCHMARKS.md](../../BENCHMARKS.md).

## Who wrote it

An independent author (a separate AI agent) wrote every case and its key on 2026-10-10. Nobody edited the cases
afterwards. Every alert starts at `2026-10-10T08:00:00+00:00` (13:30 IST).

The author was not allowed to read WARDEN's incident signatures, policies, prompt, rubrics, fixtures, tests, evals or
earlier benchmark runs. It read only WARDEN's evidence readers (`aws_stack.py`, `aws_describe.py`, `resources.py`,
`aws_backend.py`, `k8s_backend.py`, `database.py`, `tools.py`, plus `evidence.py` and `models.py` for shapes), to copy
the exact line formats WARDEN produces. The scripts that generated the cases contain the key and are not published.

Every case was checked against WARDEN's own schema before it was written:

- each alert loads as `warden.models.Alert`, and each context as `ContextBundle`;
- each label key is one WARDEN's alarm mapping gives (`resources.LABEL_KEYS`, plus `alarm`);
- each action is an `ActionKind`;
- each `cause_evidence` string is an exact substring of the case's evidence;
- no-fault keys are exactly `["no_action", "escalate_to_human"]`, and incomplete-evidence keys are exactly
  `["escalate_to_human"]`.

## Assumptions

- **Account and Region.** The cases use `ap-south-1` and the AWS documentation account `111122223333`. Resource names
  start with `warden-dev-`. Where an alarm dimension is an AWS-assigned id (an instance, an EFS file system, a NAT
  gateway, a KMS key and so on), it is id-shaped.
- **Metric-math alarms.** Three cases use one alarm across two resources (`sqs-dlq-broken-consumer`,
  `sqs-dlq-redrive-after-rollback`, `sqs-fifo-poison-message`), so the alarm names both the consumer function and the
  queue.
- **CloudTrail lookups by name.** `CHANGE` lines assume CloudTrail finds a write by the resource name in the labels.
  Where a service's events are not usually indexed that way (API Gateway is the main example), the case shows
  `CHANGE none`. Writes to resources the alarm does not name never appear.
- **Maximum statistic on sibling metrics.** Per-request metrics read with `Maximum` show `1`. This is noise, not a
  signal.
- **CloudFront and Route 53.** Their alarms exist only in us-east-1, so a one-Region reader finds nothing. Both cases
  are `incomplete`, with empty evidence.
- **Short evidence.** Several cases have fewer than 8 evidence lines. No lines were invented to pad them.

## Counts

29 `fault`, 6 `multi_fault`, 8 `no_fault` and 5 `incomplete`. 11 cases are a novel failure kind.

## Formats

A case is `{"id", "alert": {...}, "context": {"logs", "metrics", "recent_deploys", "tool_errors", "empty_reads"}}`.
Feed `alert` and `context` to WARDEN as the alert and the gathered `ContextBundle`.

`answer-key.json` maps each case id to `kind`, `service`, `novel`, `cause` (one sentence, for people),
`cause_evidence` (exact substrings; a right diagnosis cites at least one), `correct_actions`, `harmful_actions` and
`target`. When no `ActionKind` fits, the correct action is `escalate_to_human`.

## Run it

```bash
WARDEN_PROVIDER=anthropic python scripts/heldout_bench.py \
    --cases docs/bench/heldout-g9-2026-10-10 --out <a new directory outside the repository>
```
