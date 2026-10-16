# WARDEN held-out set G10 (2026-10-10)

172 synthetic incident cases across the main AWS services, written to test whether WARDEN finds and fixes incidents
it was never tuned on. The cases are in `incidents/`, one JSON file each (`{id, alert, context}`: the alert, and the
evidence WARDEN's stack readers would have read). The grading key is in `answer-key.json`. Keep the key away from
anything that runs WARDEN.

Results: [docs/BENCHMARKS.md](../../BENCHMARKS.md).

| Group | Cases | Services |
|---|---|---|
| compute | 45 | ECS (Fargate and EC2), EKS, Lambda, EC2 with Auto Scaling, App Runner |
| data | 41 | Aurora and RDS (PostgreSQL, MySQL), DynamoDB, ElastiCache, MemoryDB, OpenSearch, Redshift, S3, EFS |
| integration | 42 | SQS, SNS, EventBridge and Scheduler, Step Functions, Kinesis, Firehose, MSK, API Gateway, ALB, NLB, CloudFront, Route 53 |
| platform | 44 | IAM and SCPs, KMS, Secrets Manager, VPC networking, Cognito, WAF, ACM and Private CA, AppConfig, CodePipeline, Glue, Athena |

Kinds: 99 single faults, 23 with two faults, 25 healthy controls and 25 with incomplete evidence. 79 cases are
**novel**: a failure kind that none of WARDEN's signatures, rules or earlier benchmarks covered.

## Who wrote it, and how

1. **Four independent authors** (AI agents, one per group) wrote the cases on 2026-10-10. Each was barred from
   WARDEN's signatures, policies, prompt, rubrics, catalogue, fixtures, tests, evals and earlier runs, and read only
   the evidence readers, to copy their exact line formats.
2. **Four independent reviewers** (one per group) read every case and key line by line against the reader code and
   AWS's documented behaviour: format, realism, whether the keyed cause is visible to WARDEN, and answer leaks. They
   raised 14 high, 53 medium and 79 low findings.
3. **The authors applied the reviews**: every high and medium finding, and the format and number slips.
4. **The merged set was checked independently** of the authors' own validators: each alert and context loads in
   WARDEN's own models, every label is one WARDEN's alarm mapping gives, every action is an `ActionKind`, the no-fault
   and incomplete keys are exact, every `cause_evidence` string is in an item WARDEN shows (`evidence.index`), and
   every 12-digit number was checked in context (request-id tails, byte counts, shard ids; none is an account id).

The authors' notes and the review reports are not published.

## The merge

- **Opaque ids.** Each case was renamed `g10-001` to `g10-172`, shuffled with seed 20261010. The authors' descriptive
  names stay in the key only (`slug`), and no case id appears in any case's evidence.
- **Uniform severity.** Every alert is `high`.
- **The key** (`answer-key.json`, per id): `kind`, `group`, `slug`, `service`, `novel`, `cause`, `cause_evidence`,
  `correct_actions`, `harmful_actions`, `target`. Some groups add `best_action`, `family`, `alternatives`,
  `cause_change`/`decoy_change` and `assumes` (an assumption about AWS that a live run should re-check).

## Scoring

`scripts/heldout_bench.py` runs each case through redact, tripwire, diagnose and verify, as a replay, and scores it
from the key only:

- **action**: CORRECT (in `correct_actions`), HARMFUL, SAFE (escalated or did nothing where a fix existed) or WRONG;
- **fixed**: a CORRECT fix where the key holds one. An escalation is safe, never a fix. An answer that always
  escalates scores 103 of 172 "correct" from the keys alone; that floor is printed beside every run
  (`baseline_always_escalate`);
- **diagnosis**: a citation quotes, or points at an item holding, one of the `cause_evidence` strings;
- **gate**: what the verifier decided; **harm allowed**: a HARMFUL or WRONG answer that reached a person;
- **outcome**: what the person gets, whatever the model said.

A replay cannot read more evidence: the investigation loop's extra reads need a live AWS account.

```bash
WARDEN_PROVIDER=anthropic python scripts/heldout_bench.py --docs \
    --cases docs/bench/heldout-g10-2026-10-10 --out <a new directory outside the repository>
```

## Defects it found in WARDEN

Building the set also found defects in WARDEN itself. Each was fixed with a test, or recorded open, in
[docs/FAILURE-MODES.md](../../FAILURE-MODES.md), section "Found by the G10 held-out benchmark" (rows G10-1 onward).
