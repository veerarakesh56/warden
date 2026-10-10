# WARDEN held-out set G10 (2026-10-10)

172 incident cases across every main AWS service, written to test whether WARDEN finds and fixes incidents it was
never tuned on. The cases are in `incidents/`, one JSON file each (`{id, alert, context}`: the alert, and the evidence
WARDEN's stack readers would have read). The grading key is in `key.json`. Keep the key away from anything that runs
WARDEN.

| Group | Cases | Services |
|---|---|---|
| compute | 45 | ECS (Fargate and EC2), EKS, Lambda, EC2 with Auto Scaling, App Runner |
| data | 41 | Aurora and RDS (PostgreSQL, MySQL), DynamoDB, ElastiCache, MemoryDB, OpenSearch, Redshift, S3, EFS |
| integration | 42 | SQS, SNS, EventBridge and Scheduler, Step Functions, Kinesis, Firehose, MSK, API Gateway, ALB, NLB, CloudFront, Route 53 |
| platform | 44 | IAM and SCPs, KMS, Secrets Manager, VPC networking, Cognito, WAF, ACM and Private CA, AppConfig, CodePipeline, Glue, Athena |

Kinds: 99 single faults, 23 with two faults, 25 healthy controls and 25 with incomplete evidence. 79 cases are
**novel**: a failure kind none of WARDEN's signatures, rules or earlier benchmarks covers.

## Who made it, and how

1. **Four independent authors** (Claude Opus 5.5 agents, one per group) wrote the cases on 2026-10-10. Each was
   barred from WARDEN's signatures, policies, prompt, rubrics,
   catalogue, fixtures, tests, evals and earlier runs, and read only the evidence readers, to copy their exact line
   formats. Each one's rules, assumptions and generator notes are in `authors/<group>-README.md`.
2. **Four independent reviewers** (one per group) read every case and key line by line against the reader code and
   AWS's documented behaviour: format, realism, whether the keyed cause is visible to WARDEN, and answer leaks. Their
   tables hold 14 HIGH, 53 MED and 79 LOW rows; the reports are in `reviews/<group>-REVIEW.md`.
3. **The authors applied the reviews** in their own generators: every HIGH and MED, and the format and number slips.
   What each chose not to apply, and why, is at the end of its README.
4. **The coordinator merged and checked them** (`merge` below), and checked every case independently of the authors'
   validators: each alert and context loads in WARDEN's own models, every label is one WARDEN's alarm mapping gives,
   every action is an `ActionKind`, the no-fault and incomplete keys are exact, every `cause_evidence` string is in an
   item WARDEN shows (`evidence.index`), and every 12-digit number was checked in context (request-id tails, byte
   counts, shard ids - none an account id; listed in `scripts/check_publishable.py`).

## The merge

- **Opaque ids.** A case's file name and alert id were its author's slug (`int-ok-*` meant a healthy control,
  `*-inc-*` incomplete evidence, `*-multi-*` two faults, and many named the cause). They are now `g10-001` to `g10-172`,
  shuffled with seed 20261010; the slug stays in the key only. No case id appears inside any case's evidence.
- **Uniform severity.** Every alert is `high`: the authors had set `low` on healthy controls only.
- **The key** (`key.json`, per id): `kind`, `group`, `slug`, `service`, `novel`, `cause`, `cause_evidence`,
  `correct_actions`, `harmful_actions`, `target`. Some groups add `best_action`, `family`, `alternatives`,
  `cause_change`/`decoy_change` and `assumes` (an assumption about AWS a live window should re-check).

## Scoring

`scripts/heldout_bench.py` runs each case through redact -> tripwire -> diagnose -> verify, as a replay, and scores it
from the key only:

- **action**: CORRECT (in `correct_actions`), HARMFUL, SAFE (escalated or did nothing where a fix existed) or WRONG;
- **fixed**: a CORRECT fix where the key holds one. An escalation is safe, never a fix - the reviews showed that an
  answer that always escalates scores 103 of 172 "correct" from the keys alone, and that floor is printed beside
  every run (`baseline_always_escalate`);
- **diagnosis**: a citation quotes, or points at an item holding, one of the `cause_evidence` strings;
- **gate**: what the verifier decided; **harm allowed**: a HARMFUL or WRONG answer that reached a person.

A replay cannot read more evidence (the investigation loop's extra reads need live AWS).

## What building it found in WARDEN

The authors and reviewers recorded defects in WARDEN itself, separate from the cases. Each was fixed with a test
and a plant check, or recorded open; see `docs/FAILURE-MODES.md`, rows H1-H7.

Two of the authors aligned two tool-error texts to WARDEN's reader code as it stood mid-fix (the tagged PartialData
and "more writes than were read" partials, `authors/integration-README.md` and `authors/compute-README.md`). The case
files are the same for every run; how a WARDEN version renders them is part of what that run measures.

Results: [RESULTS.md](RESULTS.md).
