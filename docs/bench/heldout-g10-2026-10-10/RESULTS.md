# Held-out benchmark G10 (2026-10-10): results

172 cases from four independent authors, reviewed line by line by four more (see [README.md](README.md)). Each run is
one pass of WARDEN's redact -> tripwire -> diagnose -> verify over every case, as a replay, scored from the key only
(`scripts/heldout_bench.py --docs`).

- Model: Claude Sonnet 5 on the Claude API; the AWS documentation lookups on, as in the read zone.
- Runs, all on 2026-10-10: the baseline on WARDEN 209063b (before any fix this set found), then ff73442 and 397346f
  (after the reader, trust, tool-error and grounding fixes). Each run's per-case scores are in `runs/`; the full reports are kept outside the repository.

## Measured

| | baseline 209063b | ff73442 | 397346f |
|---|---|---|---|
| Correct action (of 172) | 132 | 131 | 138 |
| Right fix where the key holds one (of 88) | 79 | 80 | 80 |
| Diagnosis cites the cause | 160 | 164 | 163 |
| Right fix reached a person | 17 | 19 | 23 |
| Harmful proposals | 18 | 20 | 16 |
| Wrong proposals | 21 | 20 | 16 |
| Harmful or wrong reached a person | 1 | 1 | 1 |
| Unanswered (model unavailable) | 1 | 0 | 1 |
| Model cost (USD) | 3.95 | 3.94 | 4.05 |

**The floor.** An answer that always escalates scores 103 of 172 "correct" from the keys alone, and fixes nothing.
WARDEN's 132-138 are read against that 103.

**Last run by kind:** single faults 77/99, two faults 22/23, healthy controls 18/25, incomplete evidence 21/25; novel
kinds 59/79. **By group:** compute 34/45, data 33/41, integration 36/42, platform 35/44.

**What one run can show.** Two runs of the same code differ by a few cases (G10 measured 18-22 of 30 on one prompt).
The baseline and ff73442 are within that band. 397346f's +6 correct and +6 right fixes reaching a person include the
P15 fix (0b33ffb); one run each cannot separate that from variance.

## The one wrong answer that reached a person, in every run

g10-135 (`cmp-multi-ecs-oom-and-desired`): a memory leak, and a person's cut of the service's desired count ten
minutes before the alarm. The model named only the leak and proposed a restart; nothing in the verifier stopped it.
P31 (added after the baseline, observe mode) records it in run 397346f: *"UpdateService on pricing-api by
user/dev-ssingh (C3) is neither cited nor reverted"*. Measured on the baseline's answers, P31 named 2 wrong answers
and none of the 132 right ones.

## What held right fixes back (397346f)

Of the right fixes that were not approved for a person, the policies that held them: P15 citations do not support the
action (31), P8 partial context (26), P30 no catalogue entry carries it out (22), P6 blast radius (8). Most P15 and
P30 holds are reverts and scale-ups of resources WARDEN has no fix for - an escalation is the right outcome there.

## After the runs

The answers above were re-verified with the code after these runs (a700faf) - the verifier only, no model call - and
the deterministic changes were measured, not assumed:

| Same answers, current verifier | baseline | ff73442 | 397346f |
|---|---|---|---|
| Right fix approved for a person | 23 | 23 | 25 |
| Harmful or wrong approved for a person (a700faf) | 2 | 2 | 2 |
| ... with P31 enforced (owner decision) | 1 | 2 | 1 |

The changes behind it: the P15 revert fix, rollbacks supported by the deploy record (g10-117, g10-171), only the
latest change to a resource is undone (g10-082), and new revert families (Lambda timeout/memory/storage, SQS queue
timing, Kinesis retention), and P31 enforced. P31 escalates g10-135 where the model ignored the desired-count cut;
in ff73442 the model cited that change and dismissed it, which P31 by design does not judge. The other one per run is
a revert:

- g10-158 (baseline): undo of a Terraform apply on a healthy queue. The platform's live read refuses it twice over: a
  change made by infrastructure as code is left to the code, and a queue's retention period is never set by WARDEN.
- g10-085 (ff73442): undo of a forced redeploy's UpdateService. The live read refuses it (no desired count in the
  request), and the CHANGE line now names the request's fields, so the verifier refuses it too - the cases predate
  that line format, so the replay cannot show it.
- g10-075 (397346f): undo of a CI pipeline's Lambda configuration change. The live read refuses it unless that change
  set only the timeout, memory or ephemeral storage; the case does not record which fields it set.

In WARDEN's flow, an approved verdict plans a fix only through the platform's live read (`activities.plan_fix`); a
refusal there plans nothing and the person is told why.

## Owner decisions (2026-10-10, after these runs)

- **P29** (P8 escalates over WARDEN's own log sample). On the baseline, enforcing it would let 9 more right fixes reach
  a person and no wrong one. Stays observed until the live window measures it.
- **P31** (a person's recent write left unaddressed). Named only wrong answers in observe mode: enforced.
- **Reverting an infrastructure-as-code change.** WARDEN's live read now refuses to undo a change made through
  Terraform, OpenTofu, Pulumi or Crossplane (by the request's user agent; CloudFormation already counted as an AWS
  service), and prepares the exact inverse for a person - the next apply would undo WARDEN's undo. The keys call a
  revert right in 44 answers across the runs where the change was made by a role named for a pipeline or Terraform;
  the cases do not record user agents, so how many of those the live read would refuse is not known. Kept.
- **Network undo.** Routes may be restored after a passkey approval (T3, the security-group undo's refusals); network
  ACL entries (a security control) and Route 53 health checks stay with a person.

## Limits

- A replay reads nothing more: the investigation loop's extra reads, Reachability Analyzer and every live refusal above
  need live AWS (the live window).
- The cases copy WARDEN's reader formats as of 2026-10-10 morning; formats changed since (request fields on CHANGE
  lines) are not in them.
- One run per code version; pass^k over several runs is the next measurement.
