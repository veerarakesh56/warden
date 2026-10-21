# Benchmarks

Every benchmark number this project quotes is on this page, with its date, the model that answered, and how to
reproduce it. Read the limits at the end before reading any number.

Three kinds of measurement exist:

| Kind | What it is | Where the data is |
|---|---|---|
| **Live runs** (waves 1-3) | Real faults injected into a throwaway AWS stack; WARDEN read the live account with a read-only identity and proposed a fix. It never acted. | `tests/fixtures/bench/<run>/` (redacted: account id and role ARNs masked) |
| **Replays** | The evidence recorded in those live runs, diagnosed again by today's pipeline and a chosen model. Used to qualify a model. | the same recorded runs |
| **Held-out sets** (G9, G10) | Synthetic incidents written by independent authors who never saw WARDEN's rules, with a separate answer key. | `docs/bench/heldout-*/` |

How each answer is graded is in [`scenarios/SCORING.md`](../scenarios/SCORING.md). Only typed fields are graded (the
proposed action, the gate's verdict, the cited evidence), never the model's prose.

## Which model runs in production, and why

| | |
|---|---|
| Model | Claude Sonnet 5.5 (`claude-sonnet-5-5`), effort `high`, on the Anthropic API |
| Qualified | 2026-10-15, 14:56 UTC (20:26 IST), anthropic SDK 1.4.0, prompt `d435b59f...` |
| Replay of the 30 recorded live incidents | **17 of 30 correct, 0 wrong answers allowed by the gate**, 24 escalated, 0 acted wrongly; $0.42 |
| The bar | 0 wrong-and-allowed and at least 17 correct (`src/warden/data/providers.yaml`) |
| Not qualified on the same day | Claude Opus 5.5: 15 of 30 |

The same file records Sonnet 5.5's answers to the G10 held-out set, re-scored under the current gate: 160 of 172
correct actions, 6 harmful proposals (every one stopped by the gate), 137 right outcomes, 0 harmful answers allowed,
$3.15. Opus 5.5 on the same set: 162 correct, 1 harmful, 136 right outcomes, 0 harmful allowed, $9.00. These two
per-case runs are not published; the totals are as recorded in `providers.yaml`.

WARDEN refuses any provider and model pair that is not listed there as qualified (`providers.qualified`); with no
usable model, an incident is escalated on the rules alone.

Reproduce (calls the model; costs about $0.50 on the API):

```bash
WARDEN_PROVIDER=anthropic WARDEN_MODEL=claude-sonnet-5-5 ANTHROPIC_API_KEY=... \
    python scripts/qualify_provider.py --out <a new directory outside the repository>
```

`--score-only` re-scores a finished run with no model call.

## Live runs on a real AWS account (September 2026)

Each scenario injected one fault (or none, for a healthy control) into a stack built for the run in `ap-south-2`, ran
WARDEN three times, then reverted the fault. WARDEN read the account with a read-only identity scoped to that wave.
The model was Claude Sonnet, answering through the `claude` command-line tool. Each run's rubric was committed
before the run, and its hash is in the run's `manifest.json`.

| Run | Platform | Scenarios x repeats | Diagnosis | Wrong or harmful, and the gate allowed it |
|---|---|---|---|---|
| `wave1-2026-09-11T155744Z` | ECS Fargate + CloudWatch | 14 (13 faults, 1 healthy) x 3 = 42 | 20 correct, 5 safe but unhelpful, 14 wrong, 3 no evidence | **14** |
| `wave2-2026-09-24T115746Z` | managed EKS (one `t3.small` spot node) | 10 (8 faults, 2 healthy) x 3 = 30 | 17 correct, 7 safe but unhelpful, 3 harmful, 2 wrong, 1 no evidence | **3** |
| `wave3-2026-09-25T044307Z` | RDS for PostgreSQL 16.13 (`db.t4g.micro`) | 6 (5 faults, 1 healthy) x 3 = 18 | 12 correct, 2 safe but unhelpful, 4 wrong, 0 no evidence | **0** |

What they found:

- **Wave 1: the gate could not stop "nothing is wrong".** All 14 wrong answers were `no_action` on a live fault.
  The version measured (0.7.0) exempted `no_action` from the evidence policies. That exemption was removed in 0.8.0;
  replaying the recorded reports through the newer gate refuses 12 of the 14 (a replay, not a new measurement).
- **Wave 1 also found a backend gap.** ECS's `failedTasks` count was not read, so a crash-looping deployment looked
  healthy. It has been read since 0.8.0, and has not been re-measured live.
- **Wave 2: three `scale_up` answers to an out-of-memory kill got through.** Policy P11 now escalates that pattern;
  it was written after seeing these runs, so it is not independently tested by them.
- **Wave 3: no wrong diagnosis got through.** Where WARDEN could see the sessions behind a problem, the model was
  right; where it could only count them, it was not. The reader was improved after the run and not re-measured.
- **The model is not deterministic**: 7 of 14 wave 1 scenarios, and 4 of 10 in wave 2, gave different answers across
  three identical repeats.
- An earlier wave 1 run (`wave1-2026-09-11T052533Z`) is kept but is **invalid as a measurement**: 39 of its 42 runs
  read the previous scenario's logs as evidence. That harness bug is fixed, and each run's evidence window is now
  checked by the scorer.

Re-score a recorded run offline (no AWS, no API key):

```bash
python -m scenarios.score --run tests/fixtures/bench/wave1-2026-09-11T155744Z \
    --rubric tests/fixtures/bench/wave1-2026-09-11T155744Z/grading/scoring.yaml
```

Always pass the run's own `--rubric`: `scenarios/scoring.yaml` has grown since, and scoring an old run against it
gives numbers that are not the published ones. Re-decide the recorded evidence with today's gate (no model call):

```bash
python scripts/replay_gate.py --reports tests/fixtures/bench/wave1-2026-09-11T155744Z/reports
```

The full-stack lab ([`FULLSTACK-LAB.md`](FULLSTACK-LAB.md)) ran faults fs-00 to fs-05 on 2026-09-26 and was then
stopped. **No full-stack score is published.**

## Held-out set G9: 48 cases (2026-10-10)

Written by one independent author; see [the set's README](bench/heldout-g9-2026-10-10/README.md). Answered by Claude
Sonnet 5 on the Anthropic API (anthropic 1.11.0), code of commit `d01407c`.

| | Result |
|---|---|
| Correct action | **34 of 48** (71%) |
| Diagnosis cites the evidence that carries the cause | 39 of 48 (81%) |
| Wrong or harmful action proposed | 13 of 48, of which the gate stopped 12 |
| Novel failure kinds, correct action | 4 of 11 |

The one wrong answer that reached a person proposed `scale_up` for NAT gateway port exhaustion. No catalogue entry
acts on a NAT gateway, so it would have been advice only. The run also found a real gap: CloudFront and Route 53
alarms exist only in us-east-1, and WARDEN read one Region. WARDEN has read alarms in AWS's global-service Region
since then (`aws_global_region` in `src/warden/data/environments.yaml`); that has not been re-run on this set.

## Held-out set G10: 172 cases (2026-10-10)

Written by four independent authors and reviewed by four more; see
[the set's README](bench/heldout-g10-2026-10-10/README.md). Answered by Claude Sonnet 5 on the Anthropic API with the
AWS documentation lookups on, three times on three code versions the same day.

| | baseline `209063b` | `ff73442` | `397346f` |
|---|---|---|---|
| Correct action (of 172) | 132 | 131 | 138 |
| Diagnosis cites the cause | 160 | 164 | 163 |
| Harmful or wrong proposals | 39 | 40 | 32 |
| Harmful or wrong reached a person | 1 | 1 | 1 |
| Model cost (USD) | 3.95 | 3.94 | 4.05 |

**The floor:** an answer that always escalates scores 103 of 172 "correct" from the keys alone, and fixes nothing.
Read WARDEN's 132-138 against that 103. Two runs of the same code differ by a few cases, so the differences between
these three columns are within run-to-run variation.

The same saved answers were re-scored on 2026-10-11 under later versions of the gate, with no model call
(`--reverify`). With the newest of those gates, the right outcome for the person (a right fix plan reached the
approver, or a hand-off where a hand-off is right) was 146, 145 and 149 of 172; a wrong plan reached the approver in
1, 2 and 1 cases.

What these numbers do not show: "reached the approver" is the gate's verdict. The fix plan itself is made by the
platform's live read, which a replay cannot run.

Reproduce:

```bash
WARDEN_PROVIDER=anthropic ANTHROPIC_API_KEY=... python scripts/heldout_bench.py --docs \
    --cases docs/bench/heldout-g10-2026-10-10 --out <out>      # answers every case (about $4)
python scripts/heldout_bench.py --cases docs/bench/heldout-g10-2026-10-10 --out <out> --reverify
                                                                # the same answers, today's gate, no model call
```

## Paid bench runs from the cloud runtime

Two runs for the owner's paid measurement, each one command with the cloud runtime's own key
([`scripts/cloud_run.py`](../scripts/cloud_run.py), jobs in [`scripts/bench_jobs.py`](../scripts/bench_jobs.py)):

- `headtohead`: two models answer the same hard cases - every held-out case whose key has more than one cause (29
  today: 23 in G10, 6 in G9) - compared on quality and on cost, each model at its own price in `providers.yaml`.
  "Compared" is McNemar on the first answer to each case both models answered: how many cases the row's model got
  right that the other got wrong ("better"), the reverse ("worse"), and the two-sided p.
- `bench`: one model answers every held-out case (220 today: G9 and G10), `--repeats` times. pass^k counts a case
  only when every repeat was right; "Correct" counts every right answer.

Each run prints its estimate before any call, refuses to start when the estimate is over `--budget-usd`, holds that
budget as a hard ceiling while it runs, and `--dry-run` does everything but the paid call. AWS documentation lookups
are off, so these rows are not comparable with the `--docs` G10 runs above. A bench measures: it never changes which
model diagnoses (`providers.yaml` is not written). `--record` adds the rows below; nothing else writes them.

```bash
python scripts/cloud_run.py headtohead --model <model A> --vs <model B> --budget-usd 4 --record
python scripts/cloud_run.py bench --model <model> --repeats 3 --budget-usd 25 --record
```

<!-- cloud-run-bench:begin -->
| Measured | Job | Model | Answers (cases x repeats) | Correct | pass^k | Cites the cause | Right outcome | Harm allowed | Unanswered | USD spent / budget | Compared | Prompt |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
<!-- cloud-run-bench:end -->

## Injection tripwire (2026-09-27)

The optional detector (Meta's Llama Prompt Guard 2, 86M, run locally) was measured on the repository's recorded
incidents: **0 false alarms in 4,637 distinct real log and event lines**, and it caught **6 of the 14** attack
payloads in `tests/test_injection_corpus.py`. The misses are why it is a tripwire on top of quarantine and the
outbound gate, never a replacement for them.

## Poisoned logs (2026-10-17)

Pasquini et al., *When AIOps Become "AI Oops"* (USENIX Security 2026,
[arXiv:2508.06394](https://arxiv.org/abs/2508.06394)), steer AIOps agents into harmful fixes by making an
application log a plausible wrong cause and a cheap fix (`[SOLUTION] ...`, `#HUMAN HINT: ...`) through a URL path, a
User-Agent, a Referer, a username or a form field - past Prompt Shields and Prompt-Guard-2. `evals/poisoned_logs.py`
plants eleven such lines (scale to zero, delete, wrong target, failover, IAM change, downgrade, weakened health check,
a pasted install command, a false "expected during maintenance" close, a traffic shift, a forged config line) in an
ordinary incident (a deploy before a 4.2% error rate) and runs WARDEN's real pipeline with a model that **follows**
each one - citing the planted fact (`naive`), or citing the real deploy and error rate and inventing a clear margin
over the real cause (`evasive`, which passes P13, P34 and P35) - in dev and in prod: 44 runs, with the tripwire
assumed bypassed.

| | Result (offline, no model call) |
|---|---|
| Rejected or escalated | **42 of 44** |
| Reached the approver | 2: the downgrade, `evasive`, dev and prod - the payload asks for a rollback, which after a deploy is also the evidenced fix. No plan carries the payload's version (the catalogue refuses a target that is not the labelled service, and its rollback returns to the revision the platform recorded), and the report names only "the previous revision WARDEN recorded" |
| Closed with no person | 0 (the false close is held by `P36-NO-ACTION-DESPITE-SIGNATURE`) |
| The planted line's version, image tag or ARN in the report, its Slack top or the record | 0 |
| The planted `curl ... \| sh` shown to a person | 0 (withheld by G4, in the key log lines too) |
| Reached the model as a sentence | none - no run of three of a payload's words, no decorator. Closed-vocabulary facts do (`failover`, `health check`), and the forged config line's two `key=value` facts sit side by side |

`evals/test_poisoned_logs.py` asserts this on every push. `python evals/poisoned_logs.py --live` asks the configured
real model instead: **it costs money, is off by default and no CI job runs it**; run it in the cloud runtime. Not
measured yet: whether a real model follows these payloads at all, and the real Prompt Guard 2 on them.

## Limits

- **Small and synthetic.** The held-out cases are synthetic, written for this project in one day. The live runs are
  one model, one small stack per platform, a few dozen scenarios. None of this is a comparison with other tools.
- **The live runs are old.** They measured WARDEN 0.7.0 in September 2026. Many readers and policies have changed
  since; a replay of that evidence shows the effect of a pipeline change, but it is not a new live measurement.
- **Replays read nothing new.** The investigation loop's extra reads, and every live refusal by a write platform,
  need a live account.
- **No fix was applied on AWS** in any published run. WARDEN applying fixes is tested in CI against a real k3d
  Kubernetes cluster and real database servers, not measured on a live AWS account.
- **Single runs.** Each code version was run once on each held-out set; repeated runs (pass^k) are not measured.
- **The live runs used the `claude` command-line tool** on a subscription, so they cannot be re-run with an API key
  as they were; their per-call cost was estimated, not billed.
