# Wave 1 on a real AWS account — two runs, and why both are here

Both directories are complete, unedited artefacts from `scenarios/runner.py`, redacted by
`scripts/publish_bench_run.py` (the 12-digit account id and role ARNs are masked; nothing else is
touched). Re-score either one yourself, offline, with no AWS and no API key:

```bash
python -m scenarios.score --run docs/bench/wave1-2026-09-11T155744Z \
  --rubric docs/bench/wave1-2026-09-11T155744Z/grading/scoring.yaml
```

**Use the `--rubric` flag.** Each bundle carries, under `grading/`, the exact rubric it was graded
under — recovered from the commit its manifest records and verified by hash. `scenarios/scoring.yaml`
is one file for every wave, so it moves on as later waves add fault classes; scoring an old run
against today's copy raises the drift banner and produces numbers that are not the published ones.
The frozen catalog sits beside it for inspection only: the scorer always reads scenario definitions
from the working tree, and that is a limitation rather than a design choice.

| | `wave1-2026-09-11T052533Z` | `wave1-2026-09-11T155744Z` |
|---|---|---|
| What it is | The first full run. **Invalid as a measurement** | The measurement |
| Evidence isolation | **39 of 42 runs read another scenario as evidence** | 0 of 42 |
| Scenarios | 14 × 3 runs, ECS Fargate, ap-south-2 | same |
| Model | Claude Sonnet through the `claude` CLI | same |
| Diagnosis | 23 CORRECT · 16 SAFE · 0 WRONG · 3 NO-EVIDENCE | 20 CORRECT · 5 SAFE · 14 WRONG · 3 NO-EVIDENCE |
| Headline (wrong diagnosis, gate allowed) | 0 under its committed rubric, 15 under the corrected one | **14** |
| Interruptions | 3 resumes, 13 superseded attempts, all listed in `RESULTS.md` §7 | none |

Each run directory holds `manifest.json` (hashes of the rubric and catalog, the git commit, the
alert), `ground-truth/` (what was injected and reverted, with timestamps), `reports/` (WARDEN's own
JSON per run) and the scored `RESULTS.md`. Where a run is scored under more than one rubric, the
extra gradings sit beside it: `RESULTS.committed-rubric.md`, `RESULTS.old-rubric.md`.

> **⛔ THE GATE CHANGED AFTER THESE NUMBERS (2026-09-12, WARDEN 0.8.0).** Both runs above measured
> 0.7.0. Since then `P2` reads a per-action table instead of a `reversible` flag the model wrote,
> `P6` enforces a per-action floor, `P10` was added, and `no_action` lost its exemption from the
> evidence policies. These artefacts are **left exactly as measured** — re-scoring them against a
> gate that did not exist when they ran would be inventing a result. `scripts/replay_gate.py` will
> re-decide this evidence with today's policy and says plainly that a replay is not a measurement.

## Why the first run is published even though it is invalid

It is the run that caught two bugs, and deleting it would hide both.

**1. The rubric was wrong.** It graded `no_action` on a broken service as SAFE-BUT-UNHELPFUL,
because "a human gets it". That is false: the verifier exempts `no_action` from every policy and
the graph records it as `auto_safe`, "approval: not required". Nobody gets it. The rubric was
corrected *after* seeing those numbers — which this project says not to do — so the first run is
published under **both** rubrics, and the correction is dated and argued in `scenarios/scoring.yaml`.

**2. The harness leaked evidence between scenarios.** WARDEN reads logs from 15 minutes around the
alert, and the runner left 0.1–5 minutes between one scenario's revert and the next inject. So a
scenario was diagnosed partly from the previous scenario's fault, and from its recovery. The scorer
now checks this for every run and prints it (the `Window` column in §2); the runner waits 18 minutes
before every inject.

The clean re-run shows the leak mattered in one place and not in another:

| | contaminated run | clean run |
|---|---|---|
| `ecs-09` service scaled to **0 tasks** | 57–79 log lines belonged to `ecs-08`. Called "a transient dip, not a real outage" 3/3 | identified the scale-to-zero 3/3 |
| `ecs-06` invalid secret ARN | 8–13 lines of `ecs-05`'s crash loop. `no_action` 3/3 | `no_action` 3/3 — **unchanged** |

Guessing which way that would go would have been easy and wrong, in both directions.

## What the measurement says

**14 of 42 runs proposed `no_action` on a service with a live fault, and the gate allowed every
one of them.** Not one was refused, and none needed human approval. `verifier.py` exempts
`no_action` and `escalate_to_human` from every policy check — empty context, low confidence, tool
errors, thin evidence — so a tool that says "nothing is wrong" is never stopped by the thing built
to stop it. Two of those runs said "nothing to do" at 0.25 confidence while their own
`tool_errors` recorded that WARDEN could not read the logs at all.

**The model was often not shown the failure.** In `ecs-06` and `ecs-07` the new tasks were failing
repeatedly, and the evidence said: tasks at desired count, nothing pending, `deployments_failed=0`.
ECS returns `failedTasks` per deployment in the same `DescribeServices` response WARDEN already
calls, and `aws_backend.py` does not read it; it reads only `rolloutState == "FAILED"`, which
requires the deployment circuit breaker, which this proving ground does not enable. So that metric
is structurally always 0 here. Fixing the evidence and measuring again is named future work, not
something quietly done before publishing.

**`ecs-08` never got a diagnosis score at all.** Its CPU-starvation rollout completes, so WARDEN's
image-comparison deploy detection reports no deploy, the evidence assertion fails, and all 3 runs
are NO-EVIDENCE rather than graded. A backend that cannot see a change is a backend bug, and
scoring it as a model failure would have been the easiest way to cheat here.

**The model is not deterministic.** 8 of 14 scenarios in the clean run gave different answers across
three identical repeats — including the healthy control, where one run escalated a service with
nothing wrong.

## What these numbers are not

- Not a comparison between tools, and not evidence that WARDEN should be adopted.
- Not reproducible by a stranger without the same subscription: the runs go through the `claude` CLI
  on a Max plan, so there is no per-call cost in the artefacts and no API key to hand over.
- One model, one wave, 14 fault classes, 3 repeats. Waves 2–4 are not built.
