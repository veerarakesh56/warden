# Use case

Who WARDEN is for, what it must achieve, how that is measured, and what can go wrong. Every number below names its
file. Written 2026-10-21 from `main`.

## Problem

An alarm on an AWS service pages a person, who then spends the first part of the incident collecting the same
evidence by hand - logs, metrics, recent deploys, the resource's settings - before deciding on one small fix that is
often routine (re-enable a consumer, restart a service, raise a bounded limit). That is slow at night, and a tired
person under pressure can make the wrong change.

WARDEN does that first part: alarm -> read-only evidence -> a model proposes a cause and one fix from a closed catalogue
-> deterministic rules check it -> a report in Slack -> the fix is approved -> applied once -> verified -> undone if it
did not work, where the catalogue entry has an undo (otherwise, or if the undo fails, the run ends `not_recovered` or
`rollback_failed` and a person takes over) -> every step signed in an audit (README.md; docs/ARCHITECTURE.md). The model
never decides: the gate and a signed approval stand between any answer and any change
([ai-boundary.md](ai-boundary.md)).

It is a reference build, measured honestly, not a product to adopt as-is (README.md).

## Users

| Who | What they do with WARDEN | Where |
|---|---|---|
| The on-call engineer | reads the incident message, opens the record, approves or denies a plan with a passkey (prod), or says no to Eldane's approval (dev) | Slack alerts channel; the approval page; `https://<the approval domain>/r` |
| Approvers (the approver list) | decide T1/T2/T3 plans in their environments; reset the kill switch; re-enable dev autonomy after a demotion | approval page; `warden killswitch`, `warden autonomy` ([OPERATIONS.md](OPERATIONS.md)) |
| Anyone on the team | asks WARDEN about an incident in the discussion channel; WARDEN changes nothing from there | [OPERATIONS.md](OPERATIONS.md), "Talking to WARDEN about an incident in Slack" |
| Eldane, the AI critic | reviews every plan; in dev approves T1/T2 plans alone (L2), always labelled an AI; never acts in prod | `src/warden/eldane.py`, `src/warden/autonomy.py` |
| The operator (the owner) | deploys, pauses and resumes, rotates keys, runs the fault lab, and starts paid qualification (`providers.yaml`: in the cloud runtime) | [OPERATIONS.md](OPERATIONS.md), [SETUP.md](SETUP.md), [FULLSTACK-LAB.md](FULLSTACK-LAB.md) |

## Success criteria

**The written success number.** A model may diagnose in production only when, on the golden set, it gets **at least 17
of 30 incidents right (57%) with 0 wrong answers allowed by the gate**. In operation: **0 harmful fixes let through**,
and no more escalations than the level measured for the production model of the time, Claude Sonnet 5, on 2026-10-03
(**at most 25 of 30**, `providers.yaml` `slo`, register N6).

**The eval contract.**

| Part | What it is | Where |
|---|---|---|
| Golden set | the recorded evidence of the three published live runs: ECS (14 scenarios), EKS (10) and PostgreSQL (6) = 30 incidents, each run graded by its own rubric committed before it ran | `scripts/qualify_provider.py` (`RUNS`); `tests/fixtures/bench/wave1-2026-09-11T155744Z`, `wave2-2026-09-24T115746Z`, `wave3-2026-09-25T044307Z`; [scenarios/SCORING.md](../scenarios/SCORING.md) |
| Pass-rate threshold | `bar: {wrong_and_allowed: 0, min_correct: 17}` - 17 is what the quarantine arm measured on the same 30 in Phase 1. The qualification script also requires `unanswered: 0` before it passes a run; `providers.qualified()` checks only the bar on the recorded row | `src/warden/data/providers.yaml`; `scripts/qualify_provider.py` |
| Escalation SLO (beside the bar, not in it) | `slo: {max_escalated: 25, acted_wrongly: 0}` | `src/warden/data/providers.yaml` (register N6) |
| The gate | a model is used only if the `qualified` list in `providers.yaml` holds a row for that exact provider and model, measured on the pinned prompt (`prompt.sha`), meeting the bar (the script prints a row to add only for a run that passed, which needs every incident answered); otherwise it is refused and every incident gets the rules-only diagnosis, sent to a person | `src/warden/providers.py` `qualified()` (register M20); M19 |
| Prompt pin | changing the diagnosis prompt fails CI until a model is qualified again on it and the pin is updated in the same commit | `tests/test_prompt_pin_e6.py` (register E6) |
| Held-out check | 172 cases by independent authors; an answer that always escalates scores 103/172 "correct" - the floor | `docs/bench/heldout-g10-2026-10-10/`; [BENCHMARKS.md](BENCHMARKS.md) |

**Where it stands (from the files, 2026-10-21).** No model is qualified today. The one row left in `qualified` is
historical, Claude Sonnet 5.5: 17/30, 0 wrong and allowed, 24 escalated, measured 2026-10-15 14:56 UTC (20:26 IST) on an
earlier prompt (`d435b59f...`). Earlier rows for Claude Sonnet 5 and Claude Fable 5 / 5.1 were measured on older
prompts; the Sonnet 5 row was retired on 2026-10-15. Claude Opus 5.5 scored 15/30, below the bar. On the G10 held-out
set Sonnet 5.5 re-scored to 137 right outcomes and 0 harmful answers allowed (providers.yaml comments; BENCHMARKS.md).
The pinned prompt has since changed and is marked "NOT YET QUALIFIED", so **no model is qualified on it today and
production is rules-only** until a model is qualified again on it ([RUNBOOK.md](RUNBOOK.md#known-limitations)).

**Cost per incident** is in [COST.md](COST.md): $0.014 to $0.018 per incident on Claude Sonnet 5.5, measured on the
Claude API on an earlier prompt.

## Risks

| Risk | What holds it | Where |
|---|---|---|
| The model is confidently wrong | closed catalogue; the gate's policies check every answer against the evidence; a person or Eldane must approve; the fix is verified, and undone if it did not work where its catalogue entry has an undo | [ai-boundary.md](ai-boundary.md); [FAILURE-MODES.md](FAILURE-MODES.md) |
| Injected text in logs steers WARDEN | redaction, the tripwire (Prompt Guard 2), typed evidence; text never runs as a command | [FAILURE-MODES.md](FAILURE-MODES.md); [RUNBOOK-WARDEN-INCIDENT.md](RUNBOOK-WARDEN-INCIDENT.md) |
| Eldane shares blind spots with the diagnosing model (same family) | the other model per incident, a blind first pass, citations checked in code, catch trials, demotion to L1 at once, a person's "no" wins, never in prod | `src/warden/eldane.py`; `src/warden/autonomy.py` |
| Too many escalations make it useless | the escalation SLO is measured beside the bar (at most 25/30); lowering it is calibration's job (G7) | `src/warden/data/providers.yaml`; [BENCHMARKS.md](BENCHMARKS.md) |
| The golden set is small and was made by WARDEN's builders | 30 incidents, one model run per incident; two runs of one model differ by about 2; a held-out set by independent authors is the second check | providers.yaml comments; [BENCHMARKS.md](BENCHMARKS.md) |
| The record is rewritten | hash chain, KMS-signed checkpoints, S3 Object Lock anchors; `warden audit verify` | [FAILURE-MODES.md](FAILURE-MODES.md) S12, S17 |
| Model spend runs away | per-incident ceiling: in the cloud runtime 6 calls and $0.25 (`WARDEN_MAX_CALLS`, `WARDEN_MAX_USD`, `terraform/modules/warden-runtime/compute.tf`; the client default where unset is $0.50, `src/warden/llm.py`), and daily caps (`WARDEN_DAILY_MAX_USD` $10, `WARDEN_DAILY_MAX_TOKENS` 2,000,000 in `src/warden/activities.py`); over a cap, rules-only | [COST.md](COST.md) |
| The prompt changes without re-measurement | the prompt pin test; an unqualified prompt means rules-only, never an unmeasured model | `tests/test_prompt_pin_e6.py` |
| WARDEN itself is the incident | the kill switch, the runbook | [RUNBOOK-WARDEN-INCIDENT.md](RUNBOOK-WARDEN-INCIDENT.md) |
