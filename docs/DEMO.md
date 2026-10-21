# Demo: one small, reversible fix in dev

A 2-3 minute film of WARDEN fixing one real fault in the dev full-stack lab, from the alarm to the signed record. The
film is cut: the real run takes about 30-40 minutes, mostly waiting for an alarm and a safety window. Say so on screen
("cut: N minutes"). When AWS is off, use the [sample variant](#sample-variant-aws-off) instead.

Written 2026-10-21 from the code on `main`. Nothing here was filmed or run live for this page.

## Which fault, and why

**fs-07, the orders queue's consumer switched off** (`sqs_consumer_disabled`, docs/FULLSTACK-LAB.md section 5).

| Why this one | Where it is shown |
|---|---|
| The fix is T1: "single, reversible, bounded" - one setting on one resource | `src/warden/catalog.py`: `Entry("lambda_enable_esm", "T1", ...)`, its undo "the event source mapping's enabled state" |
| WARDEN's own undo exists: if the fix does not hold, the mapping is put back as it was | the same catalogue entry; `src/warden/workflows.py` rolls back a fix that did not recover |
| Dev may apply it: `resume_flow` is in dev's `allow_actions` | `src/warden/data/environments.yaml`, `dev:` |
| Eldane may approve it: an AI approver may approve T1 and T2 only | `src/warden/approvals.py`: `AI_TIERS = ("T1", "T2")` |
| No data is touched: orders wait in the queue and are processed once the consumer is back | `scenarios/ops_fullstack.py`: `fs07_inject` / `fs07_revert` change only `Enabled` on one mapping |
| The harness saves the exact prior state and puts it back | `fs07_inject` saves `{"uuid", "enabled"}` before its one write; `fs07_revert` restores it |
| It has run live on dev before (2026-10-15) and the gaps found were fixed | comments marked "fs-07, live, 2026-10-15" in `src/warden/resolver.py`, `src/warden/aws_stack.py`, `src/warden/verifier.py`, `src/warden/catalog.py`, `src/warden/activities.py` |

Rejected: fs-27 (rule disabled) is also T1, but its alarm needs a 10-minute window (`reconciler-invocations-low`,
`terraform/fullstack/alarms.tf`) and the fix shows only at the next 5-minute run. fs-09 (DynamoDB capacity) is T1
too, but its catalogue entry has no undo ("n/a (bounded increase)").

One honest note: the lab's rubric (`scenarios/scoring.yaml`, `sqs_consumer_disabled`) was written on 2026-09-26,
before the catalogue had `lambda_enable_esm`, and still grades `escalate_to_human` as the right answer. A benchmark
score for fs-07 would count this fix as not the rubric's. The demo shows the fix; it is not a benchmark result.

## Before filming (off camera)

1. **A model must be qualified on the pinned prompt, or there is no fix to film.** Today none is:
   `src/warden/data/providers.yaml` says the pinned prompt (`prompt.sha`) is "NOT YET QUALIFIED", so every incident
   gets the rules-only diagnosis and goes to a person with no plan (register M19, `src/warden/providers.py`
   `qualified()`). The laptop re-qualifies first ([USE-CASE.md](USE-CASE.md#success-criteria)). Check:

   ```bash
   python -c "from warden.providers import load_qualified as q; d=q(); print(any(isinstance(r, dict) and r.get('prompt') == d['prompt']['sha'] for r in d['qualified']))"
   ```

   `False` means: film the [sample variant](#sample-variant-aws-off), or film the rules-only escalation and say so.
2. The dev stack and WARDEN's runtime are up (resumed, not paused: [OPERATIONS.md](OPERATIONS.md), "Pause and
   resume"), the kill switch is off, and dev's autonomy is at L2:

   ```bash
   warden autonomy status --environment dev
   ```

   Any demotion listed means a person approves instead of Eldane (L1). Do not re-enable autonomy just for the film:
   read each demotion first (OPERATIONS.md, "Dev autonomy"). An L1 run films the same way, except a person approves
   with their passkey on the approval page.
3. A shell with the harness role's credentials (`iam/<env>/harness.json`, assumed from the read-only operator role:
   [SETUP.md](SETUP.md) section 3d) and the lab's files outside the repository:

   ```bash
   export WARDEN_ENV=dev                                   # the default: the first of fault_environments
   export WARDEN_FS_STACK=<path to the dev stack.json>     # `terraform output -json`, written by the infra pipeline
   export WARDEN_FS_RUN=<a new run directory outside the repository>
   ```

4. Soak, at least 30 minutes; `inject` refuses without it:

   ```bash
   python -m scenarios.fullstack_cli soak
   ```

5. Open, side by side: the terminal, dev's Slack alerts channel, and `https://<the approval domain>/r` signed in with
   Slack.

## The script

| Film time | Real time | On screen | What to click or say |
|---|---|---|---|
| 0:00-0:15 | - | Slack, the terminal, the records page | "One real fault, in dev, end to end. Nothing is mocked." |
| 0:15-0:30 | about 7-10 min (cut) | Terminal: the inject command below | Run it. It saves the mapping's state, turns it off, and waits for the alarm `warden-dev-orders-age` (oldest order over 300 s for 3 one-minute periods). Say "cut: about N minutes". |
| 0:30-1:00 | about 1-3 min after the alarm | Slack, dev's alerts channel | The one incident message: what is broken, the cause with its evidence, and the plan `lambda_enable_esm` on "event source mapping of warden-dev-order-processor" (T1). Beneath it: "Eldane · AI critic (an AI) approved WARDEN's plan ... WARDEN applies it after <time> unless a person denies it first". Point at the footer: incident id and `audit head`. |
| 1:00-1:30 | - | Click **Full record** | The record page: status, the evidence the model was shown, the findings section by section, the plan, Eldane's review, every step in UTC and IST. |
| 1:30-1:45 | 5 min (cut) | The approval page's buttons | "For five minutes - and until the apply starts - a person can say no with their passkey; a person always overrides Eldane." Do not click. Say "cut: 5 minutes". |
| 1:45-2:15 | about 2 min | Record page (refresh), then the terminal | The record shows the plan applied, then "Fixed - its health checks passed" after 3 healthy checks 30 s apart. Run the verify command below: `ESM Enabled, orders visible=<n>`. |
| 2:15-2:35 | up to 20 min (cut) | Terminal: the revert command below | "Undo": the harness puts back the exact state it saved (enabled), which is where WARDEN's fix already left it, and waits for the baseline. Had the fix not held, WARDEN would have undone it itself and said so. |
| 2:35-3:00 | - | Record page, top line; Slack footer | "Signed record: audit head `<hash>` - N row(s), N signed and intact". Show that the head is the same one the Slack footer names. |

The run stays open after "Fixed": WARDEN re-checks at 15 and 60 minutes (`RECHECK_AFTER`, `src/warden/workflows.py`)
and records "Fixed and held" or a relapse. A later re-check can be added to the film as a closing card.

### The exact commands

From the repository root, in the shell set up above (`scenarios/fullstack_cli.py`; docs/FULLSTACK-LAB.md section 6):

```bash
python -m scenarios.fullstack_cli inject fs-07     # save the mapping's state, disable it, wait for the alarm
python -m scenarios.fullstack_cli verify fs-07     # poll "fixed when": the mapping Enabled and the backlog under 20
python -m scenarios.fullstack_cli revert fs-07     # put the saved state back, wait for the baseline
python -m scenarios.fullstack_cli status           # every step of this run, and the stack's health now
```

Do not run `diagnose` or `fix` for the film: those run a local copy of WARDEN as the reader identity (a model call on
the laptop's provider) and record a benchmark outcome. In the film, the cloud runtime handles the alarm on its own
(the `warden-<env>-alarm-changes` rule, `terraform/modules/warden-runtime/frontdoor.tf`). After the last fault, the
lab's rules still apply: `python -m scenarios.fullstack_cli watch` (30 minutes) before anyone pauses or destroys the
stack.

### The signed audit

- **On camera:** the record page's first line is checked when the page opens (`src/warden/records.py`): the audit
  head, how many rows a signed checkpoint covers and are intact, and how many are not signed yet ("a checkpoint signs
  them shortly"). The Slack footer names the same head (register S17).
- **Off camera, by the book:** `warden audit verify` and `warden audit show <incident-id>` recompute every hash and
  check every signature and S3 anchor ([RUNBOOK-WARDEN-INCIDENT.md](RUNBOOK-WARDEN-INCIDENT.md) section 2). In the
  cloud they need `WARDEN_AUDIT_DSN`, and the audit database is reachable only from inside the runtime's VPC; no laptop
  step for that exists in the repository today. Do not claim the film shows an offline verification.

## Sample variant (AWS off)

Label every frame **"sample: recorded incidents, mock model, no AWS"**. Mock mode runs the whole pipeline on five
bundled incidents with no cloud account and no API key (README.md, "Quick start"; `src/warden/cli.py` `DEMO_ALERTS`):

```bash
WARDEN_MOCK=1 warden demo --verbose                     # all five, one block each (about 2 s here)
WARDEN_MOCK=1 warden run --incident inc-005 --verbose   # one: the gate's verdict and the step-by-step trail
WARDEN_MOCK=1 warden run --incident inc-005 --report    # the same, with the redacted report a person reads
```

| Film time | On screen | Say |
|---|---|---|
| 0:00-0:20 | the label | "Sample mode: recorded incidents, a mock model. Nothing touches AWS." |
| 0:20-1:10 | `warden demo --verbose` | Five incidents: three fixes held for a person's approval, one rejected by the gate (failover in prod), one that declines to invent a fix. |
| 1:10-2:10 | `warden run --incident inc-005 --report` | Masked identifiers, the evidence, the hypothesis, `terminate_connections` on `payments-db`, "approved for a person", the report. |
| 2:10-2:40 | the `audit trail` lines of `--verbose` | Each step as it is recorded: ingest, gather, redact, tripwire, diagnose (with the prompt and response hashes), verify, await approval. |
| 2:40-3:00 | the last line | "No action was executed": `warden run` never changes anything. |

What sample mode does not show, and must not be said to: no Slack message, no records page, no Eldane, no apply, no
undo, no signature (the `audit trail` lines are the run's steps, not the signed audit). The `cost` lines are the mock
client's estimate, not a real model's spend. Checked 2026-10-21 13:59 UTC (19:29 IST): `WARDEN_MOCK=1 warden demo --verbose` ran the
five incidents in about 2 seconds with those verdicts, and `run --incident inc-005 --report` printed the report.
