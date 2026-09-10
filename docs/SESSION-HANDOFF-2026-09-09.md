# Session handoff — 2026-09-09

> ⚠ **Partly superseded on 2026-09-10.** This file is left as the record of what was true on the
> 9th rather than edited to pretend otherwise. Three things below have since changed:
>
> - **§4 "`scenarios/runner.py` — not written"** is out of date. `runner.py`, `score.py` and their
>   tests exist, and a `--dry-run` executes the whole wave offline. A run against a real AWS account
>   still has not happened.
> - **§4 says to write ground truth to `scenarios/ground-truth/`. Do not.** Ground truth records
>   real task-definition ARNs, and an ARN contains the 12-digit account id — the exact leak
>   `scripts/check_publishable.py` exists to catch. Runs write to `~/warden-bench-runs/` instead.
> - **§5's second "false claim" was overstated.** `evals/test_evals.py` said a real deployment
>   *"adds"* a nightly live-model eval — aspirational, not a claim that one existed. It has been
>   reworded to be unmissable anyway. The `knowledge.py` claim in §5 was real, and is now fixed.

Written for whoever picks this up next, human or model, with **no prior context**. Everything below
was verified in this session; where something is unverified it says so.

Repo state at handoff: **`6b62a55` on `main`, pushed, CI green on all five jobs**
(`check`, `docker`, `k8s` against a real k3d cluster, `db` against five real engines, `terraform`).
**509 tests** (484 in `tests/`, 25 in `evals/`), ruff clean, both Terraform root modules validate.

⚠ The working folder was renamed `C:\work\aegis` → `C:\work\warden` today. The **venv did not
survive the move** — Windows console-script `.exe` shims embed an absolute path to `python.exe`, so
`pytest.exe` exited **0 with no output**. It was rebuilt. If you move this folder again, rebuild
`.venv` rather than trusting it.

---

## 1. What was built this session

A **fault-injection benchmark**: inject real faults into a real AWS account, run WARDEN against
them, and score what came back. Wave 1 (14 ECS scenarios) is defined; **nothing has run against a
live AWS account yet** because no credentials exist on the machine.

| Added | What it is |
|---|---|
| `src/warden/aws_backend.py` | Live ECS + CloudWatch reads. Four API calls, no more |
| `terraform/proving-ground/` | A throwaway VPC + ECS (+ optional RDS, EKS) to break on purpose |
| `scenarios/` | The catalog, the rubric, and the injector |
| `scripts/aws_proof.sh`, `aws_proof_bundle.py` | Run it end to end, redact, tear down |
| `scripts/check_publishable.py` | Refuse to publish anything that must not leave the machine |
| CLI `--service --started-at --label --json` | Point a bundled incident at a real system |

## 2. The design rule that everything else serves

⭐ **The headline of this benchmark is the FAILURES, not the accuracy.**

Three scores are produced per scenario and reported **separately, never combined**:

1. **Evidence** — deterministic, no model. Did the backend read what a real operator would see?
   If this fails, the diagnosis score is meaningless and is reported `NO-EVIDENCE`, never as a
   model failure. Blaming the model for a backend bug is the easiest way to cheat here.
2. **Diagnosis** — the model. Graded against `scenarios/scoring.yaml`, four outcomes:
   `CORRECT` / `SAFE-BUT-UNHELPFUL` / `WRONG` / `HARMFUL`.
3. **Gate** — deterministic, and **this is the product**. A 2×2 of {diagnosis right, wrong} ×
   {gate allowed, refused}. **The number that matters is "diagnosis wrong AND gate allowed."**

⛔ **A perfect score is a bug report, not an achievement.** If everything passes, the scenarios are
too easy or the rubric is too generous, and that must be investigated before anything is published.
`scenarios/SCORING.md` says so in writing.

## 3. ⛔ Rules that must not be relaxed

These exist because the benchmark has to survive a hostile reader asking *"you wrote the bug and the
answer, so of course it passes."* Each is enforced by a test, not by good intentions.

| Rule | Enforced by |
|---|---|
| No scenario id or fault-class name may appear under `src/warden/` | `tests/test_no_scenario_leakage.py` |
| Nothing in `src/warden/` may reference the ground truth | same |
| `scenarios/ops.py` must never import `warden` | `tests/test_scenario_ops.py`, on the AST |
| The injector refuses any resource not tagged `Project=warden-proving-ground` | `tests/test_scenario_ops.py`, each guard given a case it must refuse |
| The catalog carries no expected hypothesis, action or verdict | `tests/test_no_scenario_leakage.py` |
| Every scenario declares `fidelity: real \| approximated`, and an approximated one says how it differs | same |
| The rubric is committed **before** the run it grades | git history is the evidence |

⭐ **Both tripwires were verified by planting a violation and watching them go red.** A guard that
has only seen valid input has not been tested. If you add one, do the same.

⭐ **WARDEN must run under the four-permission reader role** (`terraform/proving-ground/iam.tf`),
assumed by the harness. Running it with operator credentials makes scenario `ecs-11` measure nothing
while appearing to pass — that defect was found and fixed today, and it would have been published.

## 4. What is NOT done

| | Status |
|---|---|
| `scenarios/runner.py` | ⭕ **Not written. No wave can execute.** This is the next thing to build |
| `scenarios/score.py` | ⭕ Not written |
| A run against real AWS | ⭕ **Never happened.** No credentials on this machine |
| Waves 2–4 (EKS, RDS, Lambda/ALB/S3/SQS/IAM) | ⭕ 36 more scenarios, designed only as a list |
| GitHub Actions + OIDC for the benchmark | ⭕ Not started |
| Slack wiring into the runner | ⭕ The sink itself works and is socket-tested; nothing calls it yet |

### The runner, when you write it

Inject → wait `settle_seconds` → run WARDEN as a **subprocess** with a pinned env allowlist
(`WARDEN_BACKEND`, `WARDEN_AWS_CLUSTER`, `--service`, `--started-at now`) → capture the JSON →
revert. Write ground truth to `scenarios/ground-truth/`, which `src/warden/` may never read.
Assume the reader role first and record the assumed-role ARN in the bundle.

## 5. ⛔ Two false claims currently live in this public repo

Fix these before publishing anything about the project. A reader finds them in ten minutes.

1. **`src/warden/knowledge.py:7-9`** claims the 34 incident signatures are *"folded into the
   reasoning prompt."* **They are not.** `graph.py` and `llm.py` never import `knowledge`; it is
   matched once in `cli.py:105` *after* the graph finishes, purely to decorate the report.
   ⭐ **Fix by implementing it behind an off-by-default flag** (`WARDEN_KNOWLEDGE_IN_PROMPT=1`),
   not by deleting the sentence — that turns the repo's most cheating-looking feature into the
   benchmark's best experiment: run every scenario with the catalog on and off, publish the delta,
   split by each scenario's `signature_covered` flag.
2. **`evals/test_evals.py:9-11`** references a *"nightly scored eval against the live model."*
   No such job exists; all 25 eval tests are mock-model. This benchmark is meant to become it.

## 6. Cost model

**RDS and EKS default to `false`.** That is the single most effective control, because the risk is
not the hourly rate — it is forgetting. An idle EKS control plane is ~$73/month.

| Configuration | Per hour |
|---|---|
| Default (Wave 1: ECS only) | **~$0.009** |
| + `enable_rds` | ~$0.030 |
| + `enable_eks` | ~$0.119 |

No NAT Gateway, deliberately — it would cost more than everything else combined, and it is the usual
source of a surprise bill. Everything sits in public subnets bounded by `var.my_ip_cidr`; that is a
cost decision, not a recommendation, and the README says so.

Guards: a `$5` AWS Budget alarming on **forecast** as well as actual · every resource tagged
`Project=warden-proving-ground` · `terraform destroy` from an **EXIT trap** so it runs even on
failure or Ctrl-C · a post-destroy tag sweep whose result is written to `teardown-remaining.txt`,
because **a destroy can report success and leave a node group behind**.

## 7. Landmines found the hard way

- ⛔ **`python -m pytest` is not `pytest`.** The first puts the working directory on `sys.path`;
  the second does not, and CI runs the second. 509 tests passed locally and CI died on
  `ModuleNotFoundError`. **Verify with the command CI runs.** (Fixed via `pythonpath` in
  `pyproject.toml`.)
- ⛔ **GitHub push protection blocked a push** on a fabricated Slack token in this repo's own
  scanner fixtures — in a file the scanner had allowlisted. The fix was to assemble those fixtures
  at runtime so no credential literal exists in the source, then **remove the allowlist entry**.
  ⛔ Do not click "allow the secret" on a push-protection block.
- ⛔ **A Windows console defaults to cp1252** and cannot encode `⛔`/`⭐`. A script that prints
  findings will crash *while reporting them* — i.e. exactly when it matters. `check_publishable.py`
  forces UTF-8 on stdout for this reason.
- ⛔ **`.terraform.lock.hcl` contains SHA256 hashes with runs of 12 digits**, which a naive
  account-id regex flags. The boundary must be `\w`, not `\d`.
- ⛔ **A guard that passes against a fake proves the request was made, not that the outcome was
  right.** (From an earlier session: a `resourceVersion` precondition passed every unit test and was
  rejected by a live k3d cluster.)

## 8. How to verify the repo right now

```bash
.venv/Scripts/pytest.exe tests -q        # 484 passed  - note: NOT `python -m pytest`
.venv/Scripts/pytest.exe evals -q        # 25 passed
.venv/Scripts/ruff.exe check src tests evals scripts scenarios
python scripts/check_publishable.py      # what is REALLY tracked by git, not what you meant
terraform -chdir=terraform fmt -check -recursive
terraform -chdir=terraform/proving-ground validate
```

`check_publishable.py` also takes `--staged` (before a commit) and `--dir PATH` (a proof bundle
before it is copied in). ⚠ It scans the **working tree, not git history** — a secret committed and
later removed is still in the repository, and only rotation plus a history rewrite fixes that.

## 9. Before running against a real account

1. AWS CLI + credentials. A **scoped IAM user, never root** — the harness can create and delete
   infrastructure, and whatever you authenticate as is what it can reach.
2. `cp terraform/proving-ground/terraform.tfvars.example terraform.tfvars`, then set your public IP
   (`curl -s https://checkip.amazonaws.com`) and an email for the budget alarm.
   ⛔ `terraform.tfvars` and `terraform.tfstate` are gitignored and `check_publishable.py` fails the
   build if either is ever tracked — **tfstate holds every `sensitive` value in plaintext.**
3. A model key. Free tiers are fine and two models are better than one: running the same scenarios
   on two providers lets you show that the diagnosis changed and the gate did not.
   ⛔ **The model must be called through `LLMClient`.** An agent hand-writing diagnoses while
   holding the scenario definition is not a measurement — it already knows the answer.
