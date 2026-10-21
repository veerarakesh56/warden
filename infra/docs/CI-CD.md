# infra's CI/CD

infra's pipeline steps are its composite actions, [`infra/.github/actions/`](../.github/actions); GitHub runs them
from the root workflows below. The repository-wide picture is in [docs/REPO-LAYOUT.md](../../docs/REPO-LAYOUT.md).

| Before (until 2026-10-21) | Now | Jobs | Its steps |
|---|---|---|---|
| `ci-infra.yml` | [`infra-ci.yml`](../../.github/workflows/infra-ci.yml) "CI · infra" | `check` (calls `infra-validate.yml`), `helios-gate` (new) | `validate`, `helios-gate` |
| `_infra-validate.yml` | [`infra-validate.yml`](../../.github/workflows/infra-validate.yml) "_ infra · validate" | `validate` | `validate` |
| `_infra-deploy.yml` | [`infra-deploy.yml`](../../.github/workflows/infra-deploy.yml) "_ infra · deploy" | `run` | `deploy-prepare`, `deploy-run` |
| (CI · tool's `terraform` job) | the same job, in `warden-ci.yml` | `terraform` | `terraform-root` |

- **CI · infra** runs on every change under `infra/`, the tests of infra's rules in `warden/tests`, the lock, and
  what Helios is built from: fmt and validate of every stack the pipelines deploy, the infra tests, and the plan gate
  (`infra/scripts/helios_gate.py`) against Helios built from `helios/` on real plans
  (`warden/tests/integration/test_helios_gate_live.py`, which must run, not skip).
- **_ infra · deploy** plans, applies (only a reviewed plan, `apply-plan`), destroys, pauses or resumes ONE stack
  (`fullstack` or `undo-lab`) in ONE environment, through that environment's GitHub Environment: its role
  (`AWS_ROLE_ARN`), region (`AWS_REGION`), state bucket (`TF_STATE_BUCKET`) and cluster access. Before it holds any
  credential it refuses a branch other than the environment's own, checks that the commit came from the upstream
  branch, installs the locked tools and builds Helios from `helios/`. Helios checks every plan and the applied state.
  The state keys do not depend on any folder: `fullstack/terraform.tfstate` and `runtime/terraform.tfstate`, one
  workspace per environment, exactly as before the move.

## CI first, per environment

`deploy-<env>.yml` (by hand) and `on-merge-<env>.yml` (on a push to the branch `<env>`) call `infra-validate.yml`
first and `infra-deploy.yml` only when it passed (`needs:`), in the same run, on the same commit. A push only plans;
the apply is `deploy-<env>.yml` with `apply-plan`, that plan's run id and sha256, which validates again first. `prod`
waits for its environment's reviewer.
