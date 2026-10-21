# demo-app's CI/CD

demo-app's pipeline steps are its composite actions, [`demo-app/.github/actions/`](../.github/actions); GitHub runs
them from the root workflows below. The repository-wide picture is in [docs/REPO-LAYOUT.md](../../docs/REPO-LAYOUT.md).

| Before (until 2026-10-21) | Now | Jobs | Its steps |
|---|---|---|---|
| `ci-apps.yml` | [`demo-app-ci.yml`](../../.github/workflows/demo-app-ci.yml) "CI · apps" | `check` (calls `demo-app-check.yml`) | - |
| `_apps-check.yml` | [`demo-app-check.yml`](../../.github/workflows/demo-app-check.yml) "_ apps · check" | `check` | `check` |
| `_apps-deploy.yml` | [`demo-app-deploy.yml`](../../.github/workflows/demo-app-deploy.yml) "_ apps · deploy" | `deploy` | `deploy-prepare`, `deploy-run` |

- **CI · apps** runs on every change under `demo-app/`, Argo CD's Helm values, the tests of the apps, the lock, and
  weekly: lint, the deployed requirements' known vulnerabilities, bandit, the tests, every artifact built (Lambda
  zips and the image) and the shop rendered (what Argo CD syncs and what the pipeline applies). No credentials.
- **_ apps · deploy** deploys `lambdas`, `ecs`, `k8s` or `all` to ONE environment: the GitHub Environment named for
  it holds its role, region, state bucket and cluster access, `stack.json` comes from that environment's state
  bucket, and `demo-app/scripts/deploy_fullstack_apps.py` refuses a `stack.json` of any other environment
  (`WARDEN_ENV`; `warden/tests/test_deploy_env_isolation.py`). The Argo CD application syncs
  `demo-app/manifests/shop/<env>` at the commit just deployed.

## CI first, per environment

`deploy-<env>.yml` (by hand) and `on-merge-<env>.yml` (on a push to the branch `<env>`) call `demo-app-check.yml`
first and `demo-app-deploy.yml` only when it passed (`needs:`), in the same run, on the same commit. A push that also
changes the demo stack's Terraform defers the apps until that plan is applied. `prod` waits for its environment's
reviewer. There is no deploy path without the check.
