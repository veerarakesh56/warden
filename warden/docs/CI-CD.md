# WARDEN's CI/CD

WARDEN's pipeline steps are its composite actions, [`warden/.github/actions/`](../.github/actions); GitHub runs
them from the root workflows below (the only place it runs workflows from). The repository-wide picture, and how a
change reaches dev and then prod, is in [docs/REPO-LAYOUT.md](../../docs/REPO-LAYOUT.md).

| Before (until 2026-10-21) | Now | Jobs (check-run names unchanged) | Its steps |
|---|---|---|---|
| `ci-tool.yml` | [`warden-ci.yml`](../../.github/workflows/warden-ci.yml) "CI · tool" | `security`, `check`, `docker`, `k8s-regression (k3d, every push; measured on EKS in tests/fixtures/bench)`, `db`, `terraform` | `security`, `check`, `docker`, `k8s-regression`, `db`; `terraform` runs infra's `terraform-root` |
| `runtime.yml` | [`warden-runtime-deploy.yml`](../../.github/workflows/warden-runtime-deploy.yml) "Runtime · ops" | `ci-check`, `ci-security` (new: CI first), `image`, `deploy`, `restart` | `check`, `security`, `runtime-image-build`, `runtime-image-publish`, `runtime-tools`, `runtime-deploy`, `runtime-restart` |
| `mirror-images.yml` | [`warden-mirror-images.yml`](../../.github/workflows/warden-mirror-images.yml) "Mirror · base images" | `mirror` | `mirror-images` |

## CI · tool

On every pull request into `main` that is ready for review, and every push to `main`, for every path except what
the other pipelines own (the demo app, the demo stack's Terraform, Helm values, Helios and their workflows): lint
(`ruff` over WARDEN and the Python of the other components), nothing unpublishable tracked, the unit tests (a skip
fails the job), the eval gate, the demo's verdicts, both images built from `warden/` and asserted on what they do,
WARDEN against a real k3d cluster and real databases, and the root stack's Terraform. No credentials.

## Runtime · ops (WARDEN's own runtime)

By hand, from the branch `dev` only, into the GitHub Environment `ops` (its reviewer, role, image repository and
region). **CI first:** `ci-check` and `ci-security` run CI · tool's check and scans on the same commit, in the same
run; `image` and `restart` need both, `deploy` needs `image`. Then the image is built before any credential is held,
at a commit promoted onto `dev` from `main`, pushed by the commit's SHA, signed with cosign (this workflow's identity:
`.github/workflows/warden-runtime-deploy.yml@refs/heads/dev`) and given build provenance; the deploy verifies both
before it plans `infra/terraform/runtime` with that digest. There is no prod runtime yet.

## How a change reaches the runtime

1. A pull request into `main`; CI · tool passes; it merges.
2. `main` is fast-forwarded onto `dev`.
3. Someone runs Runtime · ops on `dev` (`image`, then `plan` / `apply`); its CI jobs pass for that commit; the `ops`
   reviewer approves the job; the image is built, signed and deployed.
