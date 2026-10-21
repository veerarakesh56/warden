# Repository layout

Since 2026-10-21 every component of this repository lives in a folder of its own, so that any of them can become a
repository of its own by moving its folder. Nothing was rewritten: every file was moved with `git mv` (its history
follows it: `git log --follow <path>`), then every path that named it was changed to its new place, and Helios joined
with its full history (`git subtree add`).

| Folder | What it holds |
|---|---|
| `warden/` | The WARDEN product: `src/` (the package), `tests/`, `evals/`, `conftest.py`, `pyproject.toml`, `uv.lock`, `.python-version`, both images (`Dockerfile`, `Dockerfile.runtime`, `.dockerignore`), `docker-compose.yml`, `Makefile`, WARDEN's own scripts (`scripts/`: safety pins, publishable check, package check, mutation check, provider qualification, replay, the SBOM, the tripwire bake, Datadog setup), its product docs (`docs/`: operations, runbook, failure modes, benchmarks, data retention, AI boundary, compliance, governance, the safety pins, the SBOM) and its README |
| `infra/` | `terraform/` (the root stack, `runtime/` with `modules/warden-runtime/` - WARDEN's runtime -, `fullstack/` - the demo stack -, `proving-ground/`, `undo-lab/`), `iam/`, `helm/` (Argo CD's values), the platform Kubernetes manifests (`k8s/`: WARDEN's namespace, read-only RBAC, the remediation RBAC, the in-cluster Job, `ci/`), the scripts that run them (`scripts/`: IAM rendering and checks, the kill switch, the boundary proof, sweeps, pause / resume, the Helios gate, the global-alarm forwarder) and `docs/AWS-SETUP.md` |
| `demo-app/` | The demo application on the cloud services: `app/` (the shop's container app), `lambdas/`, `sql/`, `manifests/shop/` (what Argo CD syncs), `k8s/shop-pipeline/` and `k8s/argocd/` (the shop's Argo CD application), `scripts/deploy_fullstack_apps.py` (the apps pipeline) and `docs/FULLSTACK-LAB.md` |
| `fault-lab/` | The fault harness (`scenarios/`: runner, catalogues, ops, scoring, the alert templates, `SCORING.md`), the bench and live-proof scripts (`scripts/`: held-out bench, bench reports and publishing, preflights, the negative Pod Security pod, the cluster probe, the AWS proof, the undo lab's faults, the proving-ground database), its manifests (`k8s/proving-ground/`, `k8s/test/`) and the published held-out sets (`docs/bench/`) |
| `helios/` | Helios, with its full history: its Rust crates, `helios-ai`, the web viewer, its Action, fixtures and docs |
| `docs/` | Only what spans components: `ARCHITECTURE.md`, `DESIGN-DECISIONS.md`, `SYSTEM-COMPONENTS.md`, `PRODUCTION-ARCHITECTURE.md`, `ROADMAP.md`, `ENGINEERING-NOTES.md`, `SETUP.md`, `diagrams/` and this file |
| root | `README.md` (a map), `LICENSE`, `NOTICE`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `.github/`, `.coderabbit.yaml`, `.sonarcloud.properties`, `.gitignore`, `.gitattributes` |

`warden/` also carries a copy of `LICENSE` and `NOTICE`: the package names both as its licence files, and a build
reads them from the project's own folder only. Each of `infra/`, `demo-app/` and `fault-lab/` carries a `ruff.toml`
with WARDEN's lint settings, so its Python is linted the same way from any folder.

## Pipelines

GitHub runs workflows only from the root `.github/workflows`, and a reusable workflow must live there too. So each
component keeps its real CI/CD steps in its own composite actions, `<component>/.github/actions/<step>/action.yml`,
and the root holds thin workflows, one per pipeline, named by component, that call them
(`uses: $/<component>/.github/actions/<step>`, GitHub's self-repository syntax, as `main` already used for its
reusable workflows). A thin workflow keeps only what must stay at the root: the triggers
and their `paths`, the jobs and their permissions, environments and services, the guards that run before the
checkout, and the steps that read an environment's secrets or variables (a composite action cannot).

| Before | After | Component | What it does |
|---|---|---|---|
| `ci-tool.yml` (CI · tool) | `warden-ci.yml` (CI · tool) | warden | lint, unit tests, evals, both images, k3d, real databases, the root stack's terraform |
| `runtime.yml` (Runtime · ops) | `warden-runtime-deploy.yml` (Runtime · ops) | warden | WARDEN's runtime: CI first, then image, sign, attest, plan / apply |
| `mirror-images.yml` | `warden-mirror-images.yml` | warden | base images into this repository's registry |
| `ci-infra.yml` (CI · infra) | `infra-ci.yml` (CI · infra) | infra | the stacks' validation and tests, and the Helios gate on Helios built from `helios/` |
| `_infra-validate.yml` | `infra-validate.yml` | infra | reusable: fmt, validate, the infra tests |
| `_infra-deploy.yml` | `infra-deploy.yml` | infra | reusable: plan / apply / apply-plan / destroy / pause / resume one stack in one environment |
| `ci-apps.yml` (CI · apps) | `demo-app-ci.yml` (CI · apps) | demo-app | the apps' checks |
| `_apps-check.yml` | `demo-app-check.yml` | demo-app | reusable: lint, scans, tests, every artifact built |
| `_apps-deploy.yml` | `demo-app-deploy.yml` | demo-app | reusable: deploy the apps of one environment onto its own stack |
| - | `fault-lab-ci.yml` (CI · fault-lab) | fault-lab | lint, bandit and every test of the harness and the bench |
| `helios`'s own `ci.yml` | `helios-ci.yml` (CI · helios) | helios | Helios's own checks, as in its former repository |
| `deploy-dev.yml`, `deploy-prod.yml`, `on-merge-dev.yml`, `on-merge-prod.yml` | the same names | shared | each environment's deploys: infra and apps together, one queue per environment |
| `scan-workflows.yml` (Scan · workflows), `security-review.yml` | the same names | shared | zizmor over every workflow and composite action; the optional security review |

Every workflow kept its `name:` and every job its id and name, so every check run keeps its name: the one check a
ruleset requires (`zizmor`, on `dev` and `prod`) and the ones the merge checklist names (CI · tool, CI · infra,
CI · apps, Scan · workflows). Every pin, permission, concurrency group and the draft rule (a draft pull request runs
no CI) stayed as it was.

`paths`: each component's CI runs on its own folder plus the files outside it that its jobs read (the lock, the tests
of its rules in `warden/tests`, the WARDEN modules its scripts import). CI · tool keeps running on everything except
what the other pipelines own - as before the split, because WARDEN's tests also hold `infra/` and `fault-lab/` to
their rules. Scan · workflows has no path filter at all.

## How a change reaches dev, then prod

1. **A pull request into `main`.** CI runs for the paths it touches: CI · tool, CI · infra, CI · apps, CI ·
   fault-lab, CI · helios, and always Scan · workflows. `main` deploys nothing.
2. **`main` to `dev`.** `dev` is `main` fast-forwarded. The push to `dev` runs `on-merge-dev.yml`, which works out
   what changed and, in the same run, for the same commit:
   - apps changed (`demo-app/app`, `demo-app/lambdas`, manifests, k8s, Helm values): `demo-app-check.yml` (the CI ·
     apps checks) first, then `demo-app-deploy.yml` into the GitHub Environment `dev` - only if the check passed;
   - infra changed (`infra/terraform/fullstack`): `infra-validate.yml` first, then a plan (`infra-deploy.yml`, Helios
     on it), kept in dev's state bucket; the apply is a second, reviewed step (`deploy-dev.yml`, `apply-plan`, that
     run id and sha256), which runs `infra-validate.yml` again first.
   Every deploy job also checks that the commit came from `main` (the promotion check) before it holds a credential,
   and refuses to run from any branch but `dev`.
3. **`dev` to `prod`.** A pull request from `dev` into `prod`, merged with a merge commit that changes nothing of its
   own. `on-merge-prod.yml` then does what step 2 did, into the GitHub Environment `prod`, whose required reviewer
   approves each job; the promotion check accepts only commits from `dev`.
4. **WARDEN's own runtime** (`ops`, from `dev` only): `warden-runtime-deploy.yml` by hand. Its `ci-check` and
   `ci-security` jobs (CI · tool's check and scans) run first for that commit; the image, plan, apply, restart, pause
   and resume run only after both pass, then wait for the `ops` environment's reviewer.

Each environment's deploy uses only its own GitHub Environment - its role (`AWS_ROLE_ARN`), region (`AWS_REGION`),
state bucket (`TF_STATE_BUCKET`) and cluster access - and the apps pipeline refuses a `stack.json` of any other
environment (`demo-app/scripts/deploy_fullstack_apps.py`, `WARDEN_ENV`). There is no manual path that skips the
checks: `deploy-<env>.yml` by hand runs the same check jobs first.

## Moving a component to its own repository

1. `git subtree split --prefix=<component> -b <component>-only` gives the folder's history as a branch; push it to
   the new repository.
2. Move the component's root workflows with it, into the new repository's `.github/workflows/`:
   - `warden`: `warden-ci.yml`, `warden-runtime-deploy.yml`, `warden-mirror-images.yml`;
   - `infra`: `infra-ci.yml`, `infra-validate.yml`, `infra-deploy.yml` (and the infra half of `deploy-<env>.yml` /
     `on-merge-<env>.yml`);
   - `demo-app`: `demo-app-ci.yml`, `demo-app-check.yml`, `demo-app-deploy.yml` (and the apps half of the
     per-environment files);
   - `fault-lab`: `fault-lab-ci.yml`;
   - `helios`: `helios-ci.yml`.
   Copy `scan-workflows.yml` (and `security-review.yml` if wanted) into each.
3. In those workflows, `uses: $/<component>/.github/actions/<step>` becomes `uses: $/.github/actions/<step>`; drop
   the `<component>/` prefix from `paths`, `working-directory` and every path in the actions' steps.
4. What crosses components today, and must become a dependency or a copy when they part:
   - the tests of `infra/`, `demo-app/` and `fault-lab/` live in `warden/tests` (they import WARDEN's package and its
     fixtures), and those pipelines run them from there;
   - `demo-app`, `infra` and `fault-lab` install their Python tools from `warden/pyproject.toml` / `warden/uv.lock`
     (the `apps-check`, `apps-deploy`, `infra-deploy` and `scan` groups);
   - `infra/scripts/helios_gate.py` builds Helios from `helios/`; `infra/terraform/*` read
     `warden/src/warden/data/environments.yaml`; the apps pipeline and the Helios gate import `warden.paths`;
   - the IAM roles' trust names the workflow files (`infra/iam/templates/*trust.json`, `job_workflow_ref`): a new
     repository is a new trust.
