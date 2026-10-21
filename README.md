# WARDEN

WARDEN is an AI on-call engineer for AWS: an alarm comes in, it reads the evidence, proposes one fix from a closed
list, deterministic rules check it, and nothing changes until that exact fix is approved. **The product and its full
description are in [`warden/`](warden/README.md).**

This repository holds five components, each in a folder of its own, so that any of them can later become a
repository of its own by moving its folder ([how](docs/REPO-LAYOUT.md#moving-a-component-to-its-own-repository)):

| Folder | What it is | Its pipelines |
|---|---|---|
| [`warden/`](warden/README.md) | The WARDEN product: the Python package (`src/`), its tests and evals, its two images, its own scripts and docs | [CI · tool](.github/workflows/warden-ci.yml), [Runtime · ops](.github/workflows/warden-runtime-deploy.yml), [Mirror · base images](.github/workflows/warden-mirror-images.yml) - [CI/CD](warden/docs/CI-CD.md) |
| [`infra/`](infra/README.md) | Every Terraform stack (WARDEN's runtime, the demo stack, the proving ground, the undo lab), IAM, Helm values, the platform Kubernetes manifests, and the scripts that run them | [CI · infra](.github/workflows/infra-ci.yml), [_ infra · validate](.github/workflows/infra-validate.yml), [_ infra · deploy](.github/workflows/infra-deploy.yml) - [CI/CD](infra/docs/CI-CD.md) |
| [`demo-app/`](demo-app/README.md) | The demo application that runs on the cloud services WARDEN watches: the shop's container app, its Lambdas, SQL, Kubernetes manifests and Argo CD application, and the apps pipeline's script | [CI · apps](.github/workflows/demo-app-ci.yml), [_ apps · check](.github/workflows/demo-app-check.yml), [_ apps · deploy](.github/workflows/demo-app-deploy.yml) - [CI/CD](demo-app/docs/CI-CD.md) |
| [`fault-lab/`](fault-lab/README.md) | The fault harness (`scenarios/`) and the bench: fault catalogues, scoring, preflights, the live proofs, the held-out sets | [CI · fault-lab](.github/workflows/fault-lab-ci.yml) - [CI/CD](fault-lab/docs/CI-CD.md) |
| [`helios/`](helios/README.md) | Helios, the deterministic infrastructure failure simulator WARDEN's plan gate runs on every Terraform plan (with its full history) | [CI · helios](.github/workflows/helios-ci.yml) - [CI/CD](helios/docs/CI-CD.md) |

Shared by all of them: [`docs/`](docs/REPO-LAYOUT.md) (the architecture, design decisions, setup and diagrams that span
components), the per-environment deploy pipelines ([deploy-dev](.github/workflows/deploy-dev.yml),
[deploy-prod](.github/workflows/deploy-prod.yml), [on-merge-dev](.github/workflows/on-merge-dev.yml),
[on-merge-prod](.github/workflows/on-merge-prod.yml)), the workflow scan
([Scan · workflows](.github/workflows/scan-workflows.yml)) and the optional security review
([Review · security](.github/workflows/security-review.yml)). How a change reaches dev, then prod:
[docs/REPO-LAYOUT.md](docs/REPO-LAYOUT.md#how-a-change-reaches-dev-then-prod).

Start here: [warden/README.md](warden/README.md) (what WARDEN does and how to run it),
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/SETUP.md](docs/SETUP.md).

[Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [Code of conduct](CODE_OF_CONDUCT.md) ·
[Changelog](CHANGELOG.md) · [Apache License 2.0](LICENSE) ([NOTICE](NOTICE))
