# infra

Every Terraform stack, the IAM policies, the Helm values and the platform Kubernetes manifests, and the scripts that
run them. One of the five components of this repository ([layout](../docs/REPO-LAYOUT.md)).

| Path | What it is |
|---|---|
| [`terraform/`](terraform/README.md) | The root stack; [`runtime/`](terraform/runtime) with [`modules/warden-runtime/`](terraform/modules/warden-runtime) (WARDEN's own runtime); [`fullstack/`](terraform/fullstack/README.md) (the demo stack the demo app runs on); [`proving-ground/`](terraform/proving-ground/README.md); [`undo-lab/`](terraform/undo-lab) |
| [`iam/`](iam) | The per-environment roles and boundaries, rendered from `iam/templates` by `scripts/render_env_iam.py` |
| [`helm/`](helm) | Argo CD's values for the demo cluster |
| [`k8s/`](k8s) | WARDEN's namespace, its read-only RBAC, the remediation RBAC, the in-cluster Job, and `ci/` (the k3d job's binding) |
| [`scripts/`](scripts) | IAM rendering and live checks, the kill switch, the boundary proof, the account and teardown sweeps, pause / resume, the Helios plan gate, the global-alarm forwarder |
| [`docs/`](docs) | [AWS setup](docs/AWS-SETUP.md) and [CI/CD](docs/CI-CD.md) |

Deploys run only through the pipelines ([CI/CD](docs/CI-CD.md)); every path in a command here is written from the
repository root, e.g. `terraform -chdir=infra/terraform/fullstack plan`.
