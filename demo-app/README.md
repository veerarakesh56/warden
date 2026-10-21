# demo-app

The demo application that runs on the cloud services WARDEN watches - the shop. One of the five components of this
repository ([layout](../docs/REPO-LAYOUT.md)); the stack it runs on is `infra/terraform/fullstack`.

| Path | What it is |
|---|---|
| [`app/`](app) | The shop's container app (catalog API and cart worker), with its Dockerfile and hashed requirements |
| [`lambdas/`](lambdas) | checkout, notifier, ops, order-processor, reconciler and traffic |
| [`sql/`](sql) | The database bootstrap |
| [`manifests/shop/`](manifests/shop) | The shop's Kubernetes workloads, synced by Argo CD per environment |
| [`k8s/`](k8s) | `shop-pipeline/` (what the pipeline owns: namespace, secret, endpoints) and `argocd/` (the shop's Argo CD application) |
| [`scripts/deploy_fullstack_apps.py`](scripts/deploy_fullstack_apps.py) | The apps pipeline: build and deploy lambdas, ecs, k8s |
| [`docs/`](docs) | [The full-stack lab](docs/FULLSTACK-LAB.md) and [CI/CD](docs/CI-CD.md) |

It deploys only through CI/CD, each environment onto its own stack ([CI/CD](docs/CI-CD.md)).
