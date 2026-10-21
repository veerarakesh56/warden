# fault-lab

The fault harness and the bench: how WARDEN is measured. One of the five components of this repository
([layout](../docs/REPO-LAYOUT.md)).

| Path | What it is |
|---|---|
| [`scenarios/`](scenarios) | The harness (`runner.py`, the fault ops per platform, `score.py`), the fault catalogues, the alert templates and [how runs are scored](scenarios/SCORING.md) |
| [`scripts/`](scripts) | The held-out bench, posting and publishing bench runs, the preflights, the negative Pod Security pod, the cluster probe, the AWS proof, the undo lab's faults, the proving ground's database |
| [`k8s/`](k8s) | `proving-ground/` (the Kubernetes proving ground) and `test/` (the k3d job's OOM workload and posture probe) |
| [`docs/bench/`](docs/bench) | The published held-out incident sets |
| [`docs/CI-CD.md`](docs/CI-CD.md) | Its pipeline |

The harness imports WARDEN (`warden/src`); its tests are WARDEN's (`warden/tests`), which put `fault-lab/` on their
path (`warden/pyproject.toml`).
