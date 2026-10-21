# fault-lab's CI/CD

fault-lab's pipeline step is its composite action, [`fault-lab/.github/actions/check`](../.github/actions/check);
GitHub runs it from [`fault-lab-ci.yml`](../../.github/workflows/fault-lab-ci.yml) "CI · fault-lab" (new on
2026-10-21; job `fault-lab`). The repository-wide picture is in [docs/REPO-LAYOUT.md](../../docs/REPO-LAYOUT.md).

It runs on every change under `fault-lab/` and on a change of the lock: ruff and bandit over `fault-lab/scenarios`
and `fault-lab/scripts`, then every test in `warden/tests` that imports the harness (`scenarios`) or a fault-lab
script - found when the step runs, so a new one is never left out - and a skip fails it. No credentials. CI · tool
runs on these paths as well (WARDEN's suite covers the harness).

fault-lab deploys nothing. The bench and the live proofs run from an operator's machine (the laptop), against the
proving ground and the demo stack, never from CI; the k3d job of CI · tool applies `fault-lab/k8s/test` and runs
`fault-lab/scripts/negative_pod.py`.
