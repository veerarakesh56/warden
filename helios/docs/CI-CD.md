# Helios's CI/CD

Helios joined WARDEN's repository on 2026-10-21 (`git subtree add`, full history). Its pipeline steps are its
composite actions, [`helios/.github/actions/`](../.github/actions), run from the root workflow
[`helios-ci.yml`](../../.github/workflows/helios-ci.yml) "CI · helios" - its former repository's `ci.yml`, with every
path under `helios/` and this repository's CI rules (a pinned runner image, uv pinned with its checksum, no CI on a
draft pull request). Jobs and their names are unchanged: `check / fmt / clippy / test`, `msrv / cargo check (Rust
1.88)`, `python / ruff / pytest`, `web / build / vitest`, `action / smoke (inspect + comment body)`, `action / as a
consumer repository uses it`.

WARDEN's plan gate uses Helios built from this folder: `infra-deploy.yml` builds it (`scripts/fetch_z3.py`, then
`cargo build --release --locked --bin helios`) before the deploy job holds any credential, and CI · infra's
`helios-gate` job runs the gate on real plans against that build. Helios deploys nothing.

To make it a repository of its own again: `git subtree split --prefix=helios`, move `helios-ci.yml` into its
`.github/workflows/` with `./helios/.github/actions/` -> `./.github/actions/` and the `helios/` prefixes dropped
([docs/REPO-LAYOUT.md](../../docs/REPO-LAYOUT.md#moving-a-component-to-its-own-repository)).
