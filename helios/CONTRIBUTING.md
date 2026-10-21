# Contributing to Helios

Thanks for considering a contribution. Helios is a small project with a
deliberately small surface, so contributing is straightforward.

## Quick flow

1. Fork the repo.
2. Branch off `main`: `git checkout -b feat/<short-name>` or
   `fix/<short-name>`.
3. Make your change. Add tests.
4. `make check` (runs fmt + clippy + tests + Python checks + web build).
5. Open a PR against `main`. The CI workflow runs the full matrix
   (`check` + `python-check` + `web-check` + `action-smoke`).

## What "good" looks like

- Every new behavior has a test.
- New Rust code passes `cargo fmt --check` and `cargo clippy --workspace
  --all-targets -- -D warnings`.
- New Python code passes `ruff check helios-ai/` and has a `pytest` test.
- Public API changes (CLI subcommands, JSON shapes) update the matching
  doc under `docs/` in the same PR.

## Where to start

The easiest first PRs:

- **Add a new AWS resource type** to `crates/helios-models/`. Each kind is
  one branch of the `availability_for` match plus a fixture and a test.
- **Add a new scenario kind** to `crates/helios-engine/src/scenario.rs`.
  See `docs/scenarios.md` for the YAML schema and existing kinds for the
  pattern.
- **Improve the `helios explain` narration** by editing the prompts in
  `helios-ai/src/helios_ai/explain.py`. Use `HELIOS_AI_MOCK=1` for
  no-network iteration.
- **Document a real-world failure scenario** in
  `fixtures/scenarios/<name>.yaml`, with a fixture infra under
  `fixtures/<infra-name>/`.

The `docs/ARCHITECTURE.md` doc has a per-crate map and a "where to land
your first PR" section that goes deeper.

## Local toolchain

- Rust stable (pinned in `rust-toolchain.toml`).
- Python 3.12 with `uv` (`helios-ai/.venv/`).
- Node 22 (>= 22.13) with `npm` (only needed for `web/` work).
- Optional: `make` for the convenience targets (`make demo`, `make check`,
  `make test`, `make fmt`).

`cargo test --workspace` is the source of truth for the Rust side. `cd
helios-ai && pytest` is the source of truth for the Python side. `cd web
&& npm test && npm run build` covers the viewer.

## Code review

The single reviewer (for now) is the maintainer. PRs that follow the
above usually merge within a few days.

## License

By contributing, you agree that your contributions will be licensed under
the Apache License 2.0 (see `LICENSE`).
