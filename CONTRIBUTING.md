# Contributing to WARDEN

Thank you for helping. WARDEN changes live systems, so the rules below are strict: every change is small, tested and
honest about what it proves. Please read [README.md](README.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and
[the failure-mode register](docs/FAILURE-MODES.md) before you start.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). Report a security problem as
[SECURITY.md](SECURITY.md) says, never in a public issue.

## Set up

You need Python 3.12 or later and [uv](https://docs.astral.sh/uv/). No cloud account and no model key are needed:
mock mode runs the whole pipeline on recorded incidents.

```
uv sync --locked --extra dev
WARDEN_MOCK=1 uv run warden demo
```

The full test set needs the optional extras CI installs:

```
uv sync --locked --extra dev --extra all-providers --extra mcp --extra k8s --extra aws --extra approval --extra postgres
```

## Check your change the way CI does

These are the commands of the `CI · tool` workflow ([ci-tool.yml](.github/workflows/ci-tool.yml)):

```
ruff check src tests evals scripts scenarios
python scripts/check_publishable.py
pytest tests -q -n auto
pytest evals -q
```

And the security scans (`uv sync --locked --group scan` first):

```
bandit -q -r src scenarios scripts -ll
zizmor --offline --format plain .github
```

Tests under `tests/integration` need a live Kubernetes cluster or database servers. They skip on your machine and run
in CI's own jobs, which fail if any of them skips. Terraform changes are checked by `CI · infra`
(`terraform fmt -check -recursive` and `terraform validate`).

## What a pull request needs

- **One change per pull request**, into `main`. `main` runs CI only and deploys nothing.
- **A test for every change.** A bug fix comes with a test that fails without the fix.
- **A plant check for every new guard.** Break the guard on purpose, see its test fail, restore it. Say in the pull
  request which plant checks you did.
- **The register stays true.** If your change closes or opens a failure mode, update
  [docs/FAILURE-MODES.md](docs/FAILURE-MODES.md). A row marked done must cite a test that exists and is not skipped;
  [tests/test_register.py](tests/test_register.py) fails CI otherwise.
- **No suppressions without a reason.** Do not add `# noqa`, `# nosec`, `type: ignore`, `pragma: no cover`, a skip or
  an xfail unless it is truly needed, with a one-line reason on the same line.
- **No secrets, account ids, email addresses or real-looking tokens** anywhere, tests included. Build test credentials
  from parts at run time, as [tests/fakes.py](tests/fakes.py) does. No environment, Region or account literals in
  `src`: they come from configuration.
- **Pin what you add.** GitHub Actions by full commit SHA, Python packages through `uv.lock`, images by digest.
- **Plain words** in docs, reports and messages. Anything not built yet is called "planned".
- **Every check green** before review: CI · tool, CI · infra, CI · apps, Scan · workflows, CodeQL and the SonarCloud
  quality gate. Every review finding (CodeRabbit, SonarCloud, CodeQL) is fixed, or answered with evidence.

Maintainers merge with a rebase merge, one pull request at a time.

## Safety rules you must not weaken

Some parts are deliberate security choices. A change that weakens one is refused, even if a tool flags it:

- the passkey approval design and the public approval page;
- the closed catalogue of fixes, the deterministic verifier and the outbound gate;
- the kill switch, the bounds and the breaker;
- the signed, hash-chained audit.

If you think one of them is wrong, open an issue and explain why first.

## Reporting bugs and asking for features

Use the issue templates: **Bug report** or **Feature request**. For a bug, give the version or commit, the command you
ran, what you expected and what happened. Remove any secret, account id or personal data from logs before you paste
them.

## Licence

WARDEN is licensed under the [Apache License 2.0](LICENSE). By contributing you agree that your contribution is
licensed under it too (section 5 of the licence).
