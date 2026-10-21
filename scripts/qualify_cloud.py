"""Qualify a model on the pinned prompt with the cloud runtime's own key, and write the result into the repository -
one command (owner, 2026-10-21: paid qualification runs from the laptop with the cloud runtime's key):

    uv run --extra anthropic python scripts/qualify_cloud.py --model claude-sonnet-5-5 --budget-usd 2

"The cloud runtime" is WARDEN's own runtime environment (environments.yaml `runtime`): its Anthropic key is the
Secrets Manager secret `warden/<runtime env>/anthropic-api-key` (settings.ZONE_SECRETS, the llm zone's), read here
with the caller's own AWS identity - or ANTHROPIC_API_KEY when this process already holds it. The key stays in this
process's environment; it is never printed or written. `uv run` uses uv.lock, so the model is called through the SDK
the runtime image ships (a different SDK has scored 2 apart on the same model: providers.yaml).

scripts/qualify_provider.py measures (30 recorded incidents, under --budget-usd as a hard ceiling). Then, pass or fail,
the result is written into this checkout - a measurement, never a claim:
  - docs/BENCHMARKS.md: one dated row in the qualification table (above QUALIFICATION_RUNS_MARKER);
  - src/warden/data/providers.yaml: on a pass ON THE PINNED PROMPT (`prompt.sha`), the row under `qualified:`; else a
    `# NOT QUALIFIED` comment there with the numbers, so nothing can read it as a qualification;
  - the "Qualified on the pinned prompt" status line in README.md and docs/BENCHMARKS.md, from providers.yaml;
  - docs/safety-pins.sha256 (providers.yaml is pinned) and docs/sbom/warden.cdx.json (it lists the models).
Review the diff and open a pull request. `--from-result <qualification.json>` writes an earlier run's result with no
model call.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import sys
import tempfile

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPTS = pathlib.Path(__file__).resolve().parent
PROVIDERS_YAML = ROOT / "src" / "warden" / "data" / "providers.yaml"
BENCHMARKS_MD = ROOT / "docs" / "BENCHMARKS.md"
README_MD = ROOT / "README.md"
KEY_SLOT = "anthropic-api-key"  # the slot's name in Secrets Manager, never its value
QUALIFICATION_RUNS_MARKER = "<!-- qualification-runs:"
STATUS_PREFIX = "**Qualified on the pinned prompt**"
# A pass, as the BENCHMARKS row says it: what was done that day, never "qualified" in the present - a later run on
# the same prompt may retire the row.
OK_WORDS = "met the bar on the pinned prompt: row added to providers.yaml"
_NOT_IN_ROW = ("passed", "slo_breaches", "reverified")


def meets_bar(row: dict, bar: dict) -> bool:
    """providers.qualified()'s test of one row against the bar, plus every incident answered (qualify_provider)."""
    return (
        int(row.get("wrong_and_allowed", 1 << 30)) <= int(bar["wrong_and_allowed"])
        and int(row.get("correct", -1)) >= int(bar["min_correct"])
        and int(row.get("unanswered", 0)) == 0
    )


def qualified_now(doc: dict) -> list[dict]:
    """The rows that qualify a model today: measured on the pinned prompt and meeting the bar (providers.qualified)."""
    pinned = (doc.get("prompt") or {}).get("sha")
    return [
        r
        for r in doc.get("qualified") or []
        if isinstance(r, dict) and pinned and r.get("prompt") == pinned and meets_bar(r, doc["bar"])
    ]


def status_line(doc: dict, today: str) -> str:
    """The one line README.md and docs/BENCHMARKS.md say it with, generated from providers.yaml alone."""
    rows = qualified_now(doc)
    head = f"{STATUS_PREFIX} (as of {today}, from `src/warden/data/providers.yaml`): "
    if not rows:
        return (
            head
            + "**none**. Every model is refused, and each incident gets the rules-only diagnosis and goes to "
            "a person."
        )
    named = "; ".join(
        f"{r['provider']} `{r['model']}` ({r['correct']} of {r['runs']}, measured {r['measured']})"
        for r in sorted(rows, key=lambda r: (r["provider"], r["model"]))
    )
    return head + named + "."


def _with_status(text: str, line: str) -> str:
    out = text.splitlines(keepends=True)
    at = [i for i, s in enumerate(out) if s.startswith(STATUS_PREFIX)]
    if len(at) != 1:
        raise SystemExit(f"expected one line starting {STATUS_PREFIX!r}, found {len(at)}")
    out[at[0]] = line + "\n"
    return "".join(out)


def verdict(result: dict, doc: dict) -> tuple[bool, str]:
    """Whether the result qualifies its model today, and why in words. Recomputed here from the bar and the pin: the
    result's own `passed` is necessary, never sufficient."""
    pinned = (doc.get("prompt") or {}).get("sha")
    if not (result.get("passed") and meets_bar(result, doc["bar"])):
        return False, "below the bar: NOT qualified"
    if result.get("prompt") != pinned:
        return False, (
            f"met the bar on prompt `{str(result.get('prompt'))[:8]}`, which is not the pinned prompt: "
            "NOT qualified"
        )
    return True, OK_WORDS


def providers_with(result: dict, text: str, ok: bool, when: str) -> str:
    """providers.yaml's text with the result in it: under `qualified:` when it qualifies, else a NOT QUALIFIED comment."""
    row = json.dumps({k: v for k, v in result.items() if k not in _NOT_IN_ROW})
    if ok:
        lines = [
            f"  # Measured {when} by scripts/qualify_cloud.py with the cloud runtime's key.",
            f"  - {row}",
        ]
    else:
        breaches = "; ".join(result.get("slo_breaches") or [])
        lines = [
            f"  # NOT QUALIFIED - measured {when} by scripts/qualify_cloud.py"
            + (f" (SLO: {breaches})" if breaches else "")
            + ":",
            f"  #  {row}",
        ]
    out = text.splitlines(keepends=True)
    at = [i for i, s in enumerate(out) if s.rstrip() in ("qualified:", "qualified: []")]
    if len(at) != 1:
        raise SystemExit("providers.yaml needs exactly one `qualified:` line")
    pinned = ((yaml.safe_load(text) or {}).get("prompt") or {}).get("sha")
    if ok:  # one live row per model: an earlier prompt's row of the same model is kept as history, as a comment
        out = [_retired(s, result) for s in out]
    elif pinned and result.get("prompt") == pinned:
        # A model that fails on the pinned prompt loses its row on that prompt (CodeRabbit, PR 173); rows on earlier
        # prompts stay as they are - they qualify nothing today.
        out = [_retired(s, result, prompt=pinned) for s in out]
    out[at[0] + 1 : at[0] + 1] = [s + "\n" for s in lines]
    # `qualified` stays a list (providers.load_qualified refuses anything else): `[]` when no live row is left.
    live = any(s.startswith("  - {") for s in out[at[0] + 1 :])
    out[at[0]] = "qualified:\n" if live else "qualified: []\n"
    return "".join(out)


def _retired(line: str, result: dict, prompt: str | None = None) -> str:
    if not line.startswith("  - {"):
        return line
    row = json.loads(line[4:])
    if (row.get("provider"), row.get("model")) != (result.get("provider"), result.get("model")):
        return line
    if prompt is not None and row.get("prompt") != prompt:
        return line
    return f"  # Before (prompt {str(row.get('prompt'))[:8]}): " + line[4:]


def benchmarks_with(result: dict, text: str, why: str, when: str) -> str:
    """docs/BENCHMARKS.md's text with one dated row added above the qualification table's marker."""
    spent = result.get("spent_usd")
    cells = [
        when,
        f"{result.get('provider')} `{result.get('model')}`",
        f"`{str(result.get('prompt'))[:8]}`",
        str(result.get("correct")),
        str(result.get("wrong_and_allowed")),
        str(result.get("unanswered", 0)),
        str(result.get("escalated", "")),
        "" if spent is None else f"{spent:.2f}",
        why,
    ]
    out = text.splitlines(keepends=True)
    at = [i for i, s in enumerate(out) if s.startswith(QUALIFICATION_RUNS_MARKER)]
    if len(at) != 1:
        raise SystemExit(f"docs/BENCHMARKS.md needs exactly one {QUALIFICATION_RUNS_MARKER!r} line")
    out.insert(at[0], "| " + " | ".join(c.replace("|", "/") for c in cells) + " |\n")
    return "".join(out)


def record(
    result: dict, *, providers: str, benchmarks: str, readme: str, when: str
) -> tuple[str, str, str, str]:
    """The three files' new text and what was decided. Pure: main() writes them."""
    ok, why = verdict(result, yaml.safe_load(providers))
    providers = providers_with(result, providers, ok, when)
    line = status_line(yaml.safe_load(providers), when[:10])
    benchmarks = _with_status(benchmarks_with(result, benchmarks, why, when), line)
    return providers, benchmarks, _with_status(readme, line), why


def runtime_environment() -> str:
    from warden.environments import default_environment_policies

    env = default_environment_policies().runtime_environment
    if not env:
        raise SystemExit("environments.yaml names no runtime environment")
    return env


def model_key(env: str, client: object = None) -> str:
    """Put the runtime's Anthropic key in this process's environment, from Secrets Manager unless already there; say
    where it came from, in words (never the value)."""
    if os.environ.get("ANTHROPIC_API_KEY", "").strip():
        return "ANTHROPIC_API_KEY, already in this process"
    name = f"warden/{env}/{KEY_SLOT}"
    if client is None:
        import boto3

        from warden.environments import region

        client = boto3.client("secretsmanager", region_name=region())
    value = str(client.get_secret_value(SecretId=name).get("SecretString") or "").strip()
    if not value:
        raise SystemExit(f"{name} is empty")
    os.environ["ANTHROPIC_API_KEY"] = value
    return f"Secrets Manager {name}"


def measure(a: argparse.Namespace, secrets_client: object = None) -> dict:
    """scripts/qualify_provider.py for one Anthropic model with the runtime's key, under a hard USD ceiling."""
    env = a.env or runtime_environment()
    print(f"qualify {a.model}: key from {model_key(env, secrets_client)}; out {a.out}")
    os.environ["WARDEN_PROVIDER"] = "anthropic"
    os.environ["WARDEN_MODEL"] = a.model
    for price in ("WARDEN_PRICE_IN", "WARDEN_PRICE_OUT"):
        os.environ.pop(
            price, None
        )  # each model at its own price (providers.yaml `prices`), which the budget counts
    sys.path.insert(0, str(SCRIPTS))
    import qualify_provider

    qualify_provider.main(["--out", str(a.out), "--budget-usd", str(a.budget_usd)])
    return json.loads((a.out / "qualification.json").read_text(encoding="utf-8"))


def write(result: dict, when: str) -> str:
    """Write the result into providers.yaml, docs/BENCHMARKS.md and README.md, re-render the safety pins."""
    providers, benchmarks, readme, why = record(
        result,
        providers=PROVIDERS_YAML.read_text(encoding="utf-8"),
        benchmarks=BENCHMARKS_MD.read_text(encoding="utf-8"),
        readme=README_MD.read_text(encoding="utf-8"),
        when=when,
    )
    for path, text in (
        (PROVIDERS_YAML, providers),
        (BENCHMARKS_MD, benchmarks),
        (README_MD, readme),
    ):
        path.write_text(text, encoding="utf-8", newline="\n")
    sys.path.insert(0, str(SCRIPTS))
    import safety_pins
    import sbom

    safety_pins.main()
    sbom.main()  # the bill names each model and whether it is qualified on the pinned prompt
    return why


def compare_with_result(path: pathlib.Path) -> pathlib.Path | None:
    """The qualification.json --compare-with names: the file itself, or the one in that run directory; else None."""
    found = path / "qualification.json" if path.is_dir() else path
    return found if found.name == "qualification.json" and found.is_file() else None


def print_comparison(
    result: dict, run_dir: pathlib.Path | None, compare_with: pathlib.Path | None
) -> None:
    """Old against new before anything is written (docs/OPERATIONS.md "Upgrading the model"): the row qualified now,
    or --compare-with's run, beside this result - per incident when run directories exist - and the verdict."""
    import qualification_compare as cmp

    doc = yaml.safe_load(PROVIDERS_YAML.read_text(encoding="utf-8"))
    old = cmp.old_side(doc, result.get("provider"), compare_with)
    new = cmp.side(f"new: {result.get('model')}", result, run_dir)
    if old is None:
        old = {"label": "old: none recorded", "totals": {}, "incidents": None}
    print(cmp.render(old, new, verdict(result, doc)[1]))


def main(argv: list[str] | None = None, *, secrets_client: object = None) -> int:
    import datetime as dt

    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--model", help="an exact model id (register M15)")
    p.add_argument(
        "--budget-usd", type=float, help="a hard ceiling on what the run may spend in total"
    )
    p.add_argument(
        "--env",
        default=None,
        help="whose key: the runtime environment (environments.yaml) by default",
    )
    p.add_argument(
        "--out", type=pathlib.Path, default=None, help="a NEW directory outside the repository"
    )
    p.add_argument(
        "--from-result",
        type=pathlib.Path,
        default=None,
        help="write this qualification.json's result; no key is read and no model is called",
    )
    p.add_argument(
        "--compare-with",
        type=pathlib.Path,
        default=None,
        help="the old side: an earlier run directory (or its qualification.json); default the providers.yaml row",
    )
    a = p.parse_args(argv)
    if a.compare_with is not None and compare_with_result(a.compare_with) is None:
        # Before any key is read or any money spent (CodeRabbit, PR 173): a mistyped path is an error, never an empty
        # old side that reads as "nothing to compare with".
        p.error(
            f"--compare-with {a.compare_with}: no qualification.json there (a run directory or that file)"
        )
    sys.path.insert(0, str(SCRIPTS))
    if a.from_result:
        result = json.loads(a.from_result.read_text(encoding="utf-8"))
        a.out = a.from_result.parent
    else:
        if not a.model or a.budget_usd is None:
            p.error("--model and --budget-usd are required for a run (or --from-result)")
        a.out = (
            (a.out or pathlib.Path(tempfile.mkdtemp(prefix="warden-qualify-")))
            .expanduser()
            .resolve()
        )
        result = measure(a, secrets_client)
    measured = str(result.get("measured") or "")
    when = (
        re.sub(r"T(\d\d:\d\d)Z?$", r" \1", measured)
        if measured
        else dt.datetime.now(dt.UTC).strftime("%Y-%m-%d %H:%M")
    )
    try:
        print_comparison(result, a.out, a.compare_with)
        compared = True
    except Exception as exc:  # noqa: BLE001  # a paid result is recorded even when the comparison cannot be printed
        print(
            f"comparison unavailable ({type(exc).__name__}: {exc}); recording the result anyway",
            file=sys.stderr,
        )
        compared = False
    why = write(result, when)
    ok = why == OK_WORDS
    print(
        f"\nrecorded ({why}) in {PROVIDERS_YAML.relative_to(ROOT)}, {BENCHMARKS_MD.relative_to(ROOT)}, "
        f"{README_MD.relative_to(ROOT)}, the safety pins and the SBOM: review the diff and open a pull request"
        + (
            "; also retire the NOT YET QUALIFIED note above `prompt.sha` in providers.yaml"
            if ok
            else ""
        )
    )
    if not compared:
        return 2
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
