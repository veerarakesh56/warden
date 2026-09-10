"""Check every IAM action in the operator policies against AWS's own published action list.

    python scripts/check_iam_actions.py

⛔ WHY THIS EXISTS. `budgets:DescribeBudget` was in `operator-policy.json` and does not exist. It
looked entirely plausible — `DescribeBudget` is a real *API operation* — but AWS Budgets deliberately
names its IAM actions differently from its API (`ViewBudget` / `ModifyBudget`). It was caught by the
IAM console rejecting the paste, which is late: the same class of mistake in a Wave 2 or 3 policy
would be found the same way, one wasted attempt at a time.

The source is `awspolicygen.s3.amazonaws.com/js/policies.js` — the data behind AWS's own Policy
Generator. ~22,000 actions across ~455 services.

⚠ WHAT THIS IS NOT. It is not the Service Authorization Reference, and it can lag it: an action AWS
added recently may be missing here and reported as invalid. So a finding is "check this by hand",
not "this is definitely wrong". It also says nothing about whether a *condition* on a statement is
correct — a global-service action under `aws:RequestedRegion` is a real action that grants nothing,
and that is `tests/test_operator_policy.py`'s job, not this one.

⚠ It needs network. The offline structural checks live in the test suite and run in CI; this does
not.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import urllib.request

SOURCE = "https://awspolicygen.s3.amazonaws.com/js/policies.js"
ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_GLOB = "terraform/proving-ground/operator-policy*.json"


def fetch_actions(url: str = SOURCE, timeout: float = 60.0) -> dict[str, set[str]]:
    """service prefix -> every action AWS lists for it."""
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - fixed https URL
        raw = resp.read().decode("utf-8")
    config = json.loads(raw.split("=", 1)[1])
    by_prefix: dict[str, set[str]] = {}
    for entry in config["serviceMap"].values():
        by_prefix.setdefault(entry["StringPrefix"], set()).update(entry["Actions"])
    return by_prefix


def actions_in(paths: list[pathlib.Path]) -> dict[str, list[str]]:
    """action -> where it is used, so a finding names the statement to go and fix."""
    found: dict[str, list[str]] = {}
    for path in paths:
        for statement in json.loads(path.read_text(encoding="utf-8"))["Statement"]:
            declared = statement.get("Action") or statement.get("NotAction") or []
            for action in ([declared] if isinstance(declared, str) else declared):
                found.setdefault(action, []).append(f"{path.name}::{statement.get('Sid', '?')}")
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--glob", default=DEFAULT_GLOB)
    args = parser.parse_args()

    sys.stdout.reconfigure(encoding="utf-8")  # a Windows console is cp1252 and cannot print findings
    paths = sorted(ROOT.glob(args.glob))
    if not paths:
        print(f"no policy files matched {args.glob!r}")
        return 1

    try:
        known = fetch_actions()
    except Exception as exc:  # noqa: BLE001 - a network failure is not a policy failure
        print(f"could not fetch AWS's action list ({type(exc).__name__}: {exc}).")
        print("This check needs network. The offline structural checks are in the test suite.")
        return 2

    used = actions_in(paths)
    findings: list[str] = []
    confirmed = 0

    for action in sorted(used):
        prefix, _, name = action.partition(":")
        service = known.get(prefix)
        where = ", ".join(used[action])
        if service is None:
            findings.append(f"{action}: unknown service prefix {prefix!r}   [{where}]")
        elif name.endswith("*"):
            matches = sum(1 for k in service if k.startswith(name[:-1]))
            if matches:
                print(f"  wildcard {action} matches {matches} action(s)")
            else:
                findings.append(f"{action}: wildcard matches NOTHING   [{where}]")
        elif name in service:
            confirmed += 1
        else:
            near = sorted(k for k in service if k.lower().startswith(name.lower()[:6]))[:4]
            findings.append(
                f"{action}: not in AWS's list. closest: {near or 'nothing similar'}   [{where}]"
            )

    print(f"\n{len(paths)} file(s), {len(used)} distinct actions, {confirmed} confirmed against "
          f"AWS's list of {sum(len(v) for v in known.values())}")

    if findings:
        print(f"\n{len(findings)} to check by hand:")
        for finding in findings:
            print(f"  {finding}")
        print("\nThis list can lag the Service Authorization Reference, so a finding means "
              "'verify', not 'definitely wrong'. The IAM console's validator is the last word.")
        return 1

    print("no invalid actions found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
