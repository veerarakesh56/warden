"""Validate the IAM policies with AWS IAM Access Analyzer - AWS's own validator, not a list.

    python scripts/validate_policies.py            # every operator-policy*.json
    python scripts/validate_policies.py --strict   # also fail on WARNING, not just ERROR/SECURITY

⛔ WHY THIS EXISTS NEXT TO check_iam_actions.py. That script checks action NAMES against the data
behind AWS's Policy Generator. It is useful and it is not authoritative: it can lag, it knows nothing
about conditions, resources or grammar, and it is how `budgets:DescribeBudget` - a real API name
that is not a real IAM action - was only caught when the IAM console rejected a paste.

Access Analyzer's ValidatePolicy is the validator the console itself runs. It checks grammar, action
names, resource formats, condition keys against the actions that support them, and flags security
problems such as overly broad grants. This is that check, run before a paste instead of during one.

⚠ It needs network and credentials allowed `access-analyzer:ValidatePolicy`. The operator is granted
it through its own self-edit, inside the permissions boundary: validation only reads the document it
is sent and cannot change anything, which is why the boundary allows it without a region condition.

Exit codes: 0 clean · 1 findings at or above the threshold · 2 could not run (network, permission).
"""

from __future__ import annotations

import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_GLOB = "terraform/proving-ground/operator-policy*.json"
# In order of severity, as Access Analyzer reports them.
LEVELS = ("ERROR", "SECURITY_WARNING", "WARNING", "SUGGESTION")


def main(argv: list[str] | None = None, *, client=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--glob", default=DEFAULT_GLOB)
    parser.add_argument("--region", default="ap-south-2")
    parser.add_argument("--strict", action="store_true", help="fail on WARNING as well")
    args = parser.parse_args(argv)

    sys.stdout.reconfigure(encoding="utf-8")  # a Windows console is cp1252 and cannot print findings
    paths = sorted(ROOT.glob(args.glob))
    if not paths:
        print(f"no policy files matched {args.glob!r}")
        return 1

    if client is None:
        try:
            import boto3

            client = boto3.Session(region_name=args.region).client("accessanalyzer")
        except Exception as exc:  # noqa: BLE001
            print(f"could not create an Access Analyzer client: {type(exc).__name__}: {exc}")
            return 2

    fail_on = {"ERROR", "SECURITY_WARNING"} | ({"WARNING"} if args.strict else set())
    failing = 0
    for path in paths:
        try:
            findings = []
            pager = client.get_paginator("validate_policy")
            for page in pager.paginate(policyDocument=path.read_text(encoding="utf-8"),
                                       policyType="IDENTITY_POLICY"):
                findings += page.get("findings") or []
        except Exception as exc:  # noqa: BLE001 - a permission or network failure is not a finding
            print(f"{path.name}: could not validate ({type(exc).__name__}: {exc})")
            return 2

        counts = {level: sum(1 for f in findings if f["findingType"] == level) for level in LEVELS}
        print(f"{path.name}: " + ", ".join(f"{counts[lv]} {lv.lower()}" for lv in LEVELS))
        for finding in sorted(findings, key=lambda f: LEVELS.index(f["findingType"])):
            where = ", ".join(
                "/".join(str(p.get("value", p.get("index", ""))) for p in loc.get("path", []))
                for loc in finding.get("locations") or []
            )
            print(f"   {finding['findingType']:16s} {finding['issueCode']}: "
                  f"{finding['findingDetails'][:160]}" + (f"  [{where}]" if where else ""))
            if finding["findingType"] in fail_on:
                failing += 1

    if failing:
        print(f"\n{failing} finding(s) at or above the threshold.")
        return 1
    print("\nclean - nothing at or above the threshold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
