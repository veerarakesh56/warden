"""Command line entry point.

    aegis run --alert fixtures/alerts/inc-001.yaml
    aegis run --incident inc-001            # shorthand for the bundled fixtures
    aegis demo                              # every bundled incident, one line each
"""

from __future__ import annotations

import argparse
import json
import sys

from .graph import run
from .llm import LLMClient
from .models import Alert, Severity

# The bundled scenarios. Each one exists to exercise a different route through the graph.
DEMO_ALERTS: dict[str, dict] = {
    "inc-001": dict(
        alert_id="inc-001",
        name="HighErrorRate",
        severity=Severity.critical,
        service="checkout",
        environment="prod",
        summary="5xx rate above 4% for user priya.nair@corp.io on tenant_id=acme-42",
        started_at="2026-08-21T10:02:00Z",
    ),
    "inc-002": dict(
        alert_id="inc-002",
        name="PodOOMKilled",
        severity=Severity.high,
        service="checkout",
        environment="prod",
        summary="Repeated OOM kills, memory at 94% of limit",
        started_at="2026-08-21T14:11:00Z",
    ),
    "inc-003": dict(
        alert_id="inc-003",
        name="ReplicaLagHigh",
        severity=Severity.high,
        service="orders",
        environment="prod",
        summary="Connection pool exhausted, replica lag 47s",
        started_at="2026-08-21T03:20:00Z",
    ),
    "inc-004": dict(
        alert_id="inc-004",
        name="Elevated4xx",
        severity=Severity.low,
        service="gateway",
        environment="prod",
        summary="Slightly elevated 4xx from one client",
        started_at="2026-08-21T22:04:00Z",
    ),
}


def _print_report(report, *, verbose: bool) -> None:
    v = report.verdict
    print(f"\n=== {report.alert.alert_id}  {report.alert.name} [{report.alert.environment}] ===")
    print(f"  identifiers masked : {report.redaction_map_size}")
    if report.root_cause:
        print(f"  hypothesis         : {report.root_cause.hypothesis}")
        print(f"  confidence         : {report.root_cause.confidence:.2f}")
    if report.proposal:
        print(f"  proposed action    : {report.proposal.action.value} -> {report.proposal.target}")
        print(f"  blast radius       : {report.proposal.blast_radius}")
    if v:
        print(f"  VERDICT            : {v.status.value.upper()}")
        if v.policy_ids:
            print(f"  policies fired     : {', '.join(v.policy_ids)}")
        for reason in v.reasons:
            print(f"    - {reason}")
    print(f"  cost               : ${report.cost.usd:.4f} over {report.cost.calls} call(s)")
    if verbose:
        print("  audit trail:")
        for step in report.audit:
            print(f"    {json.dumps(step)}")


def _alert_from(incident: str) -> Alert:
    if incident not in DEMO_ALERTS:
        raise SystemExit(f"unknown incident '{incident}'. Known: {', '.join(DEMO_ALERTS)}")
    return Alert(**DEMO_ALERTS[incident])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aegis", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="run one incident through the graph")
    p_run.add_argument("--incident", default="inc-001")
    p_run.add_argument("--verbose", action="store_true")
    p_run.add_argument("--max-usd", type=float, default=0.50)

    p_demo = sub.add_parser("demo", help="run every bundled incident")
    p_demo.add_argument("--verbose", action="store_true")

    args = parser.parse_args(argv)

    if args.cmd == "run":
        llm = LLMClient(max_usd=args.max_usd)
        report = run(_alert_from(args.incident), llm=llm)
        _print_report(report, verbose=args.verbose)
        return 0

    for incident in DEMO_ALERTS:
        report = run(_alert_from(incident), llm=LLMClient())
        _print_report(report, verbose=args.verbose)
    print("\nNo action was executed. AEGIS proposes and gates; a human executes.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
