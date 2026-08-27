"""Command line entry point.

    warden run --alert fixtures/alerts/inc-001.yaml
    warden run --incident inc-001            # shorthand for the bundled fixtures
    warden demo                              # every bundled incident, one line each
"""

from __future__ import annotations

import argparse
import json
import sys

from .chatops import notify, resolve_sinks
from .graph import run
from .knowledge import default_knowledge_base
from .llm import LLMClient
from .models import Alert, Severity
from .remediation import RemediationError, RemediationRequest, decide_remediation
from .remediation_k8s import resolve_remediation_backend
from .reporting import build_report
from .tools import resolve_backend

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
    "inc-005": dict(
        alert_id="inc-005",
        name="DBConnectionsStuck",
        severity=Severity.high,
        service="payments",
        environment="prod",
        summary="Connection pool exhausted by 25 idle-in-transaction connections, no replica lag",
        started_at="2026-08-26T04:10:00Z",
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


def _emit_remediation_report(alert, report, *, principal, approve, emit_chatops) -> None:
    """Build (and optionally send) the redacted remediation report. Opt-in from `run` flags.

    The remediation gate runs only when a principal is named — it needs to know WHO is asking. With
    no principal, this just prints the report (matched patterns + verdict + promotion plan).
    """
    matches = default_knowledge_base().match(alert, report.context)

    remediation = None
    if principal is not None and report.proposal and report.verdict:
        # DRY-RUN unless WARDEN_REMEDIATION=live arms the real k8s backend. Either way the four-way
        # gate decides whether it is even reached. A live-backend init fault (no cluster) is surfaced,
        # not crashed.
        try:
            backend = resolve_remediation_backend()
        except RemediationError as exc:
            print(f"\n[remediation] live backend unavailable, not applying: {exc}")
            backend = None
        remediation = decide_remediation(
            alert,
            report.proposal,
            report.verdict,
            RemediationRequest(principal=principal, approved=approve),
            backend=backend,
        )

    built = build_report(
        alert,
        root_cause=report.root_cause,
        proposal=report.proposal,
        verdict=report.verdict,
        remediation=remediation,
        signatures=matches,
    )
    print("\n" + built.markdown)

    if emit_chatops:
        print("\nChatOps delivery:")
        for note in notify(built, resolve_sinks()):
            state = "sent" if note.delivered else "not sent"
            print(f"  - {note.sink}: {state} ({note.detail})")


def _alert_from(incident: str) -> Alert:
    if incident not in DEMO_ALERTS:
        raise SystemExit(f"unknown incident '{incident}'. Known: {', '.join(DEMO_ALERTS)}")
    return Alert(**DEMO_ALERTS[incident])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="warden", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="run one incident through the graph")
    p_run.add_argument("--incident", default="inc-001")
    p_run.add_argument("--verbose", action="store_true")
    p_run.add_argument("--max-usd", type=float, default=0.50)
    # Opt-in remediation + reporting. Off by default, so the plain `run` output is unchanged.
    p_run.add_argument("--report", action="store_true", help="build + print the redacted markdown report")
    p_run.add_argument("--principal", default=None, help="who is requesting remediation, e.g. role:oncall")
    p_run.add_argument("--approve", action="store_true", help="the principal approves applying the fix")
    p_run.add_argument("--emit-chatops", action="store_true", help="send the report to configured Slack/Teams/webhook sinks")
    p_run.add_argument("--environment", default=None, help="override the incident's environment (e.g. staging) to see the per-env gate")

    p_demo = sub.add_parser("demo", help="run every bundled incident")
    p_demo.add_argument("--verbose", action="store_true")

    args = parser.parse_args(argv)

    # Evidence source is a deployment decision, like the model provider. WARDEN_BACKEND=k8s reads a
    # live cluster; the default reads the recorded fixtures so CI never needs one.
    backend = resolve_backend()

    if args.cmd == "run":
        alert = _alert_from(args.incident)
        if args.environment:
            alert = alert.model_copy(update={"environment": args.environment})
        llm = LLMClient(max_usd=args.max_usd)
        report = run(alert, llm=llm, backend=backend)
        _print_report(report, verbose=args.verbose)

        want_remediation = args.principal is not None
        if args.report or want_remediation or args.emit_chatops:
            _emit_remediation_report(
                alert, report,
                principal=args.principal, approve=args.approve, emit_chatops=args.emit_chatops,
            )
        return 0

    for incident in DEMO_ALERTS:
        report = run(_alert_from(incident), llm=LLMClient(), backend=backend)
        _print_report(report, verbose=args.verbose)
    print("\nNo action was executed. WARDEN proposes and gates; a human executes.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
