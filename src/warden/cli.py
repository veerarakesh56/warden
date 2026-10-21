"""Command line entry point.

    warden run --incident inc-001            # shorthand for the bundled fixtures
    warden run --alert path/to/alert.yaml    # any alert, from a file
    warden demo                              # every bundled incident, one line each
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import pathlib
import sys
from datetime import UTC, datetime

import yaml
from pydantic import ValidationError

from . import gate, paths
from .graph import run
from .knowledge import default_knowledge_base
from .llm import LLMClient
from .models import Alert, Severity
from .reporting import _scrub, build_report
from .tools import resolve_backend
from .verifier import symptoms

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
        labels={"database": "orders-db"},
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
        labels={"database": "payments-db"},
    ),
}


def _out(text: object, *, err: bool = False) -> None:
    """stdout is an egress too - a terminal, a CI log, a pasted ticket (audit A-C-8): no secret, and no
    control character (an ESC sequence in model- or alert-written text can rewrite what the operator
    sees). EVERY line this CLI prints goes through here (independent review 2026-09-28: `warden
    status` printed an agent-controlled field raw)."""
    print(gate.for_terminal(str(text)), file=sys.stderr if err else sys.stdout)


def _one(text: object) -> str:
    """A field someone else wrote, on one line: a newline in an alert name forged `VERDICT` lines."""
    try:
        return " ".join(str(text).split())
    except Exception:  # noqa: BLE001 - an exception whose text raises (fifth review, 2026-10-01)
        return "(text withheld)"


def _print_report(report, *, verbose: bool) -> None:
    v = report.verdict
    _out(f"\n=== {report.alert.alert_id}  {_one(report.alert.name)} [{report.alert.environment}] ===")
    _out(f"  identifiers masked : {report.redaction_map_size}")
    # What the rules found comes first, the model's prose last (register N4): an approver reads fluent text as
    # evidence, so the verdict, its policies and what the evidence itself shows are read before it.
    if v:
        _out(f"  VERDICT            : {v.status.value.upper()}")
        if v.policy_ids:
            _out(f"  policies fired     : {', '.join(v.policy_ids)}")
        for reason in v.reasons:
            _out(f"    - {_one(reason)}")
    _out(f"  evidence shows     : {'; '.join(symptoms(report.context)) or 'no counted broken component'}")
    if report.proposal:
        _out(f"  proposed action    : {report.proposal.action.value} -> {_one(report.proposal.target)}")
        _out(f"  blast radius       : {report.proposal.effective_blast_radius} (enforced; "
              f"proposal claimed {report.proposal.blast_radius})")
    if report.root_cause:
        _out(f"  hypothesis (model) : {_one(report.root_cause.hypothesis)}")
        _out(f"  confidence (model) : {report.root_cause.confidence:.2f}")
    _out(f"  cost               : ${report.cost.usd:.4f} over {report.cost.calls} call(s)")
    if verbose:
        _out("  audit trail:")
        for step in report.audit:
            _out(f"    {json.dumps(step)}")


def _print_markdown_report(alert, report) -> None:
    """Print the redacted markdown report (`run --report`): matched patterns, verdict, who acts. It only prints:
    nothing is sent and nothing is applied - a live change goes through the RemediationWorkflow and a signed
    approval (decision D16)."""
    matches = default_knowledge_base().match(alert, report.context)
    built = build_report(
        alert,
        root_cause=report.root_cause,
        proposal=report.proposal,
        verdict=report.verdict,
        signatures=matches,
        context=report.context,
        redaction_map=report.redaction_map,
        backend=os.environ.get("WARDEN_BACKEND"),
    )
    _out("\n" + built.markdown)


def _alert_from(incident: str) -> Alert:
    if incident not in DEMO_ALERTS:
        raise SystemExit(f"unknown incident '{incident}'. Known: {', '.join(DEMO_ALERTS)}")
    return Alert(**DEMO_ALERTS[incident])


def _contained(path: str | pathlib.Path, what: str) -> pathlib.Path:
    """`path` from the command line, refused unless it lies where WARDEN's tools work (paths.inside)."""
    try:
        return paths.inside(path)
    except ValueError as e:
        raise SystemExit(f"{what}: {e}") from None


def _key_file(path: pathlib.Path) -> pathlib.Path:
    """A --key or --public-key from the command line: read from the key folder only, where keygen writes keys."""
    from . import audit

    try:
        return audit.key_path(path)
    except (ValueError, FileNotFoundError) as e:
        raise SystemExit(str(e)) from None


def _alert_from_file(path: str) -> Alert:
    """Load an alert from a YAML file with the same fields as a bundled one.

    Why this exists rather than "just add another bundled incident": every bundled alert names its
    own cause (`PodOOMKilled`, "Repeated OOM kills, memory at 94% of limit"), and that text reaches
    the model verbatim as the first line of the reasoning prompt. Anything that measures WARDEN
    against a fault it was not told about needs an alert that does not name the answer — so the
    alert has to be able to come from outside this file.

    Validation is pydantic's, and it is loud: a malformed alert fails here rather than becoming a
    confusing result later.
    """
    data = yaml.safe_load(_contained(path, "--alert").read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"--alert {path}: expected a YAML mapping, got {type(data).__name__}")
    try:
        return Alert(**data)
    except ValidationError as exc:
        raise SystemExit(f"--alert {path}: {exc}") from exc


def _apply_overrides(alert: Alert, args) -> Alert:
    """Point a bundled incident shape at a real system.

    `--started-at` matters more than it looks: the bundled alerts carry a fixed date, and a backend
    that reads a time window around it (AWS) would read a window with nothing in it and report an
    absence of evidence — which reads exactly like a healthy service.
    """
    update: dict[str, object] = {}
    if args.environment:
        update["environment"] = args.environment
    if getattr(args, "service", None):
        update["service"] = args.service

    when = getattr(args, "started_at", None)
    if when:
        if when.lower() == "now":
            update["started_at"] = datetime.now(UTC).isoformat()
        else:
            try:  # fail here, loudly, rather than silently reading the wrong window later
                parsed = datetime.fromisoformat(when)
            except ValueError as exc:
                raise SystemExit(f"--started-at must be ISO-8601 or 'now': {exc}") from exc
            if parsed.tzinfo is None:  # local or UTC? hours apart (audit A-B-L14)
                raise SystemExit("--started-at needs a zone: end it with Z or an offset such as +05:30")
            update["started_at"] = when

    labels = dict(alert.labels)
    for pair in getattr(args, "label", None) or []:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            raise SystemExit(f"--label must be K=V, got '{pair}'")
        labels[key] = value
    if labels != alert.labels:
        update["labels"] = labels

    # model_validate, not model_copy: model_copy skips validation, and the label rules must hold
    # for a --label as much as for an alert file.
    return Alert.model_validate({**alert.model_dump(), **update}) if update else alert


def _load_environment(command: str, zone: str | None = None) -> None:
    """With WARDEN_ENV set, read that environment's plain values from SSM and its secrets from Secrets Manager
    (settings.py). An unknown environment or an unreachable store stops the run: running with half a config would be
    worse than not running."""
    from . import settings
    from .environments import EnvironmentPolicyError

    try:
        loaded = settings.load(only=settings.loadable_for(command, zone), zone=zone)
    except EnvironmentPolicyError as exc:
        raise SystemExit(f"WARDEN_ENV: {exc}") from exc
    except Exception as exc:
        raise SystemExit(f"WARDEN_ENV: could not read the configuration: {type(exc).__name__}") from exc
    if loaded:
        _out(f"[config] {os.environ.get('WARDEN_ENV')}: loaded {', '.join(loaded)} (SSM, Secrets Manager)", err=True)


def _typed_passphrase() -> bytes:
    """A new key's passphrase typed twice at a terminal, never echoed; b"" when there is no terminal or the two
    differ."""
    if not sys.stdin.isatty():
        return b""
    import getpass

    first = getpass.getpass("passphrase for the new private key: ")
    if first != getpass.getpass("the same passphrase again: "):
        _out("error: the two passphrases differ", err=True)
        return b""
    return first.encode()


def _audit_command(args: argparse.Namespace) -> int:
    from . import audit

    if args.audit_cmd == "keygen":
        if args.private.exists():
            _out(f"{args.private} exists; refusing to overwrite a signing key")
            return 1
        # Encrypted unless asked otherwise (naming audit item 4, 2026-10-16: with no passphrase set, keygen wrote the
        # key in the clear and only said so, while approvals.py promised an encrypted one - and a signature is only
        # as strong as the key file at rest). The passphrase comes from the environment (Secrets Manager in the
        # cloud) or is typed at a prompt, never from the command line (shell history).
        if args.unencrypted:
            passphrase = None
            _out("WARNING: --unencrypted: the private key is written IN THE CLEAR. Anyone who can read "
                 f"{args.private} - a backup, a synced folder, another account with access - can sign as its owner. "
                 "Use it only for a throwaway key; an approver's key must be encrypted.", err=True)
        else:
            passphrase = os.environ.get("WARDEN_AUDIT_KEY_PASSPHRASE", "").encode() or _typed_passphrase()
            if not passphrase:
                _out("error: no passphrase, so no key was written: type one at the prompt (a terminal), or set "
                     "WARDEN_AUDIT_KEY_PASSPHRASE without echoing it; --unencrypted writes the key in the clear",
                     err=True)
                return 1
        try:
            audit.generate_key(args.private, args.public, passphrase)
        except (ValueError, FileExistsError, FileNotFoundError) as e:
            _out(f"error: {e}; no key was written", err=True)
            return 1
        _out(f"private key {args.private} ({'encrypted' if passphrase else 'NOT encrypted'}), "
              f"public key {args.public}")
        return 0
    if args.audit_cmd == "migrate":
        # Run by the migration role (its DSN in WARDEN_AUDIT_MIGRATION_DSN), never by the runtime: the runtime's
        # role gets SELECT and INSERT only (G6).
        dsn = os.environ.get("WARDEN_AUDIT_MIGRATION_DSN", "").strip()
        if not audit._is_postgres(dsn):
            _out("error: set WARDEN_AUDIT_MIGRATION_DSN to the migration role's postgresql:// DSN", err=True)
            return 1
        audit.migrate(dsn, writer_role=args.writer_role)
        _out(f"audit tables ready; {args.writer_role} may read and append, nothing else")
        return 0
    # The DSN comes from the environment (a secret), never the command line; else the --db file.
    target = os.environ.get("WARDEN_AUDIT_DSN", "").strip() or (_contained(args.db, "--db") if args.db else None)
    if target is None:
        _out("error: give --db, or set WARDEN_AUDIT_DSN", err=True)
        return 1
    # With the anchor bucket, every checkpoint must also match its Object Lock copy (register S12).
    bucket = getattr(args, "anchor_bucket", None)
    anchors = audit.S3Anchor(bucket).all() if bucket else None
    result = audit.verify(target, audit.load_public_key(_key_file(args.public_key)), anchors)
    if args.audit_cmd == "show":
        # Register S17: what a message's footer names, read from the record itself, after the chain is verified.
        from .environments import both_times

        log = audit.AuditLog(target)
        rows = log.entries(args.incident)
        log.close()
        for e in rows:
            # Hash first, row number last: `7  2026-10-03 06` read as a phone number and the gate withheld the line.
            _out(f"{audit.short(e['hash'])}  {e['kind']:<24} {both_times(e['at'])}  row {e['seq']}")
        _out(f"incident {args.incident}: {len(rows)} row(s); the chain is {'intact' if result.ok else 'NOT intact'}")
        return 0 if result.ok and rows else 1
    for problem in result.problems:
        _out(f"TAMPERED: {problem}")
    _out(f"{result.rows} rows, signed through row {result.signed_through}"
          + (f", {result.unsigned_tail} newer row(s) not yet signed" if result.unsigned_tail else ""))
    _out("intact" if result.ok else "NOT intact")
    return 0 if result.ok else 1


def _approver_key(path: pathlib.Path):
    from . import audit

    # The approver's passphrase comes from the environment, never from the command line (shell history).
    return audit.load_private_key(_key_file(path), os.environ.get("WARDEN_APPROVER_KEY_PASSPHRASE", "").encode() or None)


async def _autonomy_command(args: argparse.Namespace) -> int:
    """A person turns autonomy back on in an environment after a demotion (autonomy.enable, owner 2026-10-17), through
    the runtime's own AutonomyWorkflow: every demotion is shown first, and the approver states how many they read - the
    signature covers exactly those, as a kill switch reset does."""
    import uuid

    from . import approvals, runtime
    from .workflows import AutonomyWorkflow

    client = await runtime.connect()
    handle = await client.start_workflow(AutonomyWorkflow.run, args.environment,
                                         id=f"autonomy-{args.environment}-{uuid.uuid4().hex[:12]}",
                                         task_queue=runtime.TASK_QUEUE)
    state = None
    for _ in range(120):
        if (state := await handle.query(AutonomyWorkflow.state)) is not None:
            break
        await asyncio.sleep(0.5)
    if state is None:
        await handle.cancel()
        _out("error: the runtime did not answer: is a core worker running?", err=True)
        return 1
    shown = state["demotions"]
    _out(f"autonomy in {args.environment}: at most {state['ceiling']}; "
         f"{len(shown)} demotion{'s' if len(shown) != 1 else ''} since a person last enabled it")
    for why in shown:
        _out(f"  - {_one(why)}")
    if args.autonomy_cmd == "status" or not shown or args.demotions != len(shown):
        await handle.cancel()
        if args.autonomy_cmd == "enable" and shown:
            _out(f"not enabled: you reviewed {args.demotions}, there are {len(shown)}; check them and pass "
                 f"--demotions {len(shown)}")
            return 1
        return 0
    signed = approvals.sign(_approver_key(args.key), approver=args.approver, workflow_id=f"autonomy-{args.environment}",
                            plan_hash=state["plan_hash"], tier="T3")
    await handle.signal(AutonomyWorkflow.enable, signed)
    problems = await handle.result()
    for problem in problems:
        _out(f"not enabled: {_one(problem)}")
    if not problems:
        _out(f"autonomy in {args.environment} is enabled again, signed by {args.approver} and recorded")
    return 1 if problems else 0


def _enrol_command(args: argparse.Namespace) -> int:
    """A link for enrolling a passkey on the approval page, signed here with the approver's own key - and opened in
    this machine's browser, never printed: whoever holds the link may use it, and a terminal is an egress (_out)."""
    import webbrowser

    from .approval_page import invite

    domain = os.environ.get("WARDEN_APPROVAL_RP_ID", "").strip()
    if not domain:
        _out("error: WARDEN_APPROVAL_RP_ID is not set: the approval page's domain", err=True)
        return 1
    if not webbrowser.open(f"https://{domain}/e/{invite(_approver_key(args.key), args.approver, now=datetime.now(UTC))}"):
        _out("error: no browser could be opened on this machine", err=True)
        return 1
    _out(f"Opened https://{domain} in your browser: create the passkey there within 15 minutes.")
    return 0


def _install_log_gate() -> None:
    """The worker: every record at INFO and above, through the gate (installed for every command in
    `_main` already; the worker also wants temporalio's INFO lines)."""
    import logging

    from .observability import install_log_gate

    install_log_gate(logging.INFO)


# Every catalogue platform the AWS platform carries out (review 2026-10-10, M1: sqs, athena and apigw were missing, so
# their plans could never be made). tests/test_actions_g9d.py holds it to the AWS platform's own entries.
AWS_PLATFORMS = ("lambda", "events", "dynamodb", "ecs", "rds", "sqs", "athena", "apigw", "elb", "appconfig", "codepipeline",
                 "ec2", "asg", "kms", "secretsmanager", "kinesis")


PLATFORM_KINDS = ("k8s", "db", "aws")


def _platform_choice(value: str) -> frozenset[str]:
    """`none`, `all`, or a comma-separated list of PLATFORM_KINDS (`aws,k8s`)."""
    if value == "none":
        return frozenset()
    kinds = frozenset(PLATFORM_KINDS) if value == "all" else frozenset(v.strip() for v in value.split(","))
    if not kinds or not kinds <= set(PLATFORM_KINDS):
        raise argparse.ArgumentTypeError(f"{value!r}: none, all, or a list of {', '.join(PLATFORM_KINDS)}")
    return kinds


def _platform(choice: str | frozenset[str]):
    """The platforms a worker connects (decision D16). Locally, building one reads its credentials now, so a worker
    that cannot reach what it was told to change fails at start, not in the middle of an approved fix. In the cloud
    runtime (WARDEN_AWS_ROLE_ARN_TEMPLATE set) Kubernetes and the database are each watched environment's own, reached
    through that environment's roles when a plan names it: an environment without an EKS cluster or a database
    configured reads and changes nothing there, and its plans go to a person."""
    from .platforms import RoutedPlatform

    kinds = _platform_choice(choice) if isinstance(choice, str) else choice
    if not kinds:
        return None
    cloud = bool(os.environ.get("WARDEN_AWS_ROLE_ARN_TEMPLATE", "").strip())
    platforms = {}
    if "k8s" in kinds:
        from .platforms.k8s import KubernetesPlatform, eks_from_environment

        platforms["k8s"] = eks_from_environment() if cloud else KubernetesPlatform()
    if "db" in kinds:
        from .platforms.db import DatabasePlatform, db_from_environment

        platforms["db"] = db_from_environment() if cloud else DatabasePlatform()
    if "aws" in kinds:
        from .platforms.aws import from_environment

        aws = from_environment()
        platforms.update(dict.fromkeys(AWS_PLATFORMS, aws))
    return RoutedPlatform(**platforms)


async def _workflow_command(args: argparse.Namespace) -> int:
    from . import discuss, runtime

    zones: tuple[str, ...] = ()
    if args.cmd == "worker":
        from .settings import by_environment

        try:  # each environment's own channels: a malformed map refuses to start, never routes a guess
            by_environment("WARDEN_SLACK_CHANNELS")
            discuss.channels()
            # B35: the core zone's beat vouches for every deployed zone; a zone WARDEN does not have refuses to start.
            zones = runtime.heartbeat_zones() if args.zone == "core" else ()
        except ValueError as exc:
            _out(f"error: {exc}", err=True)
            return 1
    client = await runtime.connect()
    if args.cmd == "worker":
        _install_log_gate()
        policy = runtime.approver_policy()
        platform = _platform(args.platform)
        async with runtime.serving(client, zone=args.zone, log=runtime.open_audit(), policy=policy,
                                   backend=resolve_backend(), platform=platform):
            if args.zone not in ("all", "core"):  # a zone's activities only: no workflow to time or beat through
                _out(f"worker running the {args.zone} zone on task queue {runtime.zone_queue(args.zone)!r}; "
                     "Ctrl+C to stop")
                shadow = runtime.cloudwatch_publisher(runtime.SYNTHETIC_METRIC) if args.zone == "llm" else None
                if shadow is not None:  # register C13: the daily shadow incident runs where the model is
                    await runtime.synthetic_loop(shadow, log=lambda line: _out(line, err=True))
                if args.zone == "notify" and discuss.configured():  # the discussion channel's listener (discuss.py)
                    _out("listening in the discussion channel", err=True)
                    try:
                        await discuss.listen(client, task_queue=runtime.TASK_QUEUE)
                    except Exception as exc:  # noqa: BLE001 - the alerts this worker sends never wait on the discussion
                        _out(f"the discussion channel's listener stopped ({type(exc).__name__}); alerts go on", err=True)
                await asyncio.Event().wait()
                return 0
            problem = await runtime.check_clock(client)
            if problem:
                _out(f"error: {problem}", err=True)
                return 1
            _out(f"worker running on task queue {runtime.TASK_QUEUE!r} (platforms: {','.join(sorted(args.platform)) or 'none'}); "
                 "Ctrl+C to stop")
            publish = runtime.cloudwatch_publisher()
            if publish is None:
                await asyncio.Event().wait()
            else:  # register C13: a beat only while a full round trip works; the alarm on silence is outside WARDEN
                await runtime.heartbeat(client, publish, log=lambda line: _out(line, err=True),
                                        shadow=runtime.cloudwatch_publisher(runtime.SYNTHETIC_METRIC)
                                        if args.zone == "all" else None, zones=zones)
    if args.cmd == "intake":
        from . import intake

        event = intake.AlarmEvent.model_validate_json(args.event.read_text(encoding="utf-8"))
        decision = await intake.submit(client, event, runtime.open_audit())
        _out(f"{decision.action}: {decision.workflow_id or '-'} - {_one(decision.reason)}")
        return 0
    if args.cmd == "status":
        stage, plan = await runtime.status(client, args.workflow_id)
        _out(f"stage: {stage}")
        if plan:
            from . import catalog

            for change in catalog.change_of(plan.entry, plan.params, plan.snapshot):
                _out(f"change: {_one(change)}")
            _out(f"plan : {_one(plan.entry)} {plan.params} tier {plan.tier}")
            _out(f"target: {_one(plan.target)}")
            _out(f"where: {_one(plan.snapshot.get('server') or 'not stated by the platform')}")
            _out(f"hash : {plan.plan_hash}")
            for problem in plan.problems:
                _out(f"  refused: {problem}")
        return 0
    try:
        _out(await runtime.approve(client, args.workflow_id, plan_hash=args.plan_hash,
                                    key=_approver_key(args.key), approver=args.approver,
                                    typed_target=args.target))
    except ValueError as exc:
        _out(f"not approved: {exc}")
        return 1
    return 0


def usage_by_day(log, since) -> list[dict]:
    """Audit row CW3: what WARDEN spent on the model, per UTC day - incidents, calls, tokens, USD - from the
    incident.llm_spend rows. Tokens are the part of WARDEN's environmental footprint WARDEN can measure itself."""
    days: dict[str, dict] = {}
    for e in log.entries(kinds=("incident.llm_spend",), since=since):
        b, day = e["body"], e["at"].date().isoformat()
        d = days.setdefault(day, {"day": day, "incidents": set(), "calls": 0, "input_tokens": 0, "output_tokens": 0,
                                  "usd": 0.0})
        d["incidents"].add(e["correlation_id"])
        d["calls"] += int(b.get("calls", 0))
        d["input_tokens"] += int(b.get("input_tokens", 0))
        d["output_tokens"] += int(b.get("output_tokens", 0))
        d["usd"] += float(b.get("usd", 0.0))
    return [{**d, "incidents": len(d["incidents"])} for _, d in sorted(days.items())]


def _usage_command(args: argparse.Namespace) -> int:
    from datetime import UTC, datetime, timedelta

    from . import audit, runtime

    log = audit.AuditLog(runtime.audit_target())
    rows = usage_by_day(log, datetime.now(UTC) - timedelta(days=args.days))
    for r in rows:
        _out(f"{r['day']}  incidents {r['incidents']:>4}  calls {r['calls']:>5}  tokens in {r['input_tokens']:>9} "
             f"out {r['output_tokens']:>8}  USD {r['usd']:.4f}")
    if not rows:
        _out(f"no model use recorded in the last {args.days} day(s)")
    return 0


def _offer_again_command(args: argparse.Namespace) -> int:
    """Item 11: a fix that did not hold is offered again only after an approver signs that it may be - each fix of
    this incident that is still held back, whether its alarm came back in the soak or a re-check failed."""
    from . import approvals, history, runtime

    log = runtime.open_audit()
    held, elsewhere = [], 0
    for entry, target in history.failed_in(log, args.incident):
        by = history.did_not_hold(log, entry, target)[0]
        if by and by != args.incident:
            # Its latest failure is another incident's (CodeRabbit, PR 43): that one is read and cleared by name.
            _out(f"`{entry}` on `{target}` is held back by a later failure, in incident {by}: read it, then run "
                 f"`warden offer-again {by}`", err=True)
            elsewhere += 1
        elif by:
            held.append((entry, target))
    if not held:
        if not elsewhere:
            _out(f"nothing to clear: no fix of {args.incident} is held back as not holding", err=True)
        return 1
    key, policy = _approver_key(args.key), runtime.approver_policy()
    for entry, target in held:
        failed_at = max(history.failures(log, entry, target))[0]
        signed = approvals.sign(key, approver=args.approver, workflow_id=history.OFFER_AGAIN_WORKFLOW,
                                plan_hash=history.offer_again_hash(entry, target, failed_at), tier="T2")
        problems = history.offer_again(log, signed, policy=policy, entry=entry, target=target)
        if problems:
            _out(f"`{entry}` on `{target}` not cleared: " + "; ".join(problems), err=True)
            return 1
        _out(f"`{entry}` on `{target}` may be offered again; every plan still waits for an approval")
    return 1 if elsewhere else 0


def _label_command(args: argparse.Namespace) -> int:
    """Audit A-P-2: the approver's signed verdict on a diagnosis and its action, recorded for calibration."""
    from . import labels, runtime

    policy = runtime.approver_policy()
    label = labels.sign(_approver_key(args.key), incident_id=args.incident, approver=args.approver,
                        diagnosis=args.diagnosis, action=args.action, note=args.note or "")
    problems = labels.record(runtime.open_audit(), label, policy)
    if problems:
        _out("label not recorded: " + "; ".join(problems), err=True)
        return 1
    _out(f"label recorded for {args.incident}: diagnosis {args.diagnosis}, action {args.action}")
    return 0


def _link_command(args: argparse.Namespace) -> int:
    """Item 16a: an approver's signed, two-way link between two incidents' records (links.py)."""
    from . import links, runtime

    link = links.sign(_approver_key(args.key), incident=args.incident, other=args.other, type=args.type,
                      approver=args.approver, note=args.note or "", removed=args.remove)
    problems = links.record(runtime.open_audit(), link, runtime.approver_policy())
    if problems:
        _out("link not recorded: " + "; ".join(problems), err=True)
        return 1
    _out(f"{'link removed' if args.remove else 'linked'}: {args.incident} {links.WORDS[args.type]} {args.other}")
    return 0


def _killswitch_command(args: argparse.Namespace) -> int:
    from . import approvals, bounds, runtime

    # Live, 2026-10-16: with the cloud runtime's approval page configured and no audit DSN, `on` wrote this machine's
    # own audit file and printed ON while the cloud kept applying. The cloud's switch is reached only on the page.
    cloud = bool(os.environ.get("WARDEN_APPROVAL_RP_ID", "").strip()) and not os.environ.get("WARDEN_AUDIT_DSN", "").strip()
    if cloud and args.kill_cmd in ("status", "reset"):
        _out("error: this machine does not reach the cloud runtime's audit. `warden killswitch link` shows why the "
             "switch is on and resets it on the approval page.", err=True)
        return 1
    if args.kill_cmd == "on" and cloud:
        import webbrowser

        from .approval_page import STOP_INVITE, invite

        if not args.approver or not args.key:
            _out("error: --approver and --key are needed: the stop is signed on the approval page", err=True)
            return 1
        token = invite(_approver_key(args.key), args.approver, now=datetime.now(UTC), purpose=STOP_INVITE)
        domain = os.environ["WARDEN_APPROVAL_RP_ID"].strip()
        if not webbrowser.open(f"https://{domain}/x/{token}"):
            _out("error: no browser could be opened on this machine", err=True)
            return 1
        _out(f"Opened https://{domain} in your browser: say why, then stop WARDEN there with your passkey.")
        return 0
    if args.kill_cmd == "on" and not args.reason:
        _out("error: --reason is needed", err=True)
        return 1
    if args.kill_cmd == "link":
        # The cloud runtime's switch: its audit is reached by the approval page, not by this machine. A link signed
        # here with the approver's own key, opened in the browser and never printed (as `warden enrol`).
        import webbrowser

        from .approval_page import RESET_INVITE, invite

        domain = os.environ.get("WARDEN_APPROVAL_RP_ID", "").strip()
        if not domain:
            _out("error: WARDEN_APPROVAL_RP_ID is not set: the approval page's domain", err=True)
            return 1
        token = invite(_approver_key(args.key), args.approver, now=datetime.now(UTC), purpose=RESET_INVITE)
        if not webbrowser.open(f"https://{domain}/k/{token}"):
            _out("error: no browser could be opened on this machine", err=True)
            return 1
        _out(f"Opened https://{domain} in your browser: read why the switch is on, then reset it there.")
        return 0
    log = runtime.open_audit()
    if args.kill_cmd == "on":
        bounds.trip(log, "operator", args.reason)
    elif args.kill_cmd == "reset":
        if bounds.killswitch(log) is None:
            _out("the kill switch is not on")
            return 0
        # Every trip is shown BEFORE anything is signed, and the approver states how many they reviewed: the
        # signature covers exactly those (register R9-O4).
        shown = bounds.trips(log)
        _out(f"resetting {len(shown)} trip{'s' if len(shown) != 1 else ''}:")
        for row in shown:
            _out(f"  - {_one(row['body']['reason'])}")
        if args.trips != len(shown):
            _out(f"not reset: you reviewed {args.trips}, there are {len(shown)}; check them and pass --trips "
                 f"{len(shown)}")
            return 1
        policy = runtime.approver_policy()
        signed = approvals.sign(_approver_key(args.key), approver=args.approver, workflow_id="killswitch",
                                plan_hash=bounds.trips_hash(log), tier="T3")
        problems = bounds.reset(log, signed, policy=policy, now=datetime.now(UTC))
        for problem in problems:
            _out(f"not reset: {problem}")
        if problems:
            return 1
    on = bounds.trips(log)
    if not on:
        _out("kill switch: off")
        return 0
    # Every trip since the last reset: a reset is signed for the latest, and the approver must have seen them all.
    _out(f"kill switch: ON ({len(on)} trip{'s' if len(on) != 1 else ''} since the last reset)")
    for row in on:
        _out(f"  - {_one(row['body']['reason'])}")
    return 0


def _no_controls(value):
    if isinstance(value, str):
        return gate.strip_controls(value)
    if isinstance(value, list):
        return [_no_controls(v) for v in value]
    if isinstance(value, dict):
        return {_no_controls(k): _no_controls(v) for k, v in value.items()}
    return value


class _Parser(argparse.ArgumentParser):
    """argparse writes a bad argument back to stderr raw - an escape sequence, or a key typed on the command line
    (sixth review NEW-3, seventh review). Its error becomes SystemExit text, which main() prints through the gate
    like every other error; the usage line holds nothing typed and is printed as argparse does."""

    def error(self, message: str):  # type: ignore[override]
        self.print_usage(sys.stderr)
        raise SystemExit(f"{self.prog}: {message}")


def main(argv: list[str] | None = None) -> int:
    """The CLI. An uncaught error is printed as one gated line, never as a raw traceback: the error
    text can quote evidence, a key or an escape sequence (independent review 2026-09-28)."""
    from .observability import exit_message

    try:
        return _main(argv)
    except SystemExit as exc:
        # A message Python would print raw - an --alert file's content, or a tuple or exception (fifth
        # review, 2026-10-01).
        message = exit_message(exc.code)
        if message is not None:
            _out(f"error: {_one(message)}", err=True)
            return 2
        raise
    except KeyboardInterrupt:
        raise
    except Exception as exc:  # noqa: BLE001 - the last line of defence for what reaches the terminal
        _out(f"error: {type(exc).__name__}: {_one(exc)}", err=True)
        return 1


def _main(argv: list[str] | None = None) -> int:
    # ⛔ Never crash while REPORTING. On Windows a piped stdout is cp1252 and cannot encode `→`,
    # which the model writes into its own hypotheses - so printing a successful diagnosis raised
    # UnicodeEncodeError and turned it into a failed run. `replace` shows a `?` in the terminal
    # instead; the JSON report is written in UTF-8 regardless, so nothing is lost there. The
    # encoding itself is deliberately left alone: a caller decoding this output as the platform
    # default keeps working.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):  # not a TextIOWrapper, e.g. under a test capture
            pass
    from .observability import install_log_gate

    install_log_gate()  # before anything can log: no raw last-resort handler for any command
    parser = _Parser(prog="warden", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="run one incident through the graph")
    source = p_run.add_mutually_exclusive_group()
    source.add_argument("--incident", default="inc-001", help="one of the bundled incident fixtures")
    source.add_argument("--alert", default=None, metavar="PATH", help="read the alert from a YAML file instead of using a bundled incident")
    p_run.add_argument("--verbose", action="store_true")
    p_run.add_argument("--max-usd", type=float, default=0.50)
    # Opt-in reporting. Off by default, so the plain `run` output is unchanged.
    p_run.add_argument("--report", action="store_true", help="build + print the redacted markdown report")
    p_run.add_argument("--environment", default=None, help="override the incident's environment (e.g. prod) to see the per-env gate")
    # Overrides that let a BUNDLED incident shape be pointed at a REAL system. Without them the
    # demo alerts cannot be used outside the fixtures: their `started_at` is a fixed date in the
    # past, so a backend that reads a window around it (AWS) reads an EMPTY window and reports
    # nothing — which is indistinguishable from a healthy service.
    p_run.add_argument("--service", default=None, help="override the service the alert points at, e.g. the real ECS service name")
    p_run.add_argument("--started-at", default=None, metavar="WHEN", help="override when the alert fired: an ISO-8601 timestamp, or 'now'")
    p_run.add_argument("--label", action="append", default=[], metavar="K=V", help="add an alert label; repeatable (e.g. --label cluster=prod)")
    p_run.add_argument("--json", default=None, metavar="PATH", help="also write the full report as JSON to PATH — an audit artefact, not just terminal output")

    p_demo = sub.add_parser("demo", help="run every bundled incident")
    p_demo.add_argument("--verbose", action="store_true")

    p_audit = sub.add_parser("audit", help="the tamper-evident audit log: create a signing key, verify a log")
    audit_sub = p_audit.add_subparsers(dest="audit_cmd", required=True)
    p_keygen = audit_sub.add_parser("keygen", help="create an Ed25519 signing key pair (the private key encrypted), inside WARDEN_KEY_DIR "
                                                      "(default ~/.warden) only")
    p_keygen.add_argument("--private", required=True, type=pathlib.Path)
    p_keygen.add_argument("--public", required=True, type=pathlib.Path)
    p_keygen.add_argument("--unencrypted", action="store_true",
                          help="write the private key in the clear (refused otherwise without a passphrase)")
    p_show = audit_sub.add_parser("show", help="one incident's rows and their hashes, after verifying the chain")
    p_show.add_argument("incident")
    p_show.add_argument("--db", type=pathlib.Path, help="a SQLite audit file (or set WARDEN_AUDIT_DSN)")
    p_show.add_argument("--public-key", required=True, type=pathlib.Path)
    p_verify = audit_sub.add_parser("verify", help="recompute the hash chain and check every signature")
    p_verify.add_argument("--db", type=pathlib.Path, help="a SQLite audit file (or set WARDEN_AUDIT_DSN)")
    p_verify.add_argument("--public-key", required=True, type=pathlib.Path)
    p_verify.add_argument("--anchor-bucket", help="the S3 Object Lock bucket the checkpoints are anchored in (S12)")
    p_migrate = audit_sub.add_parser("migrate", help="create the PostgreSQL audit tables (migration role only)")
    p_migrate.add_argument("--writer-role", required=True, help="the runtime's database role: SELECT and INSERT only")

    p_worker = sub.add_parser("worker", help="run the workflow worker against the Temporal server")
    p_worker.add_argument("--platform", type=_platform_choice, default="none",
                          help="what this worker may change, behind a signed approval: none (default - every "
                               "remediation is refused), k8s (WARDEN_K8S_NAMESPACE), db (WARDEN_DB_TERMINATE_DSN, "
                               "WARDEN_DB_APP_USERS), aws, a comma-separated list of those, or all")
    p_worker.add_argument("--zone", choices=("all", "core", "read", "llm", "notify", "act", "critic"), default="all",
                          help="the trust zone this process serves (register S15): core runs the workflows and the "
                               "audit's steps, read/llm/notify/act only that zone's activities with only its "
                               "credentials; all runs every zone in one process (default)")
    p_intake = sub.add_parser("intake", help="hand one alarm event to intake: start, group, escalate or ignore it")
    p_intake.add_argument("event", type=pathlib.Path, help="an alarm event, JSON (warden.intake.AlarmEvent)")
    p_status = sub.add_parser("status", help="show a remediation workflow's stage and plan (with its hash)")
    p_status.add_argument("workflow_id")
    p_approve = sub.add_parser("approve", help="sign and send an approval of the plan you reviewed")
    p_approve.add_argument("workflow_id")
    p_approve.add_argument("--plan-hash", required=True, help="the hash `warden status` showed you")
    p_approve.add_argument("--approver", required=True)
    p_approve.add_argument("--key", required=True, type=pathlib.Path, help="your Ed25519 private key (PEM)")
    p_approve.add_argument("--target", help="for T2 and T3: the plan's target, typed as `warden status` shows it")
    p_enrol = sub.add_parser("enrol", help="open the approval page's 15-minute link for enrolling your passkey")
    p_enrol.add_argument("--approver", required=True)
    p_enrol.add_argument("--key", required=True, type=pathlib.Path, help="your Ed25519 private key (PEM)")
    p_kill = sub.add_parser("killswitch", help="stop every remediation, or reset the stop with a signed approval")
    kill_sub = p_kill.add_subparsers(dest="kill_cmd", required=True)
    kill_sub.add_parser("status")
    p_on = kill_sub.add_parser("on", help="stop every automatic fix (in the cloud runtime: on the approval page)")
    p_on.add_argument("--reason", help="why (this machine's own audit; on the approval page you type it there)")
    p_on.add_argument("--approver", help="you, for the cloud runtime's stop link")
    p_on.add_argument("--key", type=pathlib.Path, help="your Ed25519 private key (PEM), for the stop link")
    p_link = kill_sub.add_parser("link", help="open the approval page's reset of the cloud runtime's kill switch")
    p_link.add_argument("--approver", required=True)
    p_link.add_argument("--key", required=True, type=pathlib.Path, help="your Ed25519 private key (PEM)")
    p_reset = kill_sub.add_parser("reset")
    p_reset.add_argument("--approver", required=True)
    p_reset.add_argument("--key", required=True, type=pathlib.Path)
    p_reset.add_argument("--trips", required=True, type=int, help="how many trips you reviewed (`warden killswitch status`)")

    p_auto = sub.add_parser("autonomy", help="see an environment's demotions, or re-enable its autonomy (signed, T3)")
    auto_sub = p_auto.add_subparsers(dest="autonomy_cmd", required=True)
    p_astatus = auto_sub.add_parser("status")
    p_astatus.add_argument("--environment", required=True)
    p_enable = auto_sub.add_parser("enable", help="after a demotion: Eldane approves alone again (never in prod)")
    p_enable.add_argument("--environment", required=True)
    p_enable.add_argument("--approver", required=True)
    p_enable.add_argument("--key", required=True, type=pathlib.Path, help="your Ed25519 private key (PEM)")
    p_enable.add_argument("--demotions", required=True, type=int,
                          help="how many demotions you reviewed (`warden autonomy status`)")

    p_usage = sub.add_parser("usage", help="model calls, tokens and cost per day, from the audit")
    p_usage.add_argument("--days", type=int, default=30)
    p_link = sub.add_parser("link", help="link two incidents' records, signed: a similar incident then finds the proven fix")
    p_link.add_argument("incident")
    p_link.add_argument("other")
    p_link.add_argument("--as", dest="type", required=True, choices=("same-root-cause", "recurrence-of", "caused-by"),
                        help="read as: <incident> has the same root cause as / is a recurrence of / was caused by <other>")
    p_link.add_argument("--note", help="optional, up to 500 characters")
    p_link.add_argument("--remove", action="store_true", help="take this link back")
    p_link.add_argument("--approver", required=True)
    p_link.add_argument("--key", required=True, type=pathlib.Path, help="your Ed25519 private key (PEM)")
    p_label = sub.add_parser("label", help="record your signed verdict on an incident's diagnosis and action")
    p_label.add_argument("incident")
    p_label.add_argument("--diagnosis", required=True, choices=("right", "wrong", "unsure"))
    p_label.add_argument("--action", required=True, choices=("right", "wrong", "unsure"))
    p_label.add_argument("--note", help="optional, up to 500 characters")
    p_label.add_argument("--approver", required=True)
    p_label.add_argument("--key", required=True, type=pathlib.Path, help="your Ed25519 private key (PEM)")
    p_again = sub.add_parser("offer-again", help="let WARDEN offer again a fix that did not hold (your signed decision)")
    p_again.add_argument("incident")
    p_again.add_argument("--approver", required=True)
    p_again.add_argument("--key", required=True, type=pathlib.Path, help="your Ed25519 private key (PEM)")

    args = parser.parse_args(argv)
    _load_environment("label" if args.cmd == "link" else args.cmd, getattr(args, "zone", None))  # after parsing: what is loaded depends on the command (audit A-B-L17)
    if args.cmd == "audit":
        return _audit_command(args)
    if args.cmd in ("worker", "intake", "status", "approve"):
        return asyncio.run(_workflow_command(args))
    if args.cmd == "enrol":
        return _enrol_command(args)
    if args.cmd == "killswitch":
        return _killswitch_command(args)
    if args.cmd == "link":
        return _link_command(args)
    if args.cmd == "label":
        return _label_command(args)
    if args.cmd == "offer-again":
        return _offer_again_command(args)
    if args.cmd == "autonomy":
        return asyncio.run(_autonomy_command(args))
    if args.cmd == "usage":
        return _usage_command(args)

    # Evidence source is a deployment decision, like the model provider. WARDEN_BACKEND=k8s reads a
    # live cluster; the default reads the recorded fixtures so CI never needs one.
    backend = resolve_backend()

    if args.cmd == "run":
        alert = _alert_from_file(args.alert) if args.alert else _alert_from(args.incident)
        alert = _apply_overrides(alert, args)
        llm = LLMClient(max_usd=args.max_usd)
        report = run(alert, llm=llm, backend=backend)
        # ⛔ The artefact FIRST, the terminal second. This printed first, and printing crashed: the
        # model writes `→` into its hypothesis, stdout was a cp1252 pipe, and UnicodeEncodeError
        # killed the process - after the whole diagnosis had succeeded, and before the JSON report
        # was written, so the result was lost and a benchmark run recorded as ERROR. The report is
        # the audit record; a failure to DISPLAY it must never be able to destroy it.
        if args.json:
            path = _contained(args.json, "--json")
            path.parent.mkdir(parents=True, exist_ok=True)
            # Redacted once more with the run's own map (audit A-C-8): the artefact gets attached
            # to tickets, and a value an upstream step missed must not ride along.
            raw = report.model_dump(mode="json")
            data, _ = _scrub(raw, dict(report.redaction_map))
            data = _no_controls(data)  # `jq -r` would print an ESC live again
            # Checked BEFORE the scrub too (review 2A defect 7): after it, every value is already
            # masked, so a check there alone could never fire on a value an upstream step missed.
            leaks = sorted(set(gate.data_leaks(raw)) | set(gate.data_leaks(data)))
            if leaks:  # an upstream miss: the artefact is refused, not written with a secret in it
                _out(f"report NOT written: the outbound gate found {', '.join(leaks)} in it", err=True)
                return 3
            path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        _print_report(report, verbose=args.verbose)
        if args.json:
            _out(f"\nreport written to {path}")

        if args.report:
            _print_markdown_report(alert, report)
        return 0

    for incident in DEMO_ALERTS:
        report = run(_alert_from(incident), llm=LLMClient(), backend=backend)
        _print_report(report, verbose=args.verbose)
    # A13 (2026-10-16): it ended "a human executes" - WARDEN applies approved plans itself (D16).
    _out("\nNo action was executed. WARDEN proposes and gates; a change runs only as a fix plan an approver "
         "approved.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
