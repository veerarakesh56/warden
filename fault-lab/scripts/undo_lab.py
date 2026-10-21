"""The undo lab's faults (terraform/undo-lab): ONE change a person could make, made as the fault-injection role - so
CloudTrail records a person's change, AWS Config records the value before it, and WARDEN has something to undo.

    python scripts/undo_lab.py status                      # every alarm and setting, read-only
    python scripts/undo_lab.py inject table_capacity       # make the change (the lab's alarm follows in minutes)
    python scripts/undo_lab.py restore table_capacity      # set it back by hand (a test WARDEN did not fix)

A fault is made only on a lab at its baseline, and a restore writes only the baseline: neither ever touches a
resource outside warden-<env>-lab-*, which is all the role's policy (iam/<env>/harness-lab.json) allows. The role is
warden-<env>-harness; the laptop's operator role may assume it and nothing else may. Region and names come from
environments.yaml and the environment's name, never from a literal.
"""

from __future__ import annotations

import argparse
import pathlib
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from warden.environments import EnvironmentPolicies
from warden.environments import names as environment_names

# Where a lab may exist: where the fault-injection role does - environments.yaml `fault_environments`, never named here.
LAB_ENVS = EnvironmentPolicies.load().fault_environments
# The baseline terraform/undo-lab/main.tf declares (tests/test_undo_lab.py holds the two equal).
WRITE_UNITS, TIMEOUT_SECONDS = 10, 30
CUT_WRITE_UNITS, CUT_TIMEOUT_SECONDS = 1, 1
IST = timezone(timedelta(hours=5, minutes=30))

Clients = Callable[[str], Any]


class NotAtBaseline(RuntimeError):
    """The lab is not as Terraform left it: a fault on top of another change would not be ONE change."""


def lab(env: str) -> dict[str, str]:
    prefix = f"warden-{env}-lab"
    return {"table": f"{prefix}-orders", "producer": f"{prefix}-producer", "consumer": f"{prefix}-consumer",
            "rule": f"{prefix}-tick", "queue": f"{prefix}-jobs"}


def _mapping(lam: Any, consumer: str) -> dict[str, Any]:
    found = lam.list_event_source_mappings(FunctionName=consumer).get("EventSourceMappings") or []
    if len(found) != 1:
        raise NotAtBaseline(f"{consumer} has {len(found)} event source mappings, not one")
    return found[0]


def _state(env: str, clients: Clients) -> dict[str, Any]:
    """Each setting a fault changes, as it is now."""
    n = lab(env)
    table = clients("dynamodb").describe_table(TableName=n["table"])["Table"]
    lam = clients("lambda")
    mapping = _mapping(lam, n["consumer"])
    return {
        "table_capacity": (table.get("ProvisionedThroughput") or {}).get("WriteCapacityUnits"),
        "read_units": (table.get("ProvisionedThroughput") or {}).get("ReadCapacityUnits"),
        "producer_concurrency": lam.get_function_concurrency(FunctionName=n["producer"]).get(
            "ReservedConcurrentExecutions"),
        "producer_timeout": lam.get_function_configuration(FunctionName=n["producer"]).get("Timeout"),
        "schedule_disabled": clients("events").describe_rule(Name=n["rule"]).get("State"),
        "consumer_disabled": mapping.get("State"),
        "mapping": mapping.get("UUID"),
    }


# fault -> (what it is, the value at the baseline, the value the fault leaves)
FAULTS: dict[str, tuple[str, Any, Any]] = {
    "table_capacity": ("the orders table's write capacity", WRITE_UNITS, CUT_WRITE_UNITS),
    "producer_concurrency": ("the producer's reserved concurrency", None, 0),
    "producer_timeout": ("the producer's timeout in seconds", TIMEOUT_SECONDS, CUT_TIMEOUT_SECONDS),
    "schedule_disabled": ("the schedule's state", "ENABLED", "DISABLED"),
    "consumer_disabled": ("the consumer's queue mapping", "Enabled", "Disabled"),
}


def _write(fault: str, value: Any, env: str, clients: Clients, state: dict[str, Any]) -> None:
    n = lab(env)
    if fault == "table_capacity":
        clients("dynamodb").update_table(TableName=n["table"], ProvisionedThroughput={
            "ReadCapacityUnits": state["read_units"], "WriteCapacityUnits": value})
    elif fault == "producer_concurrency":
        if value is None:
            clients("lambda").delete_function_concurrency(FunctionName=n["producer"])
        else:
            clients("lambda").put_function_concurrency(FunctionName=n["producer"], ReservedConcurrentExecutions=value)
    elif fault == "producer_timeout":
        clients("lambda").update_function_configuration(FunctionName=n["producer"], Timeout=value)
    elif fault == "schedule_disabled":
        events = clients("events")
        (events.enable_rule if value == "ENABLED" else events.disable_rule)(Name=n["rule"])
    else:
        clients("lambda").update_event_source_mapping(UUID=state["mapping"], Enabled=value == "Enabled")


def inject(fault: str, env: str, clients: Clients) -> str:
    """Make the fault's ONE change - only on a lab whose every setting is at its baseline."""
    what, baseline, broken = FAULTS[fault]
    state = _state(env, clients)
    off = sorted(f for f, (_, base, _) in FAULTS.items() if state[f] != base)
    if off:
        raise NotAtBaseline(f"not at its baseline ({', '.join(f'{f}={state[f]}' for f in off)}); nothing was changed")
    _write(fault, broken, env, clients, state)
    return f"{what}: {baseline} -> {broken}"


def restore(fault: str, env: str, clients: Clients) -> str:
    """Set the fault's setting back to its baseline; a setting already there is left alone."""
    what, baseline, _ = FAULTS[fault]
    state = _state(env, clients)
    if state[fault] == baseline:
        return f"{what}: already {baseline}"
    _write(fault, baseline, env, clients, state)
    return f"{what}: {state[fault]} -> {baseline}"


def status(env: str, clients: Clients) -> list[str]:
    state = _state(env, clients)
    lines = [f"{fault}: {state[fault]}" + ("" if state[fault] == base else f"  (baseline {base})")
             for fault, (_, base, _) in FAULTS.items()]
    alarms = clients("cloudwatch").describe_alarms(AlarmNamePrefix=f"warden-{env}-lab-").get("MetricAlarms") or []
    return lines + [f"alarm {a['AlarmName']}: {a['StateValue']}" for a in sorted(alarms, key=lambda a: a["AlarmName"])]


def stamp(now: datetime | None = None) -> str:
    """The moment, in both of the owner's zones."""
    now = now or datetime.now(UTC)
    return f"{now:%Y-%m-%d %H:%M:%S} UTC / {now.astimezone(IST):%H:%M:%S} IST"


def as_the_fault_role(env: str) -> Clients:
    """Clients holding a one-hour session of warden-<env>-harness, in the environment's own Region."""
    import boto3

    region = environment_names(env).region
    sts = boto3.client("sts", region_name=region)
    account = sts.get_caller_identity()["Account"]
    creds = sts.assume_role(RoleArn=f"arn:aws:iam::{account}:role/warden-{env}-harness",
                            RoleSessionName="undo-lab", DurationSeconds=3600)["Credentials"]
    session = boto3.Session(aws_access_key_id=creds["AccessKeyId"], aws_secret_access_key=creds["SecretAccessKey"],
                            aws_session_token=creds["SessionToken"], region_name=region)
    return session.client


def main(argv: list[str] | None = None, clients: Clients | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("action", choices=("status", "inject", "restore"))
    p.add_argument("fault", nargs="?", choices=sorted(FAULTS))
    p.add_argument("--env", default=LAB_ENVS[0], choices=LAB_ENVS)
    args = p.parse_args(argv)
    if args.action != "status" and not args.fault:
        p.error(f"{args.action} needs a fault: {', '.join(sorted(FAULTS))}")
    clients = clients or as_the_fault_role(args.env)
    try:
        if args.action == "status":
            print("\n".join(status(args.env, clients)))
        else:
            did = (inject if args.action == "inject" else restore)(args.fault, args.env, clients)
            print(f"{stamp()}  {args.action} {args.fault}: {did}")
    except NotAtBaseline as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
