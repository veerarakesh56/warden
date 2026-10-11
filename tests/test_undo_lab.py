"""The undo lab (terraform/undo-lab, scripts/undo_lab.py; owner 2026-10-11: prove each undo on real AWS on a small
system first). Checked offline: every name inside the prefix WARDEN's roles scope to, every role with its boundary,
each alarm reaching the resolver as the resource its undo changes, the fault script making ONE change on a lab at
its baseline and nothing anywhere else, and its role allowed nothing outside the lab."""

from __future__ import annotations

import fnmatch
import json
import pathlib
import re
import sys
from datetime import UTC, datetime

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import render_env_iam
import undo_lab

from warden import catalog, resolver, resources
from warden.models import ActionKind, Alert, RemediationProposal, Severity

TF = (ROOT / "terraform" / "undo-lab" / "main.tf").read_text(encoding="utf-8")
BLOCKS = re.findall(r'^resource "(\w+)" "(\w+)" \{\n(.*?)^\}', TF, re.DOTALL | re.MULTILINE)
ENV = "dev"


def _resolved(text: str) -> str:
    return text.replace("${local.name}", f"warden-{ENV}-lab")


def _names() -> list[tuple[str, str]]:
    out = []
    for kind, _, body in BLOCKS:
        m = re.search(r'^\s+(?:name|function_name|alarm_name)\s+= "([^"]+)"', body, re.MULTILINE)
        if m and kind != "aws_iam_role_policy":
            out.append((kind, _resolved(m.group(1))))
    return out


def test_every_name_is_inside_the_labs_prefix_and_every_role_carries_the_boundary():
    names = _names()
    assert len(names) >= 14
    assert [n for n in names if not n[1].removeprefix("/aws/lambda/").startswith(f"warden-{ENV}-lab-")] == []
    roles = [body for kind, _, body in BLOCKS if kind == "aws_iam_role"]
    assert len(roles) == 2 and all("permissions_boundary = local.permissions_boundary" in body for body in roles)
    assert "WardenEnvBoundary-${local.env}" in TF and 'Project     = "warden"' in TF


def test_the_lab_exists_only_where_its_fault_role_does():
    lab_envs = re.search(r"lab_environments = (\[[^\]]*\])", TF).group(1)
    assert tuple(json.loads(lab_envs)) == undo_lab.LAB_ENVS == render_env_iam.HARNESS_ENVS
    assert (ROOT / "iam" / ENV / "harness-lab.json").exists()
    assert not (ROOT / "iam" / "prod" / "harness-lab.json").exists()


def test_the_scripts_baseline_is_the_one_terraform_declares():
    assert int(re.search(r"write_units\s+= (\d+)", TF).group(1)) == undo_lab.WRITE_UNITS
    assert int(re.search(r"timeout_seconds\s+= (\d+)", TF).group(1)) == undo_lab.TIMEOUT_SECONDS
    work = int(re.search(r"work_seconds\s+= (\d+)", TF).group(1))
    assert undo_lab.CUT_TIMEOUT_SECONDS < work < undo_lab.TIMEOUT_SECONDS  # the cut timeout really cuts the work off
    # A throttled table slows every write: the producer stops writing in time, so the table's fault never becomes the
    # function's (seen live 2026-10-11: both alarms fired for one cut).
    writing = int(re.search(r"write_seconds\s+= (\d+)", TF).group(1))
    assert writing + work < undo_lab.TIMEOUT_SECONDS / 2 and 'os.environ["WRITE_SECONDS"]' in TF
    writes = int(re.search(r'variable "writes_per_minute".*?default\s+= (\d+)', TF, re.DOTALL).group(1))
    # One write unit serves 60 writes a minute: the cut throttles, the baseline never does.
    assert undo_lab.CUT_WRITE_UNITS * 60 < writes < undo_lab.WRITE_UNITS * 60
    for kind, resource, name in (("aws_dynamodb_table", "orders", "table"), ("aws_lambda_function", "producer", "producer"),
                                 ("aws_lambda_function", "consumer", "consumer"),
                                 ("aws_cloudwatch_event_rule", "tick", "rule"), ("aws_sqs_queue", "jobs", "queue")):
        body = next(b for k, n, b in BLOCKS if (k, n) == (kind, resource))
        declared = _resolved(re.search(r'^\s+(?:name|function_name)\s+= "([^"]+)"', body, re.MULTILINE).group(1))
        assert undo_lab.lab(ENV)[name] == declared


def _alarms() -> dict[str, dict]:
    out = {}
    for kind, _, body in BLOCKS:
        if kind != "aws_cloudwatch_metric_alarm":
            continue

        def field(name, body=body):
            return re.search(rf'^\s+{name}\s+= "?([^"\n]+)"?', body, re.MULTILINE).group(1)

        dim, ref = re.search(r"dimensions\s+= \{ (\w+) = aws_\w+\.(\w+)\.", body).groups()
        out[_resolved(field("alarm_name"))] = {
            "namespace": field("namespace"), "dimension": dim, "resource": ref, "period": int(field("period")),
            "periods": int(field("evaluation_periods")), "description": field("alarm_description")}
    return out


# alarm -> (the label the alarm's own metric gives, the lab resource it names, the undo that changes it)
UNDO = {
    "orders-write-throttles": ("dynamodb_table", "table", "dynamodb_restore_capacity"),
    "producer-throttles": ("lambda", "producer", "lambda_restore_concurrency"),
    "producer-errors": ("lambda", "producer", "lambda_restore_concurrency"),  # or lambda_restore_settings: REVERT_ALSO
    "tick-silent": ("eventbridge_rule", "rule", "events_enable_rule"),
}


def test_each_alarm_reaches_the_resolver_as_the_resource_its_undo_changes():
    alarms = _alarms()
    assert len(alarms) == 5 and all(a["period"] == 60 and a["periods"] <= 3 for a in alarms.values())
    for suffix, (label, resource, entry) in UNDO.items():
        name = f"warden-{ENV}-lab-{suffix}"
        a = alarms[name]
        target = undo_lab.lab(ENV)[resource]
        assert a["resource"] == {"table": "orders", "producer": "producer", "rule": "tick"}[resource], name
        labels = resources.labels_for([(a["namespace"], {a["dimension"]: target})])
        assert labels.get(label) == target, (name, labels)
        alert = Alert(alert_id="a1", name=name, service=target, environment=ENV, severity=Severity.high, summary="",
                      started_at="2026-10-11T00:00:00+00:00", labels={**labels, "alarm": name})
        proposal = RemediationProposal(action=ActionKind.revert_change, target=target, reasoning="r",
                                       expected_effect="e", blast_radius="single_service", reversible=True)
        asked = []

        def live(e, params, asked=asked):
            asked.append((e, dict(params)))
            return {}

        resolver.request_for(alert, proposal, live)
        assert asked and asked[0][0] == entry, (name, asked)
        assert asked[0][1][catalog.CATALOG[entry].target_param] == target
        assert resolver.no_fix_path(alert, proposal) == ""
    assert "lambda_restore_settings" in catalog.REVERT_ALSO["lambda"]


def test_no_alarm_text_names_its_cause():
    for name, a in _alarms().items():
        text = (name + " " + a["description"]).lower()
        assert not re.search(r"capacity|concurrency|timeout|disabled|suspend|cut|reserved|mapping", text), name


class Lab:
    """The lab's AWS, as much as the fault script touches."""

    def __init__(self):
        self.write, self.read, self.reserved, self.timeout = undo_lab.WRITE_UNITS, 5, None, undo_lab.TIMEOUT_SECONDS
        self.rule, self.mapping, self.calls = "ENABLED", "Enabled", []

    def __call__(self, service):
        return self

    def describe_table(self, TableName):
        return {"Table": {"ProvisionedThroughput": {"ReadCapacityUnits": self.read, "WriteCapacityUnits": self.write}}}

    def update_table(self, TableName, ProvisionedThroughput):
        self.calls.append(("update_table", TableName, ProvisionedThroughput))
        self.write = ProvisionedThroughput["WriteCapacityUnits"]

    def list_event_source_mappings(self, FunctionName):
        return {"EventSourceMappings": [{"UUID": "m-1", "State": self.mapping}]}

    def update_event_source_mapping(self, UUID, Enabled):
        self.calls.append(("update_event_source_mapping", UUID, Enabled))
        self.mapping = "Enabled" if Enabled else "Disabled"

    def get_function_concurrency(self, FunctionName):
        return {} if self.reserved is None else {"ReservedConcurrentExecutions": self.reserved}

    def put_function_concurrency(self, FunctionName, ReservedConcurrentExecutions):
        self.calls.append(("put_function_concurrency", FunctionName, ReservedConcurrentExecutions))
        self.reserved = ReservedConcurrentExecutions

    def delete_function_concurrency(self, FunctionName):
        self.calls.append(("delete_function_concurrency", FunctionName))
        self.reserved = None

    def get_function_configuration(self, FunctionName):
        return {"Timeout": self.timeout}

    def update_function_configuration(self, FunctionName, Timeout):
        self.calls.append(("update_function_configuration", FunctionName, Timeout))
        self.timeout = Timeout

    def describe_rule(self, Name):
        return {"State": self.rule}

    def disable_rule(self, Name):
        self.calls.append(("disable_rule", Name))
        self.rule = "DISABLED"

    def enable_rule(self, Name):
        self.calls.append(("enable_rule", Name))
        self.rule = "ENABLED"

    def describe_alarms(self, AlarmNamePrefix):
        return {"MetricAlarms": [{"AlarmName": AlarmNamePrefix + "tick-silent", "StateValue": "OK"}]}


N = undo_lab.lab(ENV)
WRITES = {
    "table_capacity": (("update_table", N["table"], {"ReadCapacityUnits": 5, "WriteCapacityUnits": 1}),
                       ("update_table", N["table"], {"ReadCapacityUnits": 5, "WriteCapacityUnits": 10})),
    "producer_concurrency": (("put_function_concurrency", N["producer"], 0),
                             ("delete_function_concurrency", N["producer"])),
    "producer_timeout": (("update_function_configuration", N["producer"], 1),
                         ("update_function_configuration", N["producer"], 30)),
    "schedule_disabled": (("disable_rule", N["rule"]), ("enable_rule", N["rule"])),
    "consumer_disabled": (("update_event_source_mapping", "m-1", False), ("update_event_source_mapping", "m-1", True)),
}


@pytest.mark.parametrize("fault", sorted(undo_lab.FAULTS))
def test_a_fault_is_one_change_on_a_lab_at_its_baseline_and_its_restore_writes_the_baseline_back(fault):
    assert set(WRITES) == set(undo_lab.FAULTS)
    f = Lab()
    undo_lab.inject(fault, ENV, f)
    assert f.calls == [WRITES[fault][0]]
    with pytest.raises(undo_lab.NotAtBaseline):  # a second fault on top of the first would not be ONE change
        undo_lab.inject(min(set(undo_lab.FAULTS) - {fault}), ENV, f)
    with pytest.raises(undo_lab.NotAtBaseline):
        undo_lab.inject(fault, ENV, f)
    assert f.calls == [WRITES[fault][0]]
    undo_lab.restore(fault, ENV, f)
    assert f.calls == list(WRITES[fault])
    assert "already" in undo_lab.restore(fault, ENV, f) and f.calls == list(WRITES[fault])
    assert all(line.count("(baseline") == 0 for line in undo_lab.status(ENV, f))


def test_the_command_line_refuses_without_a_fault_and_says_when_in_both_zones(capsys):
    f = Lab()
    assert undo_lab.main(["status"], clients=f) == 0 and "alarm warden-dev-lab-tick-silent: OK" in capsys.readouterr().out
    assert undo_lab.main(["inject", "schedule_disabled"], clients=f) == 0
    assert re.search(r"\d\d:\d\d:\d\d UTC / \d\d:\d\d:\d\d IST  inject schedule_disabled: .*ENABLED -> DISABLED",
                     capsys.readouterr().out)
    assert undo_lab.main(["inject", "table_capacity"], clients=f) == 1 and "refused" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        undo_lab.main(["inject"], clients=f)
    with pytest.raises(SystemExit):
        undo_lab.main(["status", "--env", "prod"], clients=f)
    assert undo_lab.stamp(datetime(2026, 10, 11, 20, 0, 0, tzinfo=UTC)) == "2026-10-11 20:00:00 UTC / 01:30:00 IST"


def test_the_fault_role_may_write_only_what_the_script_writes_and_only_in_the_lab():
    policy = json.loads((ROOT / "iam" / ENV / "harness-lab.json").read_text(encoding="utf-8"))
    writes, reads = set(), set()
    for s in policy["Statement"]:
        assert s["Effect"] == "Allow"
        actions = [s["Action"]] if isinstance(s["Action"], str) else s["Action"]
        res = [s["Resource"]] if isinstance(s["Resource"], str) else s["Resource"]
        read_only = all(re.search(r":(Describe|Get|List)", a) for a in actions)
        (reads if read_only else writes).update(actions)
        if not read_only:
            assert all(f"warden-{ENV}-lab-" in r or "event-source-mapping:*" in r for r in res), s["Sid"]
            if any("event-source-mapping" in r for r in res):
                assert f"function:warden-{ENV}-lab-*" in json.dumps(s["Condition"])
        assert not any(fnmatch.fnmatch("iam:PassRole", a) or a.endswith("*") for a in actions)
    assert writes == {"dynamodb:UpdateTable", "events:DisableRule", "events:EnableRule",
                      "lambda:DeleteFunctionConcurrency", "lambda:PutFunctionConcurrency",
                      "lambda:UpdateFunctionConfiguration", "lambda:UpdateEventSourceMapping"}
    assert reads == {"dynamodb:DescribeTable", "events:DescribeRule", "lambda:GetFunctionConcurrency",
                     "lambda:GetFunctionConfiguration", "cloudwatch:DescribeAlarms", "lambda:ListEventSourceMappings"}
