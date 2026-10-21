"""B3 (owner, 2026-10-17): Eldane reviews dev's saved Terraform plan - a deterministic shape policy first, then its
review of the redacted plan beside a planted bad one - and may approve exactly that plan (its sha256, run id, commit,
stack, environment) in _infra-deploy.yml's eldane-apply. Dev only: prod always needs a person. Each guard here has a
test that fails when the guard is removed (plant checks in the PR)."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest
import yaml

import fakes
from warden import approvals, plan_review, plan_shape
from warden.providers import Completion

ROOT = pathlib.Path(__file__).resolve().parents[1]
FLOWS = ROOT / ".github" / "workflows"
AWS = "registry.terraform.io/hashicorp/aws"
BOUND = {"environment": "dev", "stack": "fullstack", "run_id": "1234567", "sha256": "ab" * 32, "commit": "cd" * 20}


def _rc(address, actions, *, before=None, after=None, provider=AWS, mode="managed", unknown=None):
    rtype = address.split(".")[1 if address.startswith("data.") else 0]
    return {"address": address, "mode": mode, "type": rtype, "name": address.rsplit(".", 1)[-1], "provider_name": provider,
            "change": {"actions": actions, "before": before, "after": after, "after_unknown": unknown or {}}}


def _plan(*changes):
    return {"format_version": "1.2", "resource_changes": list(changes)}


ROUTINE = _plan(_rc("aws_lambda_function.orders", ["update"], before={"memory_size": 128, "timeout": 3},
                    after={"memory_size": 256, "timeout": 3}),
                _rc("aws_cloudwatch_event_rule.nightly", ["create"], after={"name": "nightly"}),
                _rc("aws_s3_bucket.reports", ["no-op"]),
                _rc("data.aws_caller_identity.me", ["read"], mode="data"))


class Model:
    """A Claude stand-in that agrees with a plan unless the plan holds a planted change; every question kept."""

    def __init__(self, *, yes_to_planted=False, real=None):
        self.asked, self.yes_to_planted, self.real = [], yes_to_planted, real

    def complete(self, *, system, user, schema=None):
        self.asked.append((system, user))
        planted = any(rtype in user for _, _, rtype in plan_review.PLANTS)
        if planted and not self.yes_to_planted:
            first = user.split("<<CHANGES>>")[1].split("]")[0].strip("\n[")
            return Completion(json.dumps({"agree": False, "reasons": [{"text": "it deletes or changes access",
                                                                       "evidence": [first]}]}), 10, 10)
        reply = self.real or {"agree": True, "reasons": [{"text": "a routine update", "evidence": ["R1"]}]}
        return Completion(json.dumps(reply), 10, 10)


def _review(plan=ROUTINE, model=None, **over):
    return plan_review.review(plan, provider=model if model is not None else Model(), critic="anthropic/test",
                              chance=lambda n: 0, **{**BOUND, **over})


# ----------------------------------------------------------------------------- the shape policy

@pytest.mark.parametrize(("address", "actions"), [
    ("aws_iam_role_policy.app", ["update"]),
    ("aws_iam_role.app", ["create"]),
    ("aws_sqs_queue_policy.orders", ["update"]),
    ("aws_vpc_security_group_ingress_rule.alb", ["create"]),
    ("aws_eks_access_entry.ops", ["delete"]),
    ("aws_dynamodb_table.carts", ["delete"]),
    ("aws_dynamodb_table.carts", ["delete", "create"]),
    ("aws_elasticache_replication_group.cache", ["create", "delete"]),
    ("aws_secretsmanager_secret.db", ["forget"]),
    ("aws_subnet.private", ["delete"]),
    ("aws_nat_gateway.main", ["delete", "create"]),
    ("aws_lb.alb", ["delete"]),
    ("aws_cloudwatch_metric_alarm.orders_5xx", ["delete"]),
    ("aws_ecs_service.orders", ["delete"]),
    ("aws_eks_cluster.main", ["delete", "create"]),
])
def test_access_changes_and_removals_of_data_network_or_platform_go_to_a_person(address, actions):
    shape = plan_shape.check(_plan(_rc(address, actions)))
    assert len(shape.problems) == 1
    assert address in shape.problems[0]


@pytest.mark.parametrize(("address", "actions"), [
    ("aws_dynamodb_table.carts", ["update"]),
    ("aws_subnet.private", ["create"]),
    ("aws_lb_listener.http", ["update"]),
    ("aws_lambda_function.orders", ["update"]),
    ("aws_lambda_alias.live", ["delete"]),
    ("aws_cloudwatch_metric_alarm.orders_5xx", ["create"]),
    ("aws_ecs_task_definition.orders", ["delete", "create"]),
    ("aws_ecr_lifecycle_policy.keep", ["update"]),
])
def test_a_routine_change_has_a_shape_eldane_may_review(address, actions):
    assert plan_shape.check(_plan(_rc(address, actions))).problems == []


def test_reads_and_no_ops_are_not_changes_and_data_sources_are_ignored():
    shape = plan_shape.check(ROUTINE)
    assert [(c.address, c.action) for c in shape.changes] == [("aws_lambda_function.orders", "update"),
                                                             ("aws_cloudwatch_event_rule.nightly", "create")]
    assert shape.problems == []


def test_a_provider_these_stacks_do_not_use_or_an_unknown_action_goes_to_a_person():
    other = plan_shape.check(_plan(_rc("aws_lambda_function.orders", ["update"],
                                       provider="registry.terraform.io/someone/aws")))
    assert other.problems == ["aws_lambda_function.orders: a provider these stacks do not use"]
    unknown = plan_shape.check(_plan(_rc("aws_lambda_function.orders", ["teleport"])))
    assert "does not know" in unknown.problems[0]


def test_more_than_the_limit_of_changes_goes_to_a_person():
    many = _plan(*[_rc(f"aws_lambda_alias.a{n}", ["create"]) for n in range(plan_shape.MAX_CHANGES + 1)])
    limit = plan_shape.MAX_CHANGES
    assert plan_shape.check(many).problems == [f"{limit + 1} changes: more than {limit} in one plan go to a person"]


def test_eldane_is_shown_names_never_values_and_the_summary_is_redacted():
    """The owner's privacy rule: no model sees a real value. A plan's values (an account's ARN, a key, an email) never
    reach the summary; only attribute names do, and the text is redacted on top."""
    key = fakes.AWS_ACCESS_KEY_ID
    email = "ops" + "@" + "example.com"
    plan = _plan(_rc("aws_lambda_function.orders", ["update"],
                     before={"environment": {"KEY": "old"}, "role": "arn:aws:iam::123456789012:role/a"},
                     after={"environment": {"KEY": key}, "role": f"arn:aws:iam::123456789012:role/{email}"}),
                 _rc(f'aws_ssm_parameter.p["{email}"]', ["create"], after={"value": key}))
    text, ids = plan_shape.summary(plan_shape.check(plan).changes)
    assert ids == {"R1", "R2"}
    assert "attributes changing: environment, role" in text
    for value in (key, "123456789012", email):
        assert value not in text, value


# ----------------------------------------------------------------------------- Eldane's review

def test_eldane_approves_a_routine_dev_plan_bound_to_exactly_it():
    model = Model()
    got = _review(model=model)
    assert got.approved is True
    assert got.trial == {"test": True, "planted": "aws_dynamodb_table", "caught": True}
    assert got.label == approvals.AI_LABEL
    assert got.binding == plan_review.binding(**BOUND)
    assert [system for system, _ in model.asked] == [plan_review.SYSTEM] * 2  # the plan, then the planted one
    assert "<<CHANGES>>" in model.asked[0][1]
    assert plan_review.approval(got.to_json(), **BOUND) == []


@pytest.mark.parametrize("field", sorted(BOUND))
def test_the_approval_is_for_exactly_that_plan_and_nothing_else(field):
    got = _review()
    other = {**BOUND, field: ("prod" if field == "environment" else BOUND[field] + "0")}
    problems = plan_review.approval(got.to_json(), **other)
    assert f"{field} is not this plan's" in problems
    assert "binding is not this plan's" in problems


def test_prod_is_never_approved_and_no_model_is_asked():
    model = Model()
    got = _review(model=model, environment="prod")
    assert got.approved is False
    assert "never approved by an AI" in got.why[0]
    assert model.asked == []
    forged = json.loads(_review().to_json()) | {"environment": "prod",
                                                 "binding": plan_review.binding(**{**BOUND, "environment": "prod"})}
    assert "prod is never approved by an AI" in plan_review.approval(json.dumps(forged), **{**BOUND, "environment": "prod"})


def test_a_shape_the_policy_refuses_never_reaches_a_model():
    model = Model()
    got = _review(_plan(_rc("aws_iam_role_policy.app", ["update"])), model=model)
    assert got.approved is False
    assert model.asked == []


def test_a_yes_to_the_planted_plan_voids_its_yes_to_the_real_one():
    got = _review(model=Model(yes_to_planted=True))
    assert got.approved is False
    assert got.trial["caught"] is False


def test_a_yes_that_cites_nothing_on_the_plan_is_a_no():
    got = _review(model=Model(real={"agree": True, "reasons": [{"text": "fine", "evidence": ["R99"]}]}))
    assert got.approved is False


def test_no_model_or_a_failing_one_approves_nothing():
    assert plan_review.review(ROUTINE, provider=None, critic="", **BOUND).approved is False

    class Down:
        def complete(self, **kw):
            raise TimeoutError("no answer")
    assert _review(model=Down()).approved is False


def test_a_plan_that_changes_nothing_needs_no_model():
    model = Model()
    got = _review(_plan(_rc("aws_s3_bucket.reports", ["no-op"])), model=model)
    assert got.approved is True
    assert model.asked == []


# ----------------------------------------------------------------------------- the script the workflow runs

@pytest.fixture
def script(monkeypatch, tmp_path):
    runs = tmp_path / "runs"  # the runs folder; tmp_path itself is the "elsewhere" a test can write outside it
    runs.mkdir()
    monkeypatch.setenv("RUNNER_TEMP", str(runs))
    spec = importlib.util.spec_from_file_location("eldane_plan_review", ROOT / "scripts" / "eldane_plan_review.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["eldane_plan_review"] = mod
    spec.loader.exec_module(mod)
    (runs / "plan.json").write_text(json.dumps(ROUTINE), encoding="utf-8")
    (runs / "tfplan").write_bytes(b"the saved plan")
    monkeypatch.setattr(mod, "_critic", lambda: (Model(), "anthropic/test"))
    return mod, runs


def _args(tmp, command, **extra):
    base = ["--tfplan", str(tmp / "tfplan"), "--environment", "dev", "--stack", "fullstack", "--run-id", "42",
            "--commit", "cd" * 20]
    return [command, *base, *[x for k, v in extra.items() for x in (f"--{k}", str(v))]]


def test_the_script_approves_and_the_check_holds_it_to_the_same_file(script):
    mod, tmp = script
    assert mod.main(_args(tmp, "review", plan=tmp / "plan.json", out=tmp / "eldane.json")) == 0
    review = tmp / "eldane.json"
    assert mod.main(_args(tmp, "check", review=review)) == 0
    # The file changed after the review: its sha256 is not the one approved.
    (tmp / "tfplan").write_bytes(b"another plan")
    assert mod.main(_args(tmp, "check", review=review)) == 1


def test_the_script_says_a_person_reviews_when_eldane_does_not_approve(script, capsys):
    mod, tmp = script
    plan = tmp / "plan.json"
    plan.write_text(json.dumps(_plan(_rc("aws_iam_role.app", ["create"]))), encoding="utf-8")
    assert mod.main(_args(tmp, "review", plan=plan, out=tmp / "eldane.json")) == 3
    said = capsys.readouterr().out
    assert "apply-plan" in said
    assert "sha256" in said
    assert mod.main(_args(tmp, "check", review=tmp / "eldane.json")) == 1


def test_the_script_reads_and_writes_only_inside_the_runs_folder(script, tmp_path):
    mod, tmp = script
    (tmp_path / "elsewhere").mkdir()
    elsewhere = tmp_path / "elsewhere" / "eldane.json"
    assert mod.main(_args(tmp, "review", plan=tmp / "plan.json", out=elsewhere)) == 2
    assert not elsewhere.exists()


# ----------------------------------------------------------------------------- the workflow

def _deploy():
    return yaml.safe_load((FLOWS / "_infra-deploy.yml").read_text(encoding="utf-8"))


def _step(name):
    (step,) = [s for s in _deploy()["jobs"]["run"]["steps"] if s.get("name") == name]
    return step


def test_eldane_apply_is_refused_in_every_environment_but_dev():
    known = _step("A known action")["run"]
    assert 'case "$ACTION/$WARDEN_ENV" in eldane-apply/dev) ;; eldane-apply/*)' in known
    assert known.index("eldane-apply/*)") < known.index("exit 1 ;; esac", known.index("eldane-apply/*)"))


def test_the_review_runs_after_the_plan_is_kept_and_the_apply_checks_it_first():
    steps = [s.get("name", "") for s in _deploy()["jobs"]["run"]["steps"]]
    keep, review = steps.index("keep the plan for review (private state bucket, never a public artifact)"), steps.index(
        "Eldane reviews the saved plan (dev only)")
    apply = steps.index("apply and publish stack.json")
    assert keep < review < apply
    assert "eldane-apply" in _step("keep the plan for review (private state bucket, never a public artifact)")["if"]
    run = _step("apply and publish stack.json")["run"]
    check = run.index("scripts/eldane_plan_review.py check")
    assert check < run.index('"terraform/$STACK" apply')
    assert '"$RUNNER_TEMP/tfplan"' in run[check:check + 200]


def test_the_review_holds_no_cloud_credential_and_alone_holds_the_model_key():
    step = _step("Eldane reviews the saved plan (dev only)")
    assert step["if"] == "env.ACTION == 'eldane-apply'"
    assert step["env"]["ANTHROPIC_API_KEY"] == "${{ secrets.ELDANE_ANTHROPIC_API_KEY }}"
    assert step["env"]["SWITCH"] == "${{ vars.ELDANE_PLAN_APPROVAL }}"
    run = step["run"]
    assert '[ "$SWITCH" = on ] ||' in run  # off until the owner turns it on
    review = run.index("scripts/eldane_plan_review.py review")
    assert "for v in $(compgen -e | grep '^AWS_'); do unset \"$v\"; done" in run[:review]
    others = [s for s in _deploy()["jobs"]["run"]["steps"] if s.get("name") != step["name"]]
    assert not any("ELDANE_ANTHROPIC_API_KEY" in json.dumps(s) for s in others)


def test_only_the_deploy_dispatch_offers_it_and_no_push_runs_it():
    for env in ("dev", "prod"):
        wf = yaml.safe_load((FLOWS / f"deploy-{env}.yml").read_text(encoding="utf-8"))
        assert "eldane-apply" in wf[True]["workflow_dispatch"]["inputs"]["infra_action"]["options"]
    for env in ("dev", "prod"):
        assert "eldane-apply" not in (FLOWS / f"on-merge-{env}.yml").read_text(encoding="utf-8")
