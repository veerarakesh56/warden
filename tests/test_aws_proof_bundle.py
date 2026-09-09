"""The evidence-bundle writer, and specifically its redaction.

This file exists because the bundle is the thing that gets *published*. A run against a real
account puts a 12-digit account id into every ARN and an RDS password into the DSN, and both reach
the JSON reports. If the redaction is wrong, the failure is not a broken build — it is a credential
in a public repository, discovered by someone else.

So the tests here are adversarial about the redaction and relaxed about the prose.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "aws_proof_bundle.py"
ACCOUNT = "111122223333"


def _report(*, deploys=None, status="approved_for_human", metrics=None, tool_errors=None) -> dict:
    return {
        "alert": {
            "alert_id": "inc-002", "name": "PodOOMKilled", "severity": "high",
            "service": "checkout", "environment": "prod", "summary": "oom",
            "started_at": "2026-09-09T00:00:00+00:00", "labels": {},
        },
        "redaction_map_size": 0,
        "context": {
            "logs": ["ecs/checkout/abc allocating 900MiB cache"],
            "metrics": metrics if metrics is not None else {"tasks_running": 1.0, "tasks_desired": 2.0},
            "recent_deploys": deploys if deploys is not None else [],
            "tool_errors": tool_errors or [],
        },
        "root_cause": {"hypothesis": "container exceeds its memory limit", "confidence": 0.81},
        "proposal": {
            "action": "rollback", "target": f"arn:aws:ecs:ap-south-1:{ACCOUNT}:service/warden-pg/checkout",
            "blast_radius": "single_service", "reversible": True,
        },
        "verdict": {"status": status, "policy_ids": ["P5"], "reasons": ["a recent deploy exists"]},
        "cost": {"usd": 0.0041, "calls": 2},
        "audit": [],
    }


@pytest.fixture
def bundle(tmp_path):
    """Build a realistic run directory and return a callable that renders it."""
    reports = tmp_path / "reports"
    reports.mkdir(parents=True)

    def write(name: str, payload: dict) -> None:
        (reports / f"{name}.json").write_text(json.dumps(payload), encoding="utf-8")

    def render(*, b_verdict: str = "pass") -> str:
        (reports / "B-verdict.txt").write_text(b_verdict, encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--dir", str(tmp_path), "--account", ACCOUNT,
             "--region", "ap-south-1", "--cluster", "warden-pg-a1b2c3",
             "--service", "checkout", "--eks", "warden-pg-a1b2c3"],
            capture_output=True, text=True, check=False,
        )
        assert result.returncode == 0, result.stderr
        return (tmp_path / "PROOF.md").read_text(encoding="utf-8")

    write("A-ecs-healthy", _report(metrics={"tasks_running": 2.0, "cpu_utilization_pct": 3.4}))
    write("B-ecs-force-new-deployment", _report())
    write("C-ecs-bad-deploy", _report(deploys=[{"service": "checkout", "revision": "2"}]))
    write("D-eks", _report())
    write("E-rds", _report())
    return type("Bundle", (), {"dir": tmp_path, "reports": reports, "write": staticmethod(write), "render": staticmethod(render)})


# --------------------------------------------------------------------------- redaction


def test_the_account_id_is_gone_from_the_published_markdown(bundle):
    assert ACCOUNT not in bundle.render()


def test_the_account_id_is_gone_from_the_json_reports_themselves(bundle):
    """The JSON is the evidence people will open. Redacting only the summary would publish the
    account id in the file the summary points at."""
    bundle.render()
    for path in bundle.reports.glob("*.json"):
        assert ACCOUNT not in path.read_text(encoding="utf-8"), path.name


def test_any_twelve_digit_number_is_redacted_not_just_the_known_account(bundle):
    """A second account id can appear - a cross-account ARN, a copied error message. Redacting only
    the one passed in would miss it, and missing it once is enough."""
    bundle.write("E-rds", _report() | {"audit": [{"note": "arn:aws:iam::999988887777:role/other"}]})
    assert "999988887777" not in bundle.render()


def test_a_password_in_a_dsn_is_masked(bundle):
    leaked = _report()
    leaked["context"]["logs"] = ["connected to postgresql://warden:hunter2SUPERSECRET@db.host:5432/warden"]
    bundle.write("E-rds", leaked)
    bundle.render()
    text = (bundle.reports / "E-rds.json").read_text(encoding="utf-8")
    assert "hunter2SUPERSECRET" not in text
    assert "warden:********@" in text


def test_redaction_does_not_eat_ordinary_numbers(bundle):
    """A blunt digit filter would also destroy timestamps and metric values, and a bundle nobody
    can read is not safe, only useless."""
    text = bundle.render()
    assert "2026-09-09" in text or "ap-south-1" in text
    assert "0.81" in text


# --------------------------------------------------------------------------- honesty


def test_situation_B_reports_the_pass_when_no_deploy_was_seen(bundle):
    text = bundle.render(b_verdict="pass")
    assert "No deploy was reported" in text


def test_situation_B_reports_the_FAILURE_and_does_not_soften_it(bundle):
    """The bundle must not be able to launder a failure into a pass. If the restart was read as a
    deploy, the published file says so."""
    text = bundle.render(b_verdict="fail")
    assert "A deploy WAS reported for a restart" in text
    assert "No deploy was reported" not in text


def test_an_inconclusive_check_is_neither_a_pass_nor_a_fail(bundle):
    text = bundle.render(b_verdict="")
    assert "inconclusive" in text


def test_a_missing_situation_is_reported_as_missing_not_skipped_silently(bundle):
    (bundle.reports / "D-eks.json").unlink()
    text = bundle.render()
    assert "not run" in text


def test_the_limits_section_survives(bundle):
    """Three honest limits. If a future edit drops them the bundle starts overclaiming."""
    text = bundle.render()
    assert "What this does not prove" in text
    assert "staged" in text
    assert "public subnets" in text


def test_the_screenshot_list_warns_before_posting(bundle):
    text = bundle.render()
    assert "Before posting" in text
    assert "blur" in text.lower()


def test_the_terminal_transcript_is_redacted_too(bundle):
    """run.log carries `terraform output` and `aws ecs describe-services`, and every ECS or IAM ARN
    in them contains the account id in full. Scrubbing only PROOF.md would publish a clean summary
    beside an unredacted transcript — the same leak with an extra step."""
    log = bundle.dir / "run.log"
    log.write_text(
        f"apply complete\narn:aws:ecs:ap-south-1:{ACCOUNT}:cluster/warden-pg\n",
        encoding="utf-8",
    )
    bundle.render()
    assert ACCOUNT not in log.read_text(encoding="utf-8")


def test_plain_text_artefacts_in_reports_are_redacted(bundle):
    """`kubectl get nodes` and the stopped-task table are saved as .txt, not .json."""
    nodes = bundle.reports / "D-eks-nodes.txt"
    nodes.write_text(f"node arn:aws:eks:ap-south-1:{ACCOUNT}:nodegroup/x\n", encoding="utf-8")
    bundle.render()
    assert ACCOUNT not in nodes.read_text(encoding="utf-8")
