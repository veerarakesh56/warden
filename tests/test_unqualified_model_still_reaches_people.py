"""The runtime's SSM tf/model still named claude-sonnet-5 after it was taken off the qualified
list. Register M20 refused it, as it must - but the refusal was raised while building the model client, before any path
that tells a person, so the fs-07 incident failed and reached nobody. Now a model that cannot be built is the
rules-only diagnosis (register M19) with the reason said, and the deploy itself refuses an unqualified model."""

from __future__ import annotations

import pathlib
import re

from warden import audit
from warden.activities import IncidentActivities
from warden.cli import DEMO_ALERTS
from warden.models import Alert
from warden.providers import ProviderError

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _refused():
    raise ProviderError("anthropic claude-sonnet-5 has not passed WARDEN's replay set (register M20)")


def test_a_model_that_cannot_be_built_is_the_rules_only_diagnosis_said_plainly(tmp_path):
    log = audit.AuditLog(tmp_path / "a.db", key=None)
    acts = IncidentActivities(audit=log, llm_factory=_refused)
    pack = acts.prepare(Alert(**DEMO_ALERTS["inc-002"]))
    out = acts.diagnose(pack)
    assert out.model_unavailable.startswith("no qualified model could be used (anthropic claude-sonnet-5 has not")
    assert out.cost.calls == 0  # no model was asked
    row = log.entries(pack.alert.alert_id, kinds=("incident.diagnose",))[-1]["body"]
    assert row["degraded"].startswith("no qualified model could be used")
    verified = acts.verify(pack, out)  # the incident goes on to its report and the gate
    assert verified.verdict.status.value != "approved_for_human"


def test_the_runtime_deploy_refuses_a_model_that_is_not_qualified():
    tf = (ROOT / "terraform" / "runtime" / "main.tf").read_text(encoding="utf-8")
    assert re.search(r'yamldecode\(file\("\$\{path\.module\}/\.\./\.\./src/warden/data/providers\.yaml"\)\)\.qualified', tf)
    assert "SSM /warden/<env>/tf/model is not a qualified model" in tf
