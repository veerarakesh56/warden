"""Register M23: non-English logs miss the English vocabulary. Measured here on translations of a bundled incident:
code-shaped evidence (OOMKilled, key=value facts) carries the diagnosis in any language; a failure told only in
prose is missed, and then the incident goes unrecognised (P24) - so WARDEN says when the logs are not English."""

from __future__ import annotations

import pytest

from warden.cli import DEMO_ALERTS
from warden.knowledge import default_knowledge_base
from warden.language import foreign, foreign_share
from warden.models import Alert, ContextBundle
from warden.quarantine import facts
from warden.tools import FixtureBackend, gather
from warden.verifier import verify

OOM_LINES = {
    "es": [("2026-08-21T14:11:02Z checkout WARN uso de memoria al 94% del límite, la memoria no se libera "
            "pod=checkout-7d9f8"),
           "2026-08-21T14:11:40Z kubelet OOMKilled container=checkout pod=checkout-7d9f8 node=ip-10-0-3-22",
           "2026-08-21T14:12:20Z checkout INFO se ha reiniciado después del fallo, el proceso está activo"],
    "de": ["2026-08-21T14:11:02Z checkout WARN Speicherauslastung 94% des Limits, der Speicher wurde nicht freigegeben",
           "2026-08-21T14:11:40Z kubelet OOMKilled container=checkout pod=checkout-7d9f8 node=ip-10-0-3-22",
           "2026-08-21T14:12:20Z checkout INFO nach dem Absturz neu gestartet, der Prozess ist aktiv"],
    "ja": ["2026-08-21T14:11:02Z checkout WARN メモリ使用率が上限の94%に達しました pod=checkout-7d9f8",
           "2026-08-21T14:11:40Z kubelet OOMKilled container=checkout pod=checkout-7d9f8 node=ip-10-0-3-22",
           "2026-08-21T14:12:20Z checkout INFO クラッシュ後に再起動しました プロセスは稼働中です"],
}


@pytest.mark.parametrize("lang", sorted(OOM_LINES))
def test_code_shaped_evidence_carries_the_diagnosis_in_any_language(lang):
    alert = Alert(**DEMO_ALERTS["inc-002"])
    english = gather(alert, FixtureBackend())
    translated = english.model_copy(update={"logs": OOM_LINES[lang]})
    ids = {m.signature.id for m in default_knowledge_base().match(alert, translated)}
    assert "K8S-OOM-001" in ids  # OOMKilled is the same word in every language
    assert "container=checkout" in " ".join(f for line in translated.logs for f in facts(line))
    assert foreign_share(translated.logs) >= 2 / 3  # the prose lines are seen as not English; the kubelet line is code


def test_a_failure_told_only_in_prose_is_missed_and_the_logs_are_flagged():
    alert = Alert(alert_id="m23-1", name="DatabaseDown", severity="high", service="orders", environment="staging",
                  summary="", started_at="2026-10-03T06:00:00Z")
    english = ContextBundle(logs=["database connection refused, too many connections"] * 3)
    spanish = ContextBundle(logs=["la base de datos rechaza la conexión, hay demasiadas conexiones para el servidor"] * 3)
    kb = default_knowledge_base()
    assert kb.match(alert, english) and not kb.match(alert, spanish)  # measured: the English vocabulary misses it
    assert foreign_share(spanish.logs) == 1.0 and foreign_share(english.logs) == 0.0


def test_the_bundled_english_incidents_are_never_flagged():
    for incident in DEMO_ALERTS:
        context = gather(Alert(**DEMO_ALERTS[incident]), FixtureBackend())
        assert not any(foreign(line) for line in context.logs), incident


def test_non_english_logs_are_observed_on_the_verdict():
    from test_verifier import _alert, _prop, _rc

    context = ContextBundle(logs=OOM_LINES["de"] * 2, metrics={"error_rate": 0.0, "x": 1.0},
                            recent_deploys=[{"sha": "abc"}])
    v = verify(_alert(), context, _rc(), _prop())
    assert any(o.startswith("P28-NON-ENGLISH-LOGS: ") for o in v.observed), v.observed
