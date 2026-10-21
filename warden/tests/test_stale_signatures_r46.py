"""Requirement R46, its stale-data part: a signature is evidence only while a person has reviewed it within a year.
(Anti-faking, anti-hallucination and anti-sycophancy are held by their own tests, cited in the requirement's row.)"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, date, datetime, timedelta

import pytest

from warden.cli import DEMO_ALERTS
from warden.knowledge import REVIEW_DAYS, KnowledgeBase, KnowledgeError, default_knowledge_base
from warden.models import Alert
from warden.tools import FixtureBackend, gather

OOM = """
signatures:
  - id: T-OOM-001
    {reviewed}
    category: memory
    maturity: basic
    title: OOM
    detect:
      name_matches: "(?i)oom"
    root_cause: out of memory
    suggested_actions:
      - kind: restart_pods
        rationale: x
"""


def _kb(tmp_path, reviewed_line: str) -> KnowledgeBase:
    f = tmp_path / "kb.yaml"
    f.write_text(OOM.format(reviewed=reviewed_line), encoding="utf-8")
    return KnowledgeBase.load(f)


def test_a_signature_unreviewed_for_a_year_is_no_longer_evidence(tmp_path):
    alert = Alert(**DEMO_ALERTS["inc-002"])
    context = gather(alert, FixtureBackend())
    kb = _kb(tmp_path, "reviewed: 2026-01-01")
    assert kb.match(alert, context, today=date(2026, 6, 1))
    assert kb.match(alert, context, today=date(2026, 1, 1) + timedelta(days=REVIEW_DAYS + 1)) == []


@pytest.mark.parametrize(("line", "why"), [
    ("", "reviewed"),
    ("reviewed: soon", "date"),
    (f"reviewed: {(datetime.now(UTC).date() + timedelta(days=30)).isoformat()}", "future"),
])
def test_every_signature_must_say_when_it_was_reviewed(tmp_path, line, why):
    with pytest.raises(KnowledgeError, match=why):
        _kb(tmp_path, line)


def test_no_shipped_signature_is_within_sixty_days_of_going_stale():
    """Fails 60 days before any entry would stop matching: the catalogue is reviewed before it decays, not after."""
    limit = datetime.now(UTC).date() - timedelta(days=REVIEW_DAYS - 60)
    stale = [s.id for s in default_knowledge_base().signatures if s.reviewed is None or s.reviewed < limit]
    assert stale == [], f"review these signatures and update their `reviewed` date: {stale}"


def test_a_stale_shipped_signature_would_stop_matching():
    kb = default_knowledge_base()
    alert = Alert(**DEMO_ALERTS["inc-002"])
    context = gather(alert, FixtureBackend())
    assert kb.match(alert, context)
    aged = KnowledgeBase([replace(s, reviewed=date(2020, 1, 1)) for s in kb.signatures])
    assert aged.match(alert, context) == []
