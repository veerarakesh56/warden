"""How far to trust what WARDEN said about an incident (item 16c): Low, Medium or High, from signals anyone can check.

Never the model's own confidence: a model that is sure of a wrong answer reads as sure (README, "What it is not").
Each signal below is a fact on the incident's signed record, and the block shows every one of them and which decided
the level:

- evidence: what WARDEN read - something was read, and no read failed;
- grounded: the diagnosis's citations name real evidence and quote it (no P13, P14 or P15);
- rules: WARDEN's deterministic rules let the answer stand - the verdict was not rejected, and nothing but the model's
  own low confidence (P4, which this block does not count either way) escalated it;
- second opinion: a second, independent diagnosis of the same evidence named the same action on the same target;
- fix verified: WARDEN's fix ran and its own checks saw the service recover and stay recovered;
- proven fix: a record this one is linked to as sharing its cause holds a fix that was applied and verified (only when
  the record carries linked records, links.py).

The level: **Low** when any signal failed; **High** when evidence, grounded and rules all passed and at least one of
second opinion, fix verified and proven fix backs them; **Medium** otherwise - nothing failed, but not enough was
checked to say more.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

LOW, MEDIUM, HIGH = "Low", "Medium", "High"
EVIDENCE, GROUNDED, RULES = "evidence", "grounded", "rules"  # the signals, by name
SECOND, FIX, PROVEN = "second opinion", "fix verified", "proven fix"
COLOUR = {LOW: "bad", MEDIUM: "warn", HIGH: "ok"}  # red, amber, green on the records page
GROUNDING = frozenset({"P13-UNGROUNDED", "P14-TARGET-NOT-IN-EVIDENCE", "P15-CITATIONS-DO-NOT-SUPPORT-ACTION"})
SELF_CONFIDENCE = frozenset({"P4-LOW-CONFIDENCE"})  # the model's own confidence: not a signal here, either way
NO_DIAGNOSIS = "P0-MODEL-UNAVAILABLE"
FAILED_FIX = frozenset({"relapsed", "rolled_back", "not_recovered", "rollback_failed", "apply_failed", "side_effects",
                        "failed_after_apply", "cancelled_after_apply"})
BASE = (EVIDENCE, GROUNDED, RULES)
BACKING = (SECOND, FIX, PROVEN)


@dataclass
class Signal:
    name: str
    passed: bool | None  # None: not checked for this incident
    why: str


@dataclass
class Block:
    level: str
    signals: list[Signal]
    decided_by: list[str]

    @property
    def colour(self) -> str:
        return COLOUR[self.level]


def _last(r: Any, kind: str) -> dict[str, Any] | None:
    rows = [e["body"] for e in r.rows if e["kind"] == kind]
    return rows[-1] if rows else None


def _count(value: Any) -> int | None:
    """A count as WARDEN writes it - a whole number, 0 or more, or nothing - else None."""
    if value is None:
        return 0
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def _evidence(r: Any) -> Signal:
    g = _last(r, "incident.gather")
    if g is None:
        return Signal(EVIDENCE, None, "no evidence read is on the record")
    counts = [_count(g.get(k)) for k in ("logs", "metrics", "deploys", "tool_errors")]
    if None in counts:  # a row that is not WARDEN's shape says nothing either way (CodeRabbit, PR 100)
        return Signal(EVIDENCE, None, "the record's read counts could not be read")
    read, failed = sum(counts[:3]), counts[3]
    if failed:
        return Signal(EVIDENCE, False, f"{failed} read(s) failed: the picture is partial")
    if not read:
        return Signal(EVIDENCE, False, "nothing was read")
    return Signal(EVIDENCE, True, f"{read} item(s) read, no read failed")


def _verify(r: Any) -> tuple[str, set[str]] | None:
    v = _last(r, "incident.verify")
    return (str(v.get("status") or ""), {str(p) for p in v.get("policies") or []}) if v else None


def _grounded(r: Any) -> Signal:
    v = _verify(r)
    if v is None or NO_DIAGNOSIS in v[1]:
        return Signal(GROUNDED, None, "there was no diagnosis to check")
    fired = sorted(v[1] & GROUNDING)
    if fired:
        return Signal(GROUNDED, False, f"the citations did not hold ({', '.join(fired)})")
    return Signal(GROUNDED, True, "every citation names real evidence and quotes it")


def _rules(r: Any) -> Signal:
    v = _verify(r)
    if v is None:
        return Signal(RULES, None, "the rules have not checked a diagnosis yet")
    status, fired = v
    others = sorted(fired - SELF_CONFIDENCE - GROUNDING - {NO_DIAGNOSIS})
    if status == "rejected":
        return Signal(RULES, False, f"the rules rejected the answer ({', '.join(others) or 'rejected'})")
    if status == "escalated" and others:
        return Signal(RULES, False, f"the rules sent it to a person ({', '.join(others)})")
    if NO_DIAGNOSIS in fired:
        return Signal(RULES, None, "no diagnosis: the rules alone sent it to a person")
    return Signal(RULES, True, "WARDEN's rules let the answer stand")


def _second(r: Any) -> Signal:
    s = _last(r, "incident.second_opinion")
    if s is None:
        return Signal(SECOND, None, "no second diagnosis was asked")
    if s.get("agree") is True:
        return Signal(SECOND, True, "a second, independent diagnosis named the same fix")
    return Signal(SECOND, False, "a second diagnosis disagreed, or none could be had")


def _fix(r: Any) -> Signal:
    end = _last(r, "workflow.end")
    status = str((end or {}).get("status") or "")
    if status == "recovered":
        return Signal(FIX, True, "the fix's own checks saw recovery, and the re-checks held")
    if status == "mitigated":  # the fix held the harm and did not end it (CodeRabbit, PR 100)
        return Signal(FIX, False, "the fix held the harm but did not fix the cause")
    if status in FAILED_FIX:
        return Signal(FIX, False, f"the fix did not hold ({status.replace('_', ' ')})")
    return Signal(FIX, None, "no fix has run to its checks")


def _proven(r: Any) -> Signal:
    proven = getattr(r, "proven", None)  # linked records (links.py), when the record carries them
    if proven:
        return Signal(PROVEN, True, f"{proven.get('entry')} was applied and verified on linked record "
                                          f"{proven.get('incident')}")
    return Signal(PROVEN, None, "no linked record holds a proven fix")


def block(r: Any) -> Block:
    """The confidence block of a record built with its steps (records.record, not `light`)."""
    signals = [_evidence(r), _grounded(r), _rules(r), _second(r), _fix(r), _proven(r)]
    by = {s.name: s for s in signals}
    failed = [s.name for s in signals if s.passed is False]
    if failed:
        return Block(LOW, signals, failed)
    backing = [n for n in BACKING if by[n].passed]
    if all(by[n].passed for n in BASE) and backing:
        return Block(HIGH, signals, [*BASE, *backing])
    missing = [n for n in BASE if by[n].passed is None] + ([] if backing else list(BACKING))
    return Block(MEDIUM, signals, missing)
