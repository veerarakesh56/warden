"""WARDEN's confidence in a diagnosis: a level - low, medium or high - from checks WARDEN can
show a person, never the model's own number. A model's self-reported confidence is not calibrated (decide.py: 0.85 on
everything), so it is shown beside this level, never instead of it.

Each check is one fact WARDEN holds:
    grounded    every citation of the diagnosis, and of its chosen cause's own support, names a real item and quotes it
                (P13's test)
    decisive    the chosen cause rests on at least one held metric, deploy or configuration/state read (P34's test)
    separated   WARDEN's count of the chosen cause leads its best rival's by the margin (P35's numbers,
                grounding.separation)
    clear_lead  ... and by twice the margin
    complete    every read WARDEN tried returned (no failed read)
    signatures  a fix: one of WARDEN's own failure signatures describes what it read; no fault: none does
    consistent  the typed outcome agrees with the remediation (P37's test)

The level: low when the diagnosis is not grounded, not decided by WARDEN's own reads or not separated from its rival;
high when every check holds; medium otherwise. The rules were fixed before any measurement
and are never tuned on one. The records page, the report and model routing read the same dictionary.
"""

from __future__ import annotations

from typing import Any

LOW, MEDIUM, HIGH = "low", "medium", "high"


def _separation_checks(sep: tuple[int, int] | None, rivals: int, margin: int) -> list[tuple[str, bool, str]]:
    """separated and clear_lead: WARDEN's count of the chosen cause against its best rival's (grounding.separation)."""
    if sep is None or rivals < 1:
        none = "no rival cause was weighed"
        return [("separated", False, none), ("clear_lead", False, none)]
    lead = sep[0] - sep[1]
    counts = f"WARDEN's count {sep[0]} against its best rival's {sep[1]} (needs a lead of {margin})"
    return [("separated", lead >= margin, counts),
            ("clear_lead", lead >= 2 * margin, f"a lead of {lead}; high needs {2 * margin}")]


def _signatures_check(seen: list[str], closing: bool, handoff: bool) -> tuple[str, bool, str]:
    """A fix: one of WARDEN's own failure signatures describes the evidence; a close: none does; a hand-off: either."""
    if handoff:
        return ("signatures", True, "a hand-off")
    if seen:
        detail = f"WARDEN's signatures describe the evidence: {', '.join(seen)}"
    else:
        detail = "no failure signature of WARDEN's describes the evidence"
    return ("signatures", not seen if closing else bool(seen), detail)


def _level(met: dict[str, bool]) -> str:
    if not (met["grounded"] and met["decisive"] and met["separated"]):
        return LOW
    return HIGH if all(met.values()) else MEDIUM


def assess(alert: Any, context: Any, root_cause: Any, proposal: Any) -> dict[str, Any]:
    """{"level": low|medium|high, "checks": [{"name", "met", "detail"}], "separation": [chosen, rival] or None}."""
    from . import evidence
    from .grounding import MARGIN, citation_problems, decisive_problem, outcome_problem, separation
    from .models import ActionKind, Outcome
    from .verifier import signatures_in_evidence

    items = evidence.view(context)
    problems = citation_problems(root_cause, items)
    decisive = decisive_problem(root_cause, items)
    sep = separation(root_cause, items)
    rivals = len(root_cause.hypotheses or []) - 1
    closing = proposal.action is ActionKind.no_action or root_cause.outcome is Outcome.no_fault
    why = outcome_problem(root_cause, proposal)
    failed = len(context.tool_errors or [])
    checks = [
        ("grounded", not problems, "; ".join(problems[:3]) if problems else "every citation holds"),
        ("decisive", decisive is None, "only log facts or failed reads support it" if decisive is not None
         else "a metric, deploy or configuration read WARDEN made decides it"),
        *_separation_checks(sep, rivals, MARGIN),
        ("complete", not failed, f"{failed} read(s) failed" if failed else "every read returned"),
        _signatures_check(signatures_in_evidence(alert, context), closing,
                          proposal.action is ActionKind.escalate_to_human),
        ("consistent", why is None, why or "the outcome and the remediation agree"),
    ]
    return {"level": _level({name: ok for name, ok, _ in checks}),
            "checks": [{"name": n, "met": ok, "detail": d} for n, ok, d in checks],
            "separation": list(sep) if sep is not None else None}
