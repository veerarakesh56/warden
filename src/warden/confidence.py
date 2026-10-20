"""WARDEN's confidence in a diagnosis (owner U3-1, 2026-10-17): a level - low, medium or high - from checks WARDEN can
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
    lead = None if sep is None else sep[0] - sep[1]
    rivals = len(root_cause.hypotheses or []) - 1
    seen = signatures_in_evidence(alert, context)
    closing = proposal.action is ActionKind.no_action or root_cause.outcome is Outcome.no_fault
    handoff = proposal.action is ActionKind.escalate_to_human
    checks = [
        ("grounded", not problems, "every citation holds" if not problems else "; ".join(problems[:3])),
        ("decisive", decisive is None, "a metric, deploy or configuration read WARDEN made decides it"
         if decisive is None else "only log facts or failed reads support it"),
        ("separated", lead is not None and rivals > 0 and lead >= MARGIN,
         "no rival cause was weighed" if lead is None or rivals < 1 else
         f"WARDEN's count {sep[0]} against its best rival's {sep[1]} (needs a lead of {MARGIN})"),
        ("clear_lead", lead is not None and rivals > 0 and lead >= 2 * MARGIN,
         "no rival cause was weighed" if lead is None or rivals < 1 else
         f"a lead of {lead}; high needs {2 * MARGIN}"),
        ("complete", not context.tool_errors,
         "every read returned" if not context.tool_errors else f"{len(context.tool_errors)} read(s) failed"),
        ("signatures", handoff or (not seen if closing else bool(seen)),
         "a hand-off" if handoff else (f"WARDEN's signatures describe the evidence: {', '.join(seen)}" if seen
                                       else "no failure signature of WARDEN's describes the evidence")),
        ("consistent", (why := outcome_problem(root_cause, proposal)) is None,
         "the outcome and the remediation agree" if why is None else why),
    ]
    met = {name: ok for name, ok, _ in checks}
    if not (met["grounded"] and met["decisive"] and met["separated"]):
        level = LOW
    elif all(met.values()):
        level = HIGH
    else:
        level = MEDIUM
    return {"level": level, "checks": [{"name": n, "met": ok, "detail": d} for n, ok, d in checks],
            "separation": list(sep) if sep is not None else None}
