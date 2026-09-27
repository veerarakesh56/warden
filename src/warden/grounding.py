"""Grounding: is what the model claims actually in the evidence? Deterministic, no model.

P13 (claims): every citation must name an evidence id that exists (evidence.py) and quote a span that
appears in that item verbatim (whitespace collapsed; case kept). A diagnosis with no citation, or
with any citation that fails, is ungrounded. One made-up quote is enough: a model that invents one
span has told us its other spans need checking too.

P14 (target): the proposal's target must name a resource in the inventory, and must not also name a
compound resource-like token (`shop-prod-checkout`) the inventory lacks. Observed live 2026-09-26:
`scale_up lambda:shop-prod-checkout` against a stack whose function is `warden-pg-fs-checkout`.
"""

from __future__ import annotations

import re

from .evidence import Item, tokens
from .models import RemediationProposal, RootCause

MIN_QUOTE = 4  # characters, whitespace excluded: a quote of "a" is in everything


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def citation_problems(root_cause: RootCause, items: dict[str, Item]) -> list[str]:
    if not root_cause.citations:
        return ["the diagnosis cites no evidence"]
    problems = []
    for c in root_cause.citations:
        cid = c.id.strip().strip("[]")
        item = items.get(cid)
        quote = _norm(c.quote)
        if item is None:
            problems.append(f"{cid or '(blank)'} is not an evidence id")
        elif len(quote.replace(" ", "")) < MIN_QUOTE:
            problems.append(f"{cid}: quote {c.quote!r} is too short to check")
        elif quote not in _norm(item.text):
            problems.append(f"{cid}: {c.quote[:80]!r} does not appear in that item")
    return problems


def target_problem(proposal: RemediationProposal, inventory: set[str]) -> str | None:
    found = tokens(proposal.target)
    if not found & inventory:
        return f"target {proposal.target!r} names no resource in the inventory"
    unknown = sorted(t for t in found - inventory if "-" in t or "_" in t)
    if unknown:
        return f"target {proposal.target!r} names {', '.join(unknown)}, which is not in the inventory"
    return None
