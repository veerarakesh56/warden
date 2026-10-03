"""The calibrated decision component (requirement R44; registers E2, E5, C22): the probability that a proposal is
the right answer, learned from independent ground truth - not the model's own confidence.

A model's self-reported confidence is not calibrated (P9's note: 0.85 on everything). This scores a proposal from
facts WARDEN measured - how much evidence there is, whether a known signature agrees with the action, how grounded
the citations are, what the gate found - with a logistic model trained by `scripts/train_decider.py` on recorded
runs whose label is the rubric's grade of the injected fault (register E2: never WARDEN's own verdicts). The
coefficients are plain JSON (`data/decider.json`); the runtime is a dot product and a sigmoid, so nothing is
unpickled.

The JSON is checked before it is used (register C22): its shape, its size, its feature list against the code's,
every number finite. A file that fails keeps the last one that passed, or none - never a half-read model.

What `p` is used for: nothing decides on it yet. It is recorded in observe mode (verifier.OBSERVED, audit A-P-8)
and shown in reports, and `tier_enabled` (register E5) holds every automatic tier off until a shadow precision's
Wilson lower bound clears its threshold.
"""

from __future__ import annotations

import json
import math
from functools import lru_cache
from importlib import resources
from typing import Any

from .models import ActionKind, Alert, ContextBundle, RemediationProposal, RootCause, Verdict

FEATURES = ("confidence", "log_lines", "metrics", "has_deploy", "tool_errors", "symptoms", "signatures",
            "rules_agree", "citations", "passive", "policies", "grounded")
MAX_BYTES = 64 * 1024
PASSIVE = {ActionKind.no_action, ActionKind.escalate_to_human}


class DeciderError(ValueError):
    pass


def features(alert: Alert, context: ContextBundle, root_cause: RootCause, proposal: RemediationProposal,
             verdict: Verdict) -> dict[str, float]:
    """What the decider reads: measured facts only, each a number."""
    from .knowledge import default_knowledge_base
    from .verifier import symptoms

    matches = default_knowledge_base().match(alert, context)
    agree = any(s.kind is proposal.action for m in matches for s in m.signature.suggested_actions)
    return {
        "confidence": float(root_cause.confidence),
        "log_lines": math.log1p(len(context.logs)),
        "metrics": math.log1p(len(context.metrics)),
        "has_deploy": float(bool(context.recent_deploys)),
        "tool_errors": float(bool(context.tool_errors)),
        "symptoms": float(len(symptoms(context))),
        "signatures": float(len(matches)),
        "rules_agree": float(agree),
        "citations": float(len(root_cause.citations)),
        "passive": float(proposal.action in PASSIVE),
        "policies": float(len(verdict.policy_ids)),
        "grounded": float("P13-UNGROUNDED" not in verdict.policy_ids),
    }


def validate(doc: Any) -> dict:
    """The decider as loaded, or DeciderError: the right features in the right order, every number finite."""
    if not isinstance(doc, dict):
        raise DeciderError("the decider is not a JSON object")
    if doc.get("features") != list(FEATURES):
        raise DeciderError("the decider's features are not the ones this code computes")
    for key in ("mean", "scale", "weights"):
        values = doc.get(key)
        if not isinstance(values, list) or len(values) != len(FEATURES):
            raise DeciderError(f"{key} must have one number per feature")
        if not all(isinstance(v, (int, float)) and math.isfinite(v) for v in values):
            raise DeciderError(f"{key} holds a value that is not a finite number")
    if any(v <= 0 for v in doc["scale"]):
        raise DeciderError("a feature scale must be positive")
    if not isinstance(doc.get("bias"), (int, float)) or not math.isfinite(doc["bias"]):
        raise DeciderError("the bias is not a finite number")
    if doc.get("label_source") != "rubric":
        raise DeciderError("the decider must be trained on independent labels (the rubric), never on WARDEN's own "
                           "outcomes (register E2)")
    return doc


def load_text(text: str) -> dict:
    if len(text.encode()) > MAX_BYTES:
        raise DeciderError("the decider file is larger than any real one")
    try:
        return validate(json.loads(text))
    except ValueError as exc:
        raise DeciderError(str(exc)) from exc


_last_good: dict | None = None


@lru_cache(maxsize=1)
def bundled() -> dict | None:
    """The shipped decider, validated; on a bad file, the last one that passed in this process, or None."""
    global _last_good
    try:
        doc = load_text((resources.files("warden") / "data" / "decider.json").read_text(encoding="utf-8"))
    except (DeciderError, OSError):
        return _last_good
    _last_good = doc
    return doc


def probability(feats: dict[str, float], doc: dict) -> float:
    z = doc["bias"] + sum(w * (feats[f] - m) / s for f, m, s, w in
                          zip(FEATURES, doc["mean"], doc["scale"], doc["weights"], strict=True))
    return 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, z))))


def wilson_lower(successes: int, n: int, z: float = 1.959964) -> float:
    """The Wilson score interval's lower bound: how good a precision is at least, at 95%, given n trials."""
    if n <= 0:
        return 0.0
    p = successes / n
    centre = p + z * z / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return (centre - margin) / (1 + z * z / n)


ENABLE_AT = 0.90  # register E5: a tier may run unattended only when shadow precision is at least this, proven


def tier_enabled(correct: int, shadowed: int, threshold: float = ENABLE_AT) -> bool:
    """Register E5: an automatic tier turns on only when its shadow precision's Wilson lower bound clears the
    threshold - 30 right out of 30 does not (0.886), so a small clean run never switches anything on."""
    return wilson_lower(correct, shadowed) >= threshold
