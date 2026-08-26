"""The incident-signature knowledge base: turn the researched catalog into deterministic detection.

`data/incident_signatures.yaml` is a human-edited catalog of failure modes (basic -> advanced). This
module loads it, validates it hard, and matches a live incident against it with plain Python — no
model call. Two uses:

  1. INFORM the model — the top matches are folded into the reasoning prompt as "known patterns that
     fit the evidence", so the hypothesis is grounded in a curated catalog rather than invented.
  2. SUGGEST fixes — each signature carries ranked `suggested_actions` drawn from the *closed*
     ActionKind enum, so a suggestion can never be an action the verifier doesn't understand.

Validation is loud on purpose (same philosophy as the verifier and the redactor): a signature whose
`suggested_actions.kind` is a typo, or whose `detect` block uses an unknown key, is a signature that
would silently never fire. Both raise at load time instead.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from .models import ActionKind, Alert, ContextBundle

# The only keys a `detect:` block may contain. An unknown key is a typo that would make the whole
# signature dead weight, so it's rejected at load. Metric NAMES inside metric_gte/lte are free-form
# (they map to whatever the backend measured); only the top-level structure is fixed.
_DETECT_KEYS = {
    "event_reason",
    "log_contains",
    "name_matches",
    "metric_gte",
    "metric_lte",
    "deploy_recent",
    "severity_in",
}
_RISK = {"low", "medium", "high"}
_MATURITY = {"basic", "intermediate", "advanced"}


class KnowledgeError(RuntimeError):
    """The knowledge base is malformed. Fatal at load — a bad catalog must not run degraded."""


@dataclass(frozen=True)
class SuggestedAction:
    kind: ActionKind
    rationale: str


@dataclass(frozen=True)
class Signature:
    id: str
    category: str
    maturity: str
    title: str
    root_cause: str
    detect: dict[str, Any]
    suggested_actions: tuple[SuggestedAction, ...]
    remediation_risk: str
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class SignatureMatch:
    """A signature that fired, with why. `score` is the count of positive signals — higher = better
    supported by the evidence. `signals` names each clause that fired, for the report/audit."""

    signature: Signature
    score: int
    signals: tuple[str, ...]


def _compile(sig_id: str, detect: dict[str, Any]) -> dict[str, Any]:
    """Validate + pre-compile one detect block. Returns it with `name_matches` compiled to a regex."""
    unknown = set(detect) - _DETECT_KEYS
    if unknown:
        raise KnowledgeError(f"{sig_id}: unknown detect key(s) {sorted(unknown)}")
    out = dict(detect)
    if "name_matches" in out:
        try:
            out["name_matches"] = re.compile(out["name_matches"])
        except re.error as exc:
            raise KnowledgeError(f"{sig_id}: bad name_matches regex: {exc}") from exc
    for k in ("event_reason", "log_contains", "severity_in"):
        if k in out and not isinstance(out[k], list):
            raise KnowledgeError(f"{sig_id}: detect.{k} must be a list")
    for k in ("metric_gte", "metric_lte"):
        if k in out and not isinstance(out[k], dict):
            raise KnowledgeError(f"{sig_id}: detect.{k} must be a mapping")
    return out


class KnowledgeBase:
    def __init__(self, signatures: list[Signature]) -> None:
        if not signatures:
            raise KnowledgeError("knowledge base is empty")
        ids = [s.id for s in signatures]
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            raise KnowledgeError(f"duplicate signature id(s): {sorted(dupes)}")
        self.signatures = signatures

    # --------------------------------------------------------------- loading

    @classmethod
    def load(cls, path: str | os.PathLike[str] | None = None) -> KnowledgeBase:
        """Load from `path`, else $WARDEN_KNOWLEDGE_PATH, else the catalog bundled in the package."""
        text = cls._read_source(path)
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise KnowledgeError(f"knowledge base is not valid YAML: {exc}") from exc
        if not isinstance(doc, dict) or "signatures" not in doc:
            raise KnowledgeError("knowledge base must be a mapping with a top-level 'signatures' key")

        signatures: list[Signature] = []
        for raw in doc["signatures"]:
            signatures.append(cls._parse_signature(raw))
        return cls(signatures)

    @staticmethod
    def _read_source(path: str | os.PathLike[str] | None) -> str:
        chosen = path or os.environ.get("WARDEN_KNOWLEDGE_PATH")
        if chosen:
            p = Path(chosen)
            if not p.is_file():
                raise KnowledgeError(f"knowledge base not found at {p}")
            return p.read_text(encoding="utf-8")
        # Bundled with the package (ships as package-data), so an installed wheel still has it.
        res = resources.files("warden") / "data" / "incident_signatures.yaml"
        return res.read_text(encoding="utf-8")

    @staticmethod
    def _parse_signature(raw: dict[str, Any]) -> Signature:
        sid = raw.get("id")
        if not sid:
            raise KnowledgeError(f"a signature is missing its id: {raw!r:.80}")
        for req in ("category", "maturity", "title", "root_cause", "detect", "suggested_actions"):
            if req not in raw:
                raise KnowledgeError(f"{sid}: missing required field '{req}'")
        if raw["maturity"] not in _MATURITY:
            raise KnowledgeError(f"{sid}: maturity must be one of {sorted(_MATURITY)}")
        risk = raw.get("remediation_risk", "medium")
        if risk not in _RISK:
            raise KnowledgeError(f"{sid}: remediation_risk must be one of {sorted(_RISK)}")

        actions: list[SuggestedAction] = []
        for a in raw["suggested_actions"]:
            kind_raw = a.get("kind")
            try:
                kind = ActionKind(kind_raw)
            except ValueError as exc:
                raise KnowledgeError(
                    f"{sid}: suggested action '{kind_raw}' is not a valid ActionKind"
                ) from exc
            actions.append(SuggestedAction(kind=kind, rationale=a.get("rationale", "")))
        if not actions:
            raise KnowledgeError(f"{sid}: needs at least one suggested_action")

        return Signature(
            id=sid,
            category=raw["category"],
            maturity=raw["maturity"],
            title=raw["title"],
            root_cause=raw["root_cause"].strip(),
            detect=_compile(sid, raw["detect"]),
            suggested_actions=tuple(actions),
            remediation_risk=risk,
            references=tuple(raw.get("references", ()) or ()),
        )

    # --------------------------------------------------------------- matching

    def match(
        self, alert: Alert, context: ContextBundle, *, limit: int = 3
    ) -> list[SignatureMatch]:
        """Rank signatures against one incident. Deterministic; no model call.

        A signature matches when (a) any `severity_in` guard it declares is satisfied, and (b) at
        least one positive signal (a log/event term, a name regex, a metric threshold, a deploy
        condition) fires. Score = number of positive signals; ties break by signature id so the
        order is stable across runs.
        """
        corpus = "\n".join(context.logs).lower()
        if alert.summary:
            corpus += "\n" + alert.summary.lower()

        matches: list[SignatureMatch] = []
        for sig in self.signatures:
            d = sig.detect
            # Guard: a declared severity filter must pass, or the signature is not applicable at all.
            if "severity_in" in d and alert.severity.value not in d["severity_in"]:
                continue

            signals: list[str] = []

            terms = [t.lower() for t in d.get("event_reason", [])] + [
                t.lower() for t in d.get("log_contains", [])
            ]
            hits = [t for t in terms if t in corpus]
            if hits:
                signals.append(f"log/event:{hits[0]}")

            nm = d.get("name_matches")
            if nm is not None and nm.search(alert.name):
                signals.append("name")

            for metric, thr in d.get("metric_gte", {}).items():
                v = context.metrics.get(metric)
                if v is not None and v >= thr:
                    signals.append(f"{metric}>={thr}")
            for metric, thr in d.get("metric_lte", {}).items():
                v = context.metrics.get(metric)
                if v is not None and v <= thr:
                    signals.append(f"{metric}<={thr}")

            # Only a positive signal when a deploy is actually required AND present. Requiring
            # "no deploy" is too weak to be a signal on its own, so deploy_recent:false never scores.
            if d.get("deploy_recent") and context.recent_deploys:
                signals.append("deploy_recent")

            if signals:
                matches.append(SignatureMatch(sig, len(signals), tuple(signals)))

        matches.sort(key=lambda m: (-m.score, m.signature.id))
        return matches[:limit]


# A process-wide cached instance so the YAML is parsed once. Tests that need a custom catalog
# construct KnowledgeBase directly and never touch this.
_DEFAULT: KnowledgeBase | None = None


def default_knowledge_base() -> KnowledgeBase:
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = KnowledgeBase.load()
    return _DEFAULT
