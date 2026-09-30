"""Injection tripwire: a trained detector over every untrusted evidence line (v2, 2026-09-27).

The quarantine (quarantine.py) already keeps untrusted text away from the model structurally. This
adds a SECOND, independent signal: Meta's Llama Prompt Guard 2 (86M), a classifier trained on a
large corpus of prompt-injection and jailbreak attempts, runs locally on each log line and event.
A line it flags does not change what the model sees; it changes what the gate allows: policy P16
escalates the incident to a person, so a flagged line can never lead to an automatic or pre-approved
fix. It is a tripwire, never a gate that clears text as safe - published work bypasses such
classifiers - so the deterministic layers stay the authority.

Modes (WARDEN_TRIPWIRE):
  off       (default) not run. Tests and CI; the report says the detector was off.
  on        run when available; if the model or its libraries are missing, the report says so.
  required  production: if the detector cannot run, P16 escalates every incident (fail closed).

The model is never bundled with WARDEN. Each deployment downloads it under its own Hugging Face
account and accepts Meta's Llama 4 Community License itself (README, "Injection detector").
"""

from __future__ import annotations

import functools
import math
import os
import re
from typing import Any

from .evidence import Item

MODEL = os.environ.get("WARDEN_TRIPWIRE_MODEL", "meta-llama/Llama-Prompt-Guard-2-86M")
# Prompt Guard reads 512 tokens. A long text is scanned in overlapping windows and scores its worst
# window, so an instruction cannot hide behind padding. ⛔ Audit A-C-21: the windows were 1,200
# CHARACTERS, assumed to be ~300 tokens - but symbols, emoji and non-Latin text run to a token or more
# per character, and the classifier silently truncated each window at 512, so the rest was never
# scored. A first fix cut windows by token and DECODED them back to text; an [UNK] decodes to the
# literal "[UNK]", which re-encodes as several tokens, so windows still overflowed and were cut
# (independent review 2026-09-28, shown with the real model). Windows are now token ids fed to the
# model directly: nothing is decoded, re-encoded or truncated.
WINDOW_TOKENS, STEP_TOKENS = 500, 400   # + the model's special tokens <= 512; 100 tokens of overlap:
                                        # an instruction straddling a cut is still whole in one window
MAX_TOKENS = 512
WINDOW_CHARS, STEP_CHARS = 400, 300     # a stand-in classifier without a model (tests): characters
# The parts the MODEL reads are also scored in short windows. In one 500-token window, about 300 benign
# characters before an instruction brought its score from 0.99 to below the threshold: 13 of 25 padded
# placements were caught (fourth review, 2026-09-30). An instruction of up to 32 tokens lies whole in a
# 64-token window with at most 32 tokens of anything else.
SHORT_TOKENS, SHORT_STEP = 64, 32
SHORT_CHARS, SHORT_STEP_CHARS = 120, 60
# ... and sentence by sentence, field by field: an instruction written as its own sentence or field is
# scored without the benign text around it (short windows alone still let 8 of 35 padded placements
# through, measured 2026-09-30 with the real model).
_SEGMENT = re.compile(r"(?<=[.;!?])\s+|\n+|,\s+|\s+(?=[A-Za-z_][\w.-]*=)")
MIN_SEGMENT_CHARS = 20
# The most model tokens one scan scores. Recorded incidents need at most 14,121 (p99 11,630, measured
# 2026-09-30 over 337 reports); a full 512-token window costs about 0.85 s on a laptop CPU, so this
# bounds a scan to about a minute. Over it, nothing is scored and the incident escalates (second
# review, 2026-09-30): a flood of log text must buy neither an unscanned pass nor a stalled incident.
MAX_SCAN_TOKENS = 32_768
MAX_THRESHOLD = 0.99
TOO_MUCH_TEXT = "TOO-MUCH-TEXT"


def threshold() -> float | None:
    """The score at which a window is flagged, or None if the setting is unusable. ⛔ Audit A-C-12:
    `float("nan")` was accepted, and every comparison with nan is False - detection silently off.
    A threshold no real score reaches switches detection off the same way: the strongest real scores
    measured were 0.998-0.9993 (second review, 2026-09-30), so the setting is capped at 0.99."""
    try:
        t = float(os.environ.get("WARDEN_TRIPWIRE_THRESHOLD", "0.9"))
    except ValueError:
        return None
    return t if math.isfinite(t) and 0.0 < t <= MAX_THRESHOLD else None


def _starts(n: int, window: int, step: int) -> list[int]:
    last = max(n - window, 0)
    return sorted({*range(0, last, step), last})


def _char_windows(text: str, window: int = WINDOW_CHARS, step: int = STEP_CHARS) -> list[str]:
    return [text[s:s + window] for s in _starts(len(text), window, step)]


def _id_windows(text: str, tokenizer: Any, window: int = WINDOW_TOKENS, step: int = STEP_TOKENS) -> list[list[int]]:
    ids = tokenizer(text, add_special_tokens=False)["input_ids"]
    return [ids[s:s + window] for s in _starts(len(ids), window, step)]


def _score_ids(classify: Any, windows: list[list[int]]) -> list[float]:
    """The malicious probability of each window, straight from the model: token ids in, no text."""
    try:
        import torch  # present with the [guard] extra: the real model needs tensors
    except ImportError:  # a stand-in model (tests, CI without the extra) takes plain lists
        torch = None
    tok, model = classify.tokenizer, classify.model
    # [CLS] ids [SEP], as tokenizer(text) itself builds them (Prompt Guard 2 is DeBERTa-v2; transformers
    # 5 has no build_inputs_with_special_tokens on it - found running the real model, 2026-09-28).
    rows = [[tok.cls_token_id, *w, tok.sep_token_id] for w in windows]
    if max(len(r) for r in rows) > MAX_TOKENS:
        raise ValueError("a window exceeds the model's input")  # never truncate silently
    labels = {i: str(name).upper() for i, name in model.config.id2label.items()}
    bad = [i for i, name in labels.items() if name in ("MALICIOUS", "LABEL_1")]
    if not bad:  # another model's labels (INJECTION/JAILBREAK): every score would be 0, silently
        raise ValueError("the model has no MALICIOUS label")
    scores: list[float] = []
    for start in range(0, len(rows), 16):
        batch = rows[start:start + 16]
        width = max(len(r) for r in batch)
        pad = tok.pad_token_id or 0
        input_ids = [r + [pad] * (width - len(r)) for r in batch]
        mask = [[1] * len(r) + [0] * (width - len(r)) for r in batch]
        if torch is not None:
            with torch.no_grad():
                logits = model(input_ids=torch.tensor(input_ids), attention_mask=torch.tensor(mask)).logits
            logits = logits.tolist() if hasattr(logits, "tolist") else logits
        else:
            logits = model(input_ids=input_ids, attention_mask=mask).logits
        for row in logits:
            top = max(row)
            exp = [math.exp(v - top) for v in row]
            scores.append(sum(exp[i] for i in bad) / sum(exp))
    return scores


def mode() -> str:
    m = os.environ.get("WARDEN_TRIPWIRE", "off").strip().lower()
    return m if m in ("off", "on", "required") else "required"  # a typo fails closed


@functools.cache
def _classifier() -> Any:
    from transformers import pipeline  # optional: pip install -e ".[guard]"

    return pipeline("text-classification", model=MODEL, top_k=None)  # scored by id: see _score_ids


def _malicious(result: list[dict]) -> float:
    return max((r["score"] for r in result if r["label"].upper() in ("MALICIOUS", "LABEL_1")), default=0.0)


def scan(items: dict[str, Item], classify: Any = None, *,
         outside: dict[str, str] | None = None) -> tuple[str, dict[str, float]]:
    """(status, {id: score}) for every text at or above the threshold.

    `outside` is what the MODEL reads that came from outside WARDEN - the alert's text, its labels, each
    trusted item - scanned in full, EACH PART ON ITS OWN. Joined into one text, the real evidence in the
    same 512-token window diluted a summary injection the model scores 0.99 alone down to 0.36 (third
    review, 2026-09-30; audit A-C-11). The untrusted L/E lines are never shown to the model (only their
    typed facts are); they are scanned with whatever budget is left, and a line past it is reported in
    the status ("ran-partial: ..."), not escalated - a flood of log text must buy neither a pass for what
    the model reads nor an escalation of every noisy incident.

    status: "off", "ran", "ran-partial: <n> of <m> log lines", or "unavailable: <why>" (never the text of
    an error that could carry data).
    """
    if mode() == "off" and classify is None:
        return "off", {}
    limit = threshold()
    if limit is None:
        return "unavailable: bad threshold", {}
    must = [(k, v) for k, v in (outside or {}).items() if v.strip()]
    logs = [(i.id, i.text) for i in items.values() if not i.trusted]
    if not must and not logs:
        return "ran", {}
    try:
        classify = classify or _classifier()
    except Exception as exc:  # noqa: BLE001 - the extra is missing, or the weights are not available
        return f"unavailable: model not loaded ({type(exc).__name__})", {}
    try:
        exact = hasattr(classify, "model") and hasattr(classify, "tokenizer")

        def windows_of(text: str) -> list:
            return _id_windows(text, classify.tokenizer) if exact else _char_windows(text)

        def short_windows_of(text: str) -> list:
            """Only where the text is longer than one short window: otherwise the long one IS it."""
            if exact:
                ws = _id_windows(text, classify.tokenizer, SHORT_TOKENS, SHORT_STEP)
            else:
                ws = _char_windows(text, SHORT_CHARS, SHORT_STEP_CHARS)
            return ws if len(ws) > 1 else []

        def segment_windows_of(text: str) -> list:
            parts = [seg for seg in _SEGMENT.split(text) if len(seg.strip()) >= MIN_SEGMENT_CHARS]
            if len(parts) < 2:
                return []
            return [w for seg in parts for w in windows_of(seg)]

        def cost(ws: list) -> int:
            return sum(len(w) for w in ws) if exact else sum(len(w) for w in ws) // 4

        windows, owner, size = [], [], 0
        for item_id, text in must:
            ws = windows_of(text) + short_windows_of(text) + segment_windows_of(text)
            windows += ws
            owner += [item_id] * len(ws)
            size += cost(ws)
        if size > MAX_SCAN_TOKENS:
            return "ran", {TOO_MUCH_TEXT: 1.0}
        scanned = 0
        for item_id, text in logs:
            ws = windows_of(text)
            if size + cost(ws) > MAX_SCAN_TOKENS:
                continue
            windows += ws
            owner += [item_id] * len(ws)
            size += cost(ws)
            scanned += 1
        if exact:
            scores = _score_ids(classify, windows) if windows else []
        else:
            scores = [_malicious(r) for r in classify(windows, batch_size=16)] if windows else []
        worst: dict[str, float] = {}
        for item_id, score in zip(owner, scores, strict=True):
            worst[item_id] = max(worst.get(item_id, 0.0), score)
    except Exception as exc:  # noqa: BLE001 - missing library, no model access, a classify error (A-C-12)
        return f"unavailable: {type(exc).__name__}", {}
    status = "ran" if scanned == len(logs) else f"ran-partial: {scanned} of {len(logs)} log lines"
    return status, {i: round(s, 3) for i, s in worst.items() if s >= limit}


