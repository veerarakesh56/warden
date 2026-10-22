"""What README.md and docs/BENCHMARKS.md say about qualification must be what src/warden/data/providers.yaml holds
(owner, 2026-10-21: the docs called a model "the production model" while the pinned prompt was qualified for none).

Read at test time from providers.yaml, never hard-coded: the pinned prompt (`prompt.sha`), the bar, and the rows. A
row qualifies a model today only on the pinned prompt and at the bar (providers.qualified); a row on an earlier prompt
is history.
"""

from __future__ import annotations

import pathlib
import re

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
DOCS = ("README.md", "docs/BENCHMARKS.md")
STATUS = "**Qualified on the pinned prompt**"
# A prompt hash as the docs quote one: 8 to 64 hex characters in backticks, optionally followed by an ellipsis.
_HASH = re.compile(r"`([0-9a-f]{8,64})(?:\.\.\.|…)?`")
# "qualified" as a claim: not "not qualified", "NOT YET QUALIFIED", "unqualified", "re-qualified", "qualification".
_CLAIM = re.compile(r"(?<![-\w])qualified\b", re.IGNORECASE)
_NEGATED = re.compile(r"\b(?:not|no|never|none)\b(?:\s+\w+){0,2}\s+qualified\b", re.IGNORECASE)
# What the planted status lines say (each test below states its own case with these).
SONNET = "claude-sonnet-5-5"
NONE = "**none**."
NAMES_SONNET = f"anthropic `{SONNET}`."


def providers() -> dict:
    return yaml.safe_load(
        (ROOT / "src" / "warden" / "data" / "providers.yaml").read_text(encoding="utf-8")
    )


def _meets_bar(row: dict, bar: dict) -> bool:
    return int(row.get("wrong_and_allowed", 1 << 30)) <= int(bar["wrong_and_allowed"]) and int(
        row.get("correct", -1)
    ) >= int(bar["min_correct"])


def qualified_now(doc: dict) -> set[str]:
    """The models providers.qualified() admits today: a row on the pinned prompt that meets the bar."""
    pinned = doc["prompt"]["sha"]
    return {
        r["model"]
        for r in doc["qualified"]
        if r.get("prompt") == pinned and _meets_bar(r, doc["bar"])
    }


def qualified_prompts(doc: dict) -> set[str]:
    """Every prompt some row met the bar on - the only hashes a doc may call a model qualified on."""
    return {r["prompt"] for r in doc["qualified"] if r.get("prompt") and _meets_bar(r, doc["bar"])}


def paragraphs(text: str) -> list[str]:
    """Blank-line separated paragraphs; each table row is its own paragraph."""
    out: list[str] = []
    for block in re.split(r"\n\s*\n", text):
        rows = [ln for ln in block.splitlines() if ln.lstrip().startswith("|")]
        out.extend(rows if rows else [" ".join(block.split())])
    return out


def status_problems(text: str, doc: dict) -> list[str]:
    lines = [ln for ln in text.splitlines() if ln.startswith(STATUS)]
    if len(lines) != 1:
        return [f"expected one line starting {STATUS!r}, found {len(lines)}"]
    named = set(re.findall(r"`([a-z0-9][a-z0-9.\-]*)`", lines[0].split(":", 1)[1]))
    named.discard("src/warden/data/providers.yaml")
    now = qualified_now(doc)
    if now and named != now:
        return [
            f"the status line names {sorted(named)}; providers.yaml qualifies {sorted(now)} on the pinned prompt"
        ]
    if not now and (named or "**none**" not in lines[0]):
        return [
            (
                f"the status line names {sorted(named) or 'something'}; providers.yaml qualifies no model on the "
                "pinned prompt: it must say **none**"
            )
        ]
    return []


def sentences(text: str) -> list[str]:
    """Each paragraph's sentences (a table row is one): a claim and a hash are read together only in one sentence."""
    return [s for para in paragraphs(text) for s in re.split(r"(?<=[.;])\s+(?=[A-Z*(`])", para)]


def hash_problems(text: str, doc: dict) -> list[str]:
    """A sentence that calls something qualified may quote only a prompt hash some row met the bar on."""
    known = qualified_prompts(doc)
    bad = []
    for para in sentences(text):
        claims = len(_CLAIM.findall(para)) > len(_NEGATED.findall(para))
        if not claims:
            continue
        for h in _HASH.findall(para):
            if not any(p.startswith(h) for p in known):
                bad.append(
                    f"claims qualified on prompt `{h}`, which no providers.yaml row met the bar on: {para[:160]}"
                )
    return bad


def production_problems(text: str, doc: dict) -> list[str]:
    """ "The production model" names a model only when one is qualified on the pinned prompt, and then that one."""
    now = qualified_now(doc)
    bad = []
    for para in paragraphs(text):
        if re.search(r"\bproduction model\b", para, re.IGNORECASE):
            ids = set(re.findall(r"claude-[a-z0-9\-]+|gemini-[a-z0-9.\-]+|gpt-[a-z0-9.\-]+", para))
            if not now or not (ids & now):
                bad.append(
                    f"calls a model the production model, but providers.yaml qualifies "
                    f"{sorted(now) or 'none'} on the pinned prompt: {para[:160]}"
                )
        if now and re.search(r"\bno model is qualified\b", para, re.IGNORECASE):
            bad.append(
                f"says no model is qualified, but providers.yaml qualifies {sorted(now)}: {para[:160]}"
            )
    return bad


def problems(text: str, doc: dict) -> list[str]:
    return status_problems(text, doc) + hash_problems(text, doc) + production_problems(text, doc)


@pytest.mark.parametrize("name", DOCS)
def test_the_docs_claim_only_what_providers_yaml_qualifies(name):
    assert problems((ROOT / name).read_text(encoding="utf-8"), providers()) == []


def test_the_pin_and_rows_are_read_from_providers_yaml():
    doc = providers()
    assert re.fullmatch(r"[0-9a-f]{64}", doc["prompt"]["sha"])
    assert qualified_now(doc) <= {r["model"] for r in doc["qualified"]}


# ---- the guard itself, on planted text (no hash or model written here: each comes from providers.yaml) ----


def _unqualified_doc() -> dict:
    """providers.yaml with no row on the pinned prompt (as on 2026-10-21) - whatever it holds today."""
    doc = providers()
    return {
        **doc,
        "qualified": [r for r in doc["qualified"] if r.get("prompt") != doc["prompt"]["sha"]],
    }


def _qualified_doc(model: str) -> dict:
    doc = providers()
    row = {
        "provider": "anthropic",
        "model": model,
        "prompt": doc["prompt"]["sha"],
        "correct": doc["bar"]["min_correct"],
        "runs": 30,
        "wrong_and_allowed": doc["bar"]["wrong_and_allowed"],
    }
    return {**doc, "qualified": [*doc["qualified"], row]}


def _status(text: str) -> str:
    return f"{STATUS} (as of 2026-10-21): {text}\n"


def test_a_claim_on_the_pinned_prompt_that_no_row_holds_fails():
    doc = _unqualified_doc()
    pinned = doc["prompt"]["sha"]
    text = _status(NONE) + f"\nClaude Sonnet 5.5 is qualified on prompt `{pinned[:8]}`.\n"
    assert any(pinned[:8] in p for p in problems(text, doc))


def test_a_status_line_naming_an_unqualified_model_fails():
    doc = _unqualified_doc()
    assert problems(_status(NAMES_SONNET), doc)


def test_a_status_line_saying_none_while_a_model_is_qualified_fails():
    assert problems(_status(NONE), _qualified_doc(SONNET))
    assert problems(_status(NAMES_SONNET), _qualified_doc(SONNET)) == []


def test_the_production_model_is_named_only_when_qualified_on_the_pinned_prompt():
    claim = (
        _status(NONE)
        + "\nThe production model, Claude Sonnet 5.5 (`claude-sonnet-5-5`), scored 17.\n"
    )
    assert problems(claim, _unqualified_doc())
    assert (
        problems(
            claim.replace(NONE, NAMES_SONNET),
            _qualified_doc(SONNET),
        )
        == []
    )


def test_history_and_negations_are_not_claims():
    doc = _unqualified_doc()
    earlier = (
        "e" * 64
    )  # an earlier prompt some row met the bar on (made up: it only has to differ from the pin)
    doc["qualified"] = [
        *doc["qualified"],
        {
            "model": "m",
            "prompt": earlier,
            "correct": doc["bar"]["min_correct"],
            "wrong_and_allowed": doc["bar"]["wrong_and_allowed"],
        },
    ]
    text = (
        _status(NONE)
        + f"\nSonnet passed on an earlier prompt (`{earlier[:8]}`); it is not qualified "
        "today, and the pinned prompt is NOT YET QUALIFIED.\n"
    )
    assert problems(text, doc) == []


def test_a_missing_or_doubled_status_line_is_caught():
    doc = _unqualified_doc()
    assert problems("no status here\n", doc)
    assert problems(_status(NONE) * 2, doc)


def test_saying_no_model_is_qualified_fails_once_one_is():
    text = _status(NAMES_SONNET) + "\nNo model is qualified on the pinned prompt.\n"
    assert problems(text, _qualified_doc(SONNET))
    assert problems(text.replace(NAMES_SONNET, NONE), _unqualified_doc()) == []
