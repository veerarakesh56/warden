"""Memory, runbooks and references that may have been tampered with (register G10-48).

Owner, 2026-10-14: "be cautious with memory, company runbooks and references - they may be tampered". Researched the
same day (MINJA, AgentPoison, ShadowMerge, the Misattribution Gap: a model-written memory turns one hostile input into
trusted context for every later incident). WARDEN keeps no memory a model writes: what it keeps are facts on its
signed record, and the evidence of ONE incident, kept to answer questions about that incident only. Its reference
knowledge changes only by a reviewed commit (N9), and every place that reads text from outside is a known one."""

from __future__ import annotations

import pathlib
import re

SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "warden"

# Every module that fetches text from outside WARDEN. A new one is a reviewed change: whatever it reads is untrusted,
# and must reach the model, if at all, only through the quarantine and the tripwire.
FETCHERS = {"aws_docs.py", "aws_stack.py", "changes.py", "chatops.py", "discuss.py", "slack_login.py", "timeline.py",
            "webhooks.py"}


def _src(name: str) -> str:
    return (SRC / name).read_text(encoding="utf-8")


def _code(text: str) -> str:
    """The names and strings a piece of source uses, without its comments and docstrings."""
    import io
    import tokenize

    out, prev = [], None
    for tok in tokenize.generate_tokens(io.StringIO(text).readline):
        if tok.type == tokenize.COMMENT:
            continue
        if tok.type == tokenize.STRING and prev in (tokenize.INDENT, tokenize.NEWLINE, tokenize.NL, None):
            continue  # a docstring
        if tok.type in (tokenize.NAME, tokenize.STRING, tokenize.OP):
            out.append(tok.string)
        prev = tok.type
    return " ".join(out)


def _function(text: str, name: str) -> str:
    start = text.index(f"    def {name}(")
    nxt = re.search(r"\n    (?:@activity\.defn\n    )?def |\n(?:class|def) ", text[start + 10:])
    return text[start:start + 10 + nxt.start()] if nxt else text[start:]


def test_every_place_that_reads_outside_text_is_a_known_one():
    found = {p.name for p in SRC.rglob("*.py")
             if re.search(r"urllib\.request|import requests|import httpx|aiohttp|from slack_sdk|urlopen",
                          p.read_text(encoding="utf-8"))}
    assert found == FETCHERS, f"a new reader of outside text: {sorted(found - FETCHERS)}"


def test_an_incidents_kept_evidence_answers_only_that_incidents_questions():
    acts = _src("activities.py")
    uses = [m.start() for m in re.finditer(r'"incident\.evidence"', acts)]
    prepare, discuss = _function(acts, "prepare"), _function(acts, "discuss_evidence")
    assert len(uses) == 2 and '"incident.evidence"' in prepare and '"incident.evidence"' in discuss
    for other in SRC.rglob("*.py"):
        if other.name not in ("activities.py", "records.py"):
            assert '"incident.evidence"' not in other.read_text(encoding="utf-8"), other.name
    # Read by the incident's own id, never across incidents.
    assert 'self.audit.entries(incident, kinds=("incident.evidence",))' in discuss


def test_no_diagnosis_reads_a_record_a_discussion_or_a_past_answer():
    graph, acts = _code(_src("graph.py")), _src("activities.py")
    diagnose = _code(_function(acts, "diagnose").split(":", 1)[1])
    for never in ("history", "records", "discuss", "incident.evidence", "incident.report", "remediation.announce"):
        assert never not in graph, never
        assert never not in diagnose, never
    # Approvers' notes are never in a prompt either (G10-43) - and what WARDEN keeps instead of posting is not.
    assert "said" not in diagnose.split() and "note" not in diagnose.split()


def test_no_model_writes_anything_a_later_incident_reads():
    """The rows a later run reads (history.py, the records page) are written by WARDEN's own steps from facts - no
    model output is ever a row's source of truth for another incident."""
    hist = _src("history.py")
    assert "hypothesis" not in hist and "answer" not in hist  # past diagnoses' and discussions' words stay out
    acts = _src("activities.py")
    answer = _function(acts, "discuss_answer")
    assert 'kinds=("incident.evidence"' not in answer and "self.audit.append(key, \"discuss.answer\"" in answer
    assert '"cites": answer.cites[:20]' in answer and '"answer": ' not in answer  # its words are not kept as fact
