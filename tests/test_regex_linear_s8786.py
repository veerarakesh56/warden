"""Regexes that read text a model, a log or an alert wrote run in time that grows with the length of that text, not
its square (Sonar python:S8786, 2026-10-16). Each input below is the worst case of the pattern it was before: 20,000
characters took it seconds - 8,000 already took 0.4-2 s, four times 4,000 - and takes these milliseconds. The
matches themselves are pinned in each module's own tests; a few here show the rewrite matches what it did."""

from __future__ import annotations

import time

import pytest

from warden import aws_stack, chatops, gate, grounding, playbook, quarantine, redaction

N = 20_000
CASES = {
    # Tried from one place only, so the old pattern was quadratic in one match: 20,000 spaces took 0.6 s, 60,000 take 5.
    "an `ago` after a long run of spaces": (lambda s: grounding._AGO.match(s, 0), " " * (3 * N) + "x"),
    "a scope clause after a long run of spaces": (lambda s: grounding._SCOPE.sub(" ", s), " " * N + "x"),
    "an image reference in a long word": (lambda s: grounding._IMAGE.sub(" ", s), "a" * N),
    "a fence of many tildes": (gate._FENCE_LINE.match, "~" * N + "\nx"),
    "a host of many non-ASCII letters": (lambda s: gate._NON_ASCII_HOST.sub("", s), "\u00e9" * N),
    "an image path of many segments": (quarantine._IMAGE.findall, "a/" * (N // 2)),
    "a key=value in a long word": (playbook._kv, "a" * N),
    "an htpasswd flag of many letters": (redaction.redact, "htpasswd -" + "b" * N),
}


@pytest.mark.parametrize("name", CASES)
def test_the_worst_case_input_is_read_in_linear_time(name):
    fn, text = CASES[name]
    start = time.perf_counter()
    fn(text)
    assert time.perf_counter() - start < 1.0, name


@pytest.mark.parametrize("target", ["a" * N + " =b", "a" * 70 + "=b"], ids=["a long word", "a 70-letter name"])
def test_an_assignment_in_a_long_name_is_still_refused_quickly(target):
    """The worst case is a long word whose `=` comes after a space; a name longer than the pattern reads is still an
    assignment, its `=` not counted as a resource kind's."""
    proposal = type("P", (), {"target": target})()
    start = time.perf_counter()
    problem = grounding.target_problem(proposal, set())
    assert time.perf_counter() - start < 1.0
    assert problem and "assignment" in problem, problem


def test_the_rewritten_patterns_match_what_they_did():
    assert grounding._AGO.match("5 min ago", 1)
    assert grounding._AGO.match("  ago", 0)
    assert not grounding._AGO.match(" minutes later", 0)
    assert grounding._SCOPE.sub(" ", "checkout (namespace=shop), x").split() == ["checkout", "x"]
    assert grounding._IMAGE.sub(" ", "use repo/app:v1.2 now").split() == ["use", "now"]
    assert chatops._HEADING.match("##   Title").group(1) == "Title"
    assert gate._FENCE_LINE.match("> ```py").groups() == ("> ", "```", "py")
    assert gate._NON_ASCII_HOST.search("go to \u0435vil.example.com").groups() == ("\u0435vil.", "example")
    assert quarantine._IMAGE.findall("pulled <acct>.dkr.ecr/app:1.2 ok") == ["<acct>.dkr.ecr/app:1.2"]
    assert aws_stack._EXCEPTION.match("[ERROR] KeyError: 'x'").groups() == ("KeyError", "'x'")
    assert playbook._kv("a=b c=[1 2] d") == {"a": "b", "c": "[1 2]"}
    assert "s3cret-pw" not in redaction.redact("htpasswd -bc /etc/pw user s3cret-pw").text
