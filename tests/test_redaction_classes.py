"""Every class the owner listed (2026-10-21) is masked, with a corpus for each - and the evidence WARDEN reasons from
is not: timestamps, resource names, a Kubernetes service's name, AWS's own host names, version strings, status codes.

Values are built from parts where their shape alone would trip a secret scanner (tests/fakes.py's rule)."""

from __future__ import annotations

import pytest

from privacy_corpus import KEPT, MASKED
from warden import egress
from warden.redaction import redact


@pytest.mark.parametrize(("kind", "text"), [(k, t) for k, texts in MASKED.items() for t in texts])
def test_every_listed_class_is_masked(kind, text):
    out = redact(text)
    kinds = {p.strip("<>").rsplit("_", 1)[0] for p in out.mapping}
    assert kind in kinds, (text, out.text)
    for value in out.mapping.values():
        assert value not in out.text


@pytest.mark.parametrize("text", KEPT)
def test_the_evidence_warden_reasons_from_is_kept(text):
    assert redact(text).text == text


@pytest.mark.parametrize(("kind", "text"), [(k, t) for k, texts in MASKED.items() for t in texts])
def test_every_listed_class_is_refused_at_the_door(kind, text):
    """The egress check holds the same list: none of them leaves raw."""
    assert kind in egress.kinds_in(text)


def test_names_in_free_prose_are_not_found_and_that_is_said():
    """The honest limit (owner: "state it plainly"): a name with no field, title or greeting before it is a word to a
    pattern. Pinned, so the day it changes the docs change with it."""
    assert redact("priya nair restarted the pod").text == "priya nair restarted the pod"
