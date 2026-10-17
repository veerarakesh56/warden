"""brand._drop_xmlns removes what the old regex removed - every xmlns attribute that follows white space, with that white
space - in time that grows with the text's length (Sonar python:S8786, 2026-10-17: 20,000 spaces took the regex 1.7 s,
the square of the run). It was compared with the regex on 400,000 random strings when it was written (PR text)."""

from __future__ import annotations

import time

import pytest

from warden import brand

CASES = {
    '<svg xmlns="http://www.w3.org/2000/svg" class="logo">': '<svg class="logo">',
    '<svg  \n xmlns="a"\txmlns:xlink="b" x="1">': '<svg x="1">',
    '<svg\u2028xmlns="a">': "<svg>",  # any white space, as `\s` reads it
    'xmlns="a" <svg>': 'xmlns="a" <svg>',  # none before it: kept
    '<svg x="1"xmlns="a">': '<svg x="1"xmlns="a">',
    '<svg xmlns:="a">': '<svg xmlns:="a">',  # not an attribute name
    '<svg xmlns="a': '<svg xmlns="a',  # unclosed
    'xmlns="a xmlns="b"': 'xmlns="a',  # the second, after a space inside the first's quotes, is the one removed
    '  xmlns="a"  xmlns="b"': "",
}


@pytest.mark.parametrize("text", CASES)
def test_it_removes_what_the_old_pattern_removed(text):
    assert brand._drop_xmlns(text) == CASES[text]


def test_the_logo_is_unchanged():
    assert brand.LOGO_SVG == brand._RAW  # the approved icon carries no xmlns; the step stays for a replaced one


@pytest.mark.parametrize("text", [" " * 200_000 + "x", 'xmlns="' * 40_000, ' xmlns="' + "a" * 200_000,
                                  ' xmlns="a"' * 20_000], ids=["spaces", "quotes", "unclosed", "many"])
def test_the_worst_inputs_are_read_in_linear_time(text):
    start = time.perf_counter()
    brand._drop_xmlns(text)
    assert time.perf_counter() - start < 1.0
