"""SonarCloud S6353/S5869/S5843/S6019 rewrites kept every pattern's meaning. In Python's default (Unicode) mode
`\\d` and `\\w` also match other scripts' digits and letters, so each pattern that now says `\\d` or `\\w` where it
said [0-9] or [A-Za-z0-9_] is ASCII-only - an Arabic-Indic or a mathematical digit must still not count."""

from __future__ import annotations

import pytest

from warden import (
    discuss,
    evidence,
    gate,
    grounding,
    models,
    quarantine,
    records,
    redaction,
    timeline,
    tripwire,
)

ARABIC_3 = chr(0x0663)  # ARABIC-INDIC DIGIT THREE: a Unicode \d
MATH_1 = chr(0x1D7D9)  # MATHEMATICAL DOUBLE-STRUCK DIGIT ONE: a Unicode \d
E_ACUTE = chr(0xE9)  # a Unicode \w


@pytest.mark.parametrize("pattern,ascii_text", [
    (records._DAY, "2026-10-20"),
    (records._PAGE_NO, "12"),
    (discuss.INCIDENT, "0123456789abcdef-20261020T062500Z"),
    (evidence._REVISION, "orders:12"),
    (timeline._SHA, "1234567a"),
])
def test_ascii_digits_only(pattern, ascii_text):
    assert pattern.fullmatch(ascii_text)
    for digit in (ARABIC_3, MATH_1):
        swapped = ascii_text.replace("2", digit)
        assert not pattern.fullmatch(swapped), (pattern.pattern, swapped)


def test_ascii_word_characters_only():
    assert evidence._CHANGE_EVENT.match("CHANGE a b PutRule on x")
    assert not evidence._CHANGE_EVENT.match(f"CHANGE a b Put{E_ACUTE}Rule on x")
    assert quarantine._KEY_ERROR.search("KeyError: 'user_id'").group(1) == "user_id"
    assert quarantine._KEY_ERROR.search(f"KeyError: 'user{E_ACUTE}'") is None
    assert grounding._EVENT_NAME.fullmatch("PutRuleTargets_2")
    assert not grounding._EVENT_NAME.fullmatch(f"PutRuleTargets{ARABIC_3}")


def test_the_invisible_classes_still_hold_their_astral_ranges():
    for c in (0x1BCA0, 0x1BCA3, 0xE0100, 0xE01EF):
        assert gate._INVISIBLE.fullmatch(chr(c)), hex(c)
    for c in (0x1BCA4, 0xE00FF, 0xE01F0):
        assert not gate._INVISIBLE.fullmatch(chr(c)), hex(c)
    for c in (0xE0000, 0xE0041, 0xE007F):
        assert models._INVISIBLE.fullmatch(chr(c)), hex(c)
    assert not models._INVISIBLE.fullmatch(chr(0xE0080))


def test_a_putty_key_is_masked_up_to_its_mac_line_or_the_end():
    putty = next(p for n, p in redaction.PATTERNS if n == "PRIVKEY" and p.pattern.startswith("Private-Lines"))
    text = "PuTTY-User-Key-File-3: ssh-rsa\nPrivate-Lines: 2\nAAAA\nBBBB\r\nPrivate-MAC: cafe\n"
    assert putty.findall(text) == ["AAAA\nBBBB"]
    assert putty.findall("Private-Lines: 1\nAAAA\nBBBB") == ["AAAA\nBBBB"]  # cut off: masked to the end


def test_the_joined_patterns_are_the_ones_they_replaced():
    assert tripwire._SEGMENT.split("one. two\nthree, four key=1") == ["one.", "two", "three", "four", "key=1"]
    found = [m.groups() for m in quarantine._JSON_KV.finditer('{"user": "ada", "n": 12, "ok": true}')]
    assert found == [("user", "ada", None), ("n", None, "12"), ("ok", None, "true")]
