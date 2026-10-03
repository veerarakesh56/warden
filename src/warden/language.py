"""Which log lines are not English (register M23).

WARDEN's keyword checks - the signature catalogue's log terms, P12's symptom words, the quarantine's phrases - are
English. Logs in another language lose them: the incident goes unrecognised, which escalates it (P24), but a person
should know why. This does not translate; it tells. A line is counted as not English when most of its letters are
outside the Latin alphabet, or when it carries more function words of another language than of English. Code-shaped
content - keys, codes, numbers, `OOMKilled` - is the same in every language and stays in the evidence either way.
"""

from __future__ import annotations

import re

_WORD = re.compile(r"[^\W\d_]+", re.UNICODE)
_ENGLISH = frozenset([
    "the", "is", "was", "are", "not", "for", "with", "on", "to", "of", "and", "in", "it", "this", "that", "be",
    "has", "have", "after", "before",
])
# Spanish, Portuguese, French, German and Italian function words that are not English words.
_OTHER = frozenset([
    "el", "la", "los", "las", "del", "que", "por", "una", "con", "para", "se", "ha", "sido", "está",
    "não", "uma", "foi", "com", "são",
    "le", "les", "des", "une", "est", "pas", "pour", "dans", "avec", "sur", "été", "du", "au",
    "der", "die", "das", "und", "nicht", "ist", "ein", "eine", "mit", "für", "auf", "wurde", "wird", "nach", "beim",
    "il", "della", "non", "è", "stato", "sono", "gli",
]) - _ENGLISH


def foreign(line: str) -> bool:
    letters = [c for c in line if c.isalpha()]
    if letters and sum(1 for c in letters if not ("a" <= c.lower() <= "z")) / len(letters) > 0.3:
        return True
    words = [w.lower() for w in _WORD.findall(line)]
    other = sum(1 for w in words if w in _OTHER)
    return other >= 2 and other > sum(1 for w in words if w in _ENGLISH)


def foreign_share(lines: list[str]) -> float:
    """The share of log lines that are not English (0 when there are none)."""
    return sum(1 for line in lines if foreign(line)) / len(lines) if lines else 0.0
