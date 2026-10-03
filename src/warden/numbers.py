"""Numbers in what the model wrote, checked against the metrics WARDEN read (register M2).

A quote must be verbatim (P13), but the model's own prose is not a quote: "error rate 42%" over `error_rate=0.042`,
or "p99 latency 21 s" over `p99_latency_ms=2140`, is a misread a reader may act on. A number with a unit - a
percentage or a duration - that comes right after the words of a metric's name is put in one unit (fractions,
seconds) and must match that metric within 5%. A number that names no metric is left alone (an interval, a window,
a count), and so is one without a unit.

Measured 2026-10-03 on the published runs: compared with every metric of its kind, the check fired on 85 of 132
answers - mostly a CloudWatch percentage below one (CPU 0.0047 means 0.0047%) read as a fraction, and intervals
("15s") that are not metrics. Hence only named metrics, named by the words since the previous number ("cpu 43%, mem
65%": the 65% is not the CPU's); a value under one is accepted as either a fraction or a percentage; and a number
is allowed the rounding its own digits show ("0.005%" stands for 0.0045% to 0.0055%).
"""

from __future__ import annotations

import re

# Minutes are left out: in prose they mostly describe a window ("over the last 15 minutes"), not a measurement.
_CLAIM = re.compile(r"(?<![\w.])(\d+(?:\.\d+)?)\s*(%|percent\b|ms\b|milliseconds?\b|s\b|secs?\b|seconds?\b)",
                    re.IGNORECASE)
# A standalone number - not the digits inside a word like "p99" or "http2" - ends the words that can name the next.
_NUMBER = re.compile(r"(?<![A-Za-z0-9_.])\d+(?:\.\d+)?")
_FRACTION_NAME = re.compile(r"rate|ratio|utili[sz]ation|usage|percent|pct|fraction", re.IGNORECASE)
_TOLERANCE = 0.05


_UNIT_WORDS = {"ms", "s", "secs", "seconds", "pct", "percent"}


def _canonical(name: str, value: float) -> tuple[str, float] | None:
    """A metric in a canonical unit and its kind - `fraction` (0..1) or `seconds` - or None for a plain count."""
    n = name.lower()
    if n.endswith("_ms") or "_ms_" in n or "latency_ms" in n:
        return "seconds", value / 1000
    if n.endswith(("_seconds", "_secs", "_s", "lag")) or "_seconds_" in n:
        return "seconds", value
    if _FRACTION_NAME.search(n):
        return "fraction", value / 100 if value > 1 else value
    return None


def _readings(name: str, value: float) -> list[float]:
    """Every honest reading of a metric in its canonical unit: a fraction-kind value under one may be a fraction
    (error_rate=0.042) or a percentage (CloudWatch CPUUtilization=0.0047, meaning 0.0047%)."""
    kind, v = _canonical(name, value) or ("", value)
    return [v, value / 100] if kind == "fraction" and value <= 1 else [v]


# Words of a metric's name too general to name it on their own ("rate" alone could be any rate).
_GENERIC = _UNIT_WORDS | {"rate", "ratio", "count", "total", "per", "sec", "utilisation", "utilization", "usage",
                          "avg", "average", "max", "min", "sum", "p50", "p90", "p95"}


def _named(before: str, metrics: dict[str, float]) -> list[str]:
    """The metrics the last three words before a number name: a distinctive word of the name is there ("cpu" names
    cpu_utilisation, "p99" names p99_latency_ms, "error" names error_rate). Only the last three: in "CPU near-zero
    and mem ~59%" the 59% is memory's, not the CPU's."""
    words = set(re.findall(r"[a-z0-9]+", before.lower())[-3:])
    return [m for m in metrics if (set(m.lower().split("_")) - _GENERIC) & words]


def _rounding(number: str, unit: str) -> float:
    """Half the last written digit, in canonical units: "0.005%" may be any value from 0.0045% to 0.0055%."""
    decimals = len(number.split(".", 1)[1]) if "." in number else 0
    kind, _ = _claim(number, unit)
    per = 0.01 if kind == "fraction" else (0.001 if unit.lower().startswith(("ms", "milli")) else 1.0)
    return 0.5 * 10 ** -decimals * per


def _claim(number: str, unit: str) -> tuple[str, float]:
    v, u = float(number), unit.lower()
    if u in ("%", "percent"):
        return "fraction", v / 100
    if u.startswith(("ms", "milli")):
        return "seconds", v / 1000
    return "seconds", v


def problems(texts: list[str], metrics: dict[str, float]) -> list[str]:
    """Every number with a unit in `texts` that no metric of its kind supports."""
    canon = {name: c for name, v in metrics.items() if (c := _canonical(name, v))}
    out = []
    for text in texts:
        text = text or ""
        previous = 0
        for m in _CLAIM.finditer(text):
            # The words that can name this number's metric: those since the previous number, nothing further back.
            digits = [d.end() for d in _NUMBER.finditer(text[:m.start()])]
            before, previous = text[max(previous, digits[-1] if digits else 0):m.start()], m.end()
            kind, value = _claim(m.group(1), m.group(2))
            # "error rate 42%" is about error_rate: compared with that metric alone, not with whichever fraction
            # happens to be near 0.42. A number that names no metric is compared with every metric of its kind.
            named = [n for n in _named(before, metrics) if canon.get(n, ("",))[0] == kind]
            if not named:
                continue
            pool = [r for n in named for r in _readings(n, metrics[n])]
            slack = _rounding(m.group(1), m.group(2))
            if not any(abs(value - v) <= max(_TOLERANCE * abs(v), slack) for v in pool):
                out.append(f"'{m.group(0).strip()}' does not match {', '.join(named)} as WARDEN read it")
    return out
