"""The Access Analyzer wrapper, against a stubbed client.

These prove the thresholds and the exit codes, not AWS's verdicts - the point of the script is that
AWS supplies those. What must hold is that an ERROR or SECURITY_WARNING can never be reported as
clean, and that a failure to RUN is never reported as a clean result either.
"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))
import validate_policies as vp


class _Pager:
    def __init__(self, findings, raises=None):
        self.findings, self.raises = findings, raises

    def paginate(self, **_):
        if self.raises:
            raise self.raises
        return [{"findings": self.findings}]


class _Client:
    def __init__(self, findings=(), raises=None):
        self.pager = _Pager(list(findings), raises)

    def get_paginator(self, name):
        assert name == "validate_policy"
        return self.pager


def _finding(kind):
    return {"findingType": kind, "issueCode": "X", "findingDetails": "d", "locations": []}


def test_a_clean_policy_is_clean():
    assert vp.main(["--glob", "terraform/proving-ground/operator-policy.json"], client=_Client()) == 0


def test_an_error_fails():
    assert vp.main(["--glob", "terraform/proving-ground/operator-policy.json"],
                   client=_Client([_finding("ERROR")])) == 1


def test_a_security_warning_fails_even_without_strict():
    """⛔ A security finding is never a warning to wave through."""
    assert vp.main(["--glob", "terraform/proving-ground/operator-policy.json"],
                   client=_Client([_finding("SECURITY_WARNING")])) == 1


def test_a_plain_warning_fails_only_under_strict():
    args = ["--glob", "terraform/proving-ground/operator-policy.json"]
    assert vp.main(args, client=_Client([_finding("WARNING")])) == 0
    assert vp.main(args + ["--strict"], client=_Client([_finding("WARNING")])) == 1


def test_being_unable_to_run_is_not_a_clean_result():
    """⛔ An AccessDenied must not print "clean". Exit 2 says the check did not happen."""
    assert vp.main(["--glob", "terraform/proving-ground/operator-policy.json"],
                   client=_Client(raises=RuntimeError("AccessDeniedException"))) == 2
