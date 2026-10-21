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


class _RecordingClient(_Client):
    """Answers per document and records what each call asked for."""

    def __init__(self, per_doc):
        self.per_doc, self.asked = per_doc, []

    def get_paginator(self, name):
        client = self

        class Pager:
            def paginate(self, policyDocument, **kind):
                client.asked.append(kind)
                return [{"findings": client.per_doc[policyDocument][:1]}, {"findings": None},
                        {"findings": client.per_doc[policyDocument][1:]}]
        return Pager()


def test_every_finding_is_printed_by_severity_with_where_it_is(tmp_path, monkeypatch, capsys):
    """Characterisation (before the cognitive-complexity split of main): per file, its counts then each finding by
    severity with its location; a trust file validated as the role's resource policy; a known-unlisted action left
    out; the threshold counted across files."""
    monkeypatch.setattr(vp, "ROOT", tmp_path)
    (tmp_path / "policy-a.json").write_text("A", encoding="utf-8")
    (tmp_path / "trust-b.json").write_text("B", encoding="utf-8")
    loc = [{"path": [{"value": "Statement"}, {"index": 0}, {"value": "Action"}]}, {"path": [{"index": 2}]}]
    per_doc = {
        "A": [{"findingType": "SUGGESTION", "issueCode": "EMPTY", "findingDetails": "s", "locations": []},
              {"findingType": "WARNING", "issueCode": "W1", "findingDetails": "x" * 200, "locations": loc},
              {"findingType": "ERROR", "issueCode": "INVALID_ACTION",
               "findingDetails": "rds:EnableInternetAccessGateway is not a valid action"}],
        "B": [{"findingType": "SECURITY_WARNING", "issueCode": "PASS_ROLE", "findingDetails": "broad"},
              {"findingType": "ERROR", "issueCode": "INVALID_ACTION", "findingDetails": "nope:Do"}],
    }
    client = _RecordingClient(per_doc)
    assert vp.main(["--glob", "*.json", "--strict"], client=client) == 1
    assert client.asked == [{"policyType": "IDENTITY_POLICY"},
                            {"policyType": "RESOURCE_POLICY",
                             "validatePolicyResourceType": "AWS::IAM::AssumeRolePolicyDocument"}]
    assert capsys.readouterr().out == (
        "policy-a.json: 0 error, 0 security_warning, 1 warning, 1 suggestion\n"
        f"   WARNING          W1: {'x' * 160}  [Statement/0/Action, 2]\n"
        "   SUGGESTION       EMPTY: s\n"
        "trust-b.json: 1 error, 1 security_warning, 0 warning, 0 suggestion\n"
        "   ERROR            INVALID_ACTION: nope:Do\n"
        "   SECURITY_WARNING PASS_ROLE: broad\n"
        "\n3 finding(s) at or above the threshold.\n")


def test_no_file_and_no_client_are_not_clean(tmp_path, monkeypatch, capsys):
    import types

    monkeypatch.setattr(vp, "ROOT", tmp_path)
    assert vp.main(["--glob", "*.json"]) == 1
    assert capsys.readouterr().out == "no policy files matched '*.json'\n"
    (tmp_path / "p.json").write_text("{}", encoding="utf-8")

    def no_session(**_):
        raise ValueError("no credentials")

    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(Session=no_session))
    assert vp.main(["--glob", "*.json"]) == 2
    assert capsys.readouterr().out == "could not create an Access Analyzer client: ValueError: no credentials\n"


def test_a_clean_run_says_so(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(vp, "ROOT", tmp_path)
    (tmp_path / "p.json").write_text("{}", encoding="utf-8")
    assert vp.main(["--glob", "*.json"], client=_Client([_finding("WARNING")])) == 0
    assert capsys.readouterr().out == ("p.json: 0 error, 0 security_warning, 1 warning, 0 suggestion\n"
                                       "   WARNING          X: d\n\nclean - nothing at or above the threshold\n")
