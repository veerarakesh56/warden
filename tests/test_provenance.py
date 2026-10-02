"""Every diagnosis records which model said it, to exactly which prompt, under which code and policies (audit A-P-1)."""

from __future__ import annotations

import hashlib

from warden import audit, graph
from warden.cli import _alert_from
from warden.llm import LLMClient


def test_the_diagnose_row_names_the_model_the_prompt_the_answer_and_the_code(monkeypatch):
    seen = {}
    real = LLMClient.structured

    def spy(self, *, system, user, **kw):
        seen["system"], seen["user"] = system, user
        out = real(self, system=system, user=user, **kw)
        seen["response"] = out.model_dump_json()
        return out

    monkeypatch.setattr(LLMClient, "structured", spy)
    report = graph.run(_alert_from("inc-001"), llm=LLMClient(mock=True))
    [row] = [s for s in report.audit if s["node"] == "diagnose"]
    p = row["provenance"]

    def sha(text):
        return hashlib.sha256(text.encode()).hexdigest()

    assert (p["provider"], p["model"]) == ("mock", "mock")
    assert p["system_sha256"] == sha(seen["system"]) and p["prompt_sha256"] == sha(seen["user"])
    assert p["response_sha256"] == sha(seen["response"])
    assert p["code"] == audit.code_version() and len(p["code"]) == 64
    assert seen["user"] not in str(row)  # hashes only: no prompt text in the record


def test_the_code_hash_changes_with_any_policy_file(tmp_path, monkeypatch):
    import shutil

    import warden

    pkg = tmp_path / "warden"
    shutil.copytree(warden.__path__[0], pkg, ignore=shutil.ignore_patterns("__pycache__"))
    monkeypatch.setattr(audit, "__file__", str(pkg / "audit.py"))
    audit.code_version.cache_clear()
    try:
        before = audit.code_version()
        yaml = pkg / "data" / "environments.yaml"
        yaml.write_bytes(yaml.read_bytes() + b"\n# changed\n")
        audit.code_version.cache_clear()
        assert audit.code_version() != before
    finally:
        monkeypatch.undo()
        audit.code_version.cache_clear()
