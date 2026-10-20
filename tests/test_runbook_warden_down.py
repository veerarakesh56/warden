"""Register C13: docs/RUNBOOK-WARDEN-DOWN.md says what a person does when WARDEN itself is down. It is read when
nothing else works, so every command in it must exist and every AWS name in it must be one the Terraform builds.
And a document the register, the code or the Terraform cites must exist: FAILURE-MODES.md cited this runbook for
weeks while it did not (B29, 2026-10-17)."""

from __future__ import annotations

import pathlib
import re
import shlex

import pytest
import yaml

from warden import cli

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUNBOOK = ROOT / "docs" / "RUNBOOK-WARDEN-DOWN.md"
MODULE = ROOT / "terraform" / "modules" / "warden-runtime"
RUNTIME_ROOT = ROOT / "terraform" / "runtime" / "main.tf"
RUNTIME_ENV = yaml.safe_load((ROOT / "src" / "warden" / "data" / "environments.yaml").read_text(encoding="utf-8"))[
    "runtime"]


class _Parsed(BaseException):  # not an Exception: main() must not swallow it
    pass


def _text() -> str:
    """The runbook, or nothing when it is missing: then every test below fails on its own, none at collection."""
    return RUNBOOK.read_text(encoding="utf-8") if RUNBOOK.is_file() else ""


def _blocks() -> list[str]:
    return [line.strip() for b in re.findall(r"```\n(.*?)```", _text(), re.DOTALL) for line in b.splitlines()]


def _warden_commands() -> list[str]:
    return [line for line in _blocks() if line.startswith("warden ")]


def _hcl() -> str:
    return "\n".join(p.read_text(encoding="utf-8") for p in sorted(MODULE.glob("*.tf")))


def _map_body(hcl: str, local: str) -> str:
    """The whole body of `<local> = { ... }`, found by matching braces, so a nested map written over several lines
    never ends it early."""
    head = re.search(r"^[ \t]*" + re.escape(local) + r"[ \t]*=[ \t]*\{", hcl, re.MULTILINE)
    assert head, local
    depth = 1
    for i in range(head.end(), len(hcl)):
        depth += {"{": 1, "}": -1}.get(hcl[i], 0)
        if depth == 0:
            return hcl[head.end():i]
    raise AssertionError(f"{local}: no closing brace")


def _top_level_keys(body: str) -> set[str]:
    keys, depth = set(), 0
    for line in body.splitlines():
        m = re.match(r"\s*([a-z][a-z-]*)\s*=\s*\{", line)
        if depth == 0 and m:
            keys.add(m.group(1))
        depth += line.count("{") - line.count("}")
    return keys


def _keys_of(local: str) -> set[str]:
    """The top-level keys of a `name = { key = {...} ... }` map in the module's locals (zones, front_doors)."""
    return _top_level_keys(_map_body(_hcl(), local))


def test_a_map_written_over_several_lines_keeps_every_key():
    hcl = "zones = {\n  a = {\n    inner = { x = 1 }\n  }\n  b = { y = 2 }\n}\nother = { c = {} }\n"
    assert _top_level_keys(_map_body(hcl, "zones")) == {"a", "b"}


def _built_names() -> set[str]:
    """Every `warden-<env>-<suffix>` name the module gives a resource: literal suffixes, and the zones' and the front
    doors' names where a resource is made `for_each` of them."""
    names = set(re.findall(r'"warden-\$\{var\.environment\}-([a-z][a-z-]*[a-z])"', _hcl()))
    return names | _keys_of("zones") | _keys_of("front_doors")


def test_the_runbook_has_what_a_person_needs_when_warden_is_down():
    text = _text()
    for section in ("How you find out", "people take over", "stop changes", "Find which part is down",
                    "Bring it back", "After it is back"):
        assert section in text, section
    joined = "\n".join(_blocks())
    for needed in ("warden killswitch on", "warden audit verify", "--desired-count 0", "aws sqs receive-message",
                   "aws cloudwatch describe-alarms --state-value ALARM", "aws sns publish",
                   # Stopping act is confirmed, not only asked for (PR 86 review): a running task acts until it stops.
                   "aws ecs wait services-stable --cluster warden-ops-runtime --services warden-ops-act"):
        assert needed in joined, needed


def test_the_runbook_names_every_zone_and_every_self_alarm():
    """A zone or a self-alarm added later must be added here too, or the runbook stops covering it."""
    text = _text()
    missing = [z for z in _keys_of("zones") if f"warden-{RUNTIME_ENV}-{z}" not in text]
    alarms = re.findall(r'alarm_name\s*=\s*"warden-\$\{var\.environment\}-([a-z-]+)"', _hcl())
    self_alarms = [a for a in alarms if a in ("heartbeat-missing", "synthetic-missing", "alarm-dlq")]
    assert sorted(self_alarms) == ["alarm-dlq", "heartbeat-missing", "synthetic-missing"], alarms
    missing += [a for a in self_alarms if f"warden-{RUNTIME_ENV}-{a}" not in text]
    assert not missing, missing


def test_every_aws_name_in_the_runbook_is_one_the_terraform_builds():
    named = set(re.findall(rf"\bwarden-{RUNTIME_ENV}-([a-z][a-z-]*[a-z])\b", _text()))
    assert named, "the runbook names no runtime resource"
    built = _built_names()
    assert not named - built, sorted(named - built)


def test_every_ssm_parameter_the_runbook_reads_is_one_the_runtime_reads():
    params = set(re.findall(rf"/warden/{RUNTIME_ENV}/tf/([a-z_]+)", _text()))
    assert params >= {"paused", "page_topic_arn"}, params
    root = RUNTIME_ROOT.read_text(encoding="utf-8")
    read = set(re.findall(r'lookup\(local\.(?:tf|csv), "([a-z_]+)"', root))
    assert not params - read, sorted(params - read)


@pytest.mark.parametrize("command", _warden_commands())
def test_every_warden_command_in_the_runbook_parses(command, monkeypatch):
    def stop(self, args=None, namespace=None):
        raise _Parsed(original(self, args, namespace))

    original = cli._Parser.parse_args
    monkeypatch.setattr(cli._Parser, "parse_args", stop)
    argv = [a if not (a.startswith("<") and a.endswith(">")) else "x" for a in shlex.split(command)[1:]]
    with pytest.raises(_Parsed):
        cli.main(argv)


_CITED_DOC = re.compile(r"\bdocs/[\w./-]+\.md\b")


def _cited_docs() -> list[tuple[str, str]]:
    files = [ROOT / "docs" / "FAILURE-MODES.md", *sorted((ROOT / "src").rglob("*.py")),
             *sorted((ROOT / "terraform").rglob("*.tf"))]
    return [(str(f.relative_to(ROOT)), m.group()) for f in files for m in _CITED_DOC.finditer(f.read_text(encoding="utf-8"))]


def test_every_document_the_register_code_or_terraform_cites_exists():
    cited = _cited_docs()
    assert any(doc == "docs/RUNBOOK-WARDEN-DOWN.md" for _, doc in cited)  # the citation that started this
    missing = sorted({(where, doc) for where, doc in cited if not (ROOT / doc).is_file()})
    assert not missing, missing
