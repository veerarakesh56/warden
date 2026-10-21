"""The pipelines as they run: each root workflow with its components' composite actions written out in place.

Since 2026-10-21 every component keeps its CI/CD steps in its own composite actions (<component>/.github/actions/*)
and the root workflows (.github/workflows, the only place GitHub runs them from) call those actions with
`uses: $/<component>/.github/actions/<name>` (GitHub's self-repository syntax). The tests that hold the pipelines to their rules read them through this
module, so a step moved into an action is still checked where it runs: `text()` replaces each such step with the
action's own steps (re-indented, its inputs replaced by what the workflow passes), `load()` parses that.
"""

from __future__ import annotations

import pathlib
import re
import textwrap

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
FLOWS = ROOT / ".github" / "workflows"
COMPONENTS = ("warden", "infra", "demo-app", "fault-lab", "helios")
_LOCAL_USE = re.compile(r"^(?P<indent>[ ]*)- uses: (?:\./|\$/)(?P<path>[\w./-]+?)/?\s*(?:#.*)?$")


def files() -> list[pathlib.Path]:
    """Every root workflow."""
    return sorted(FLOWS.glob("*.yml"))


def actions() -> list[pathlib.Path]:
    """Every component's composite action."""
    return sorted(p for c in COMPONENTS for p in (ROOT / c / ".github" / "actions").glob("*/action.yml"))


def _path(flow: str | pathlib.Path) -> pathlib.Path:
    p = pathlib.Path(flow)
    return p if p.is_absolute() else FLOWS / p


def _value(raw: object) -> tuple[str, str]:
    """(text for `${{ inputs.x }}`, text for `inputs.x` inside an expression) of a value the workflow passes."""
    text = str(raw)
    m = re.fullmatch(r"\$\{\{\s*(.*?)\s*\}\}", text)
    if m:
        return text, m.group(1)
    return f'"{text}"', "'" + text.replace("'", "''") + "'"


def _steps_of(action: pathlib.Path, given: dict) -> str:
    """The action's steps (items at 4 spaces), its inputs replaced by what the caller gave or their defaults."""
    text = action.read_text(encoding="utf-8")
    doc = yaml.safe_load(text)
    assert doc["runs"]["using"] == "composite", action
    body = text[text.index("\n  steps:\n") + len("\n  steps:\n"):]
    for name, spec in (doc.get("inputs") or {}).items():
        raw = given.get(name, (spec or {}).get("default", ""))
        whole, expr = _value(raw)
        body = re.sub(r"\$\{\{\s*inputs\." + re.escape(name) + r"\s*\}\}", lambda _m, w=whole: w, body)
        body = re.sub(r"(?<![\w.])inputs\." + re.escape(name) + r"\b", lambda _m, e=expr: e, body)
    return body


def text(flow: str | pathlib.Path) -> str:
    """The workflow's text with every local composite action's steps written out where it is used."""
    lines = _path(flow).read_text(encoding="utf-8").splitlines(keepends=True)
    out: list[str] = []
    i = 0
    while i < len(lines):
        m = _LOCAL_USE.match(lines[i])
        action = ROOT / m.group("path") / "action.yml" if m else None
        if not (m and action.is_file()):
            out.append(lines[i])
            i += 1
            continue
        indent = len(m.group("indent"))
        j = i + 1
        while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip(" ")) > indent):
            j += 1
        step = yaml.safe_load(textwrap.dedent("".join(lines[i:j])))[0]
        body = _steps_of(action, step.get("with") or {})
        shift = indent - 4
        for line in body.splitlines(keepends=True):
            if not line.strip():
                out.append(line)
            elif shift >= 0:
                out.append(" " * shift + line)
            else:
                out.append(line[-shift:])
        if not body.endswith("\n"):
            out.append("\n")
        i = j
    return "".join(out)


def load(flow: str | pathlib.Path) -> dict:
    """The workflow, parsed, with its composite actions' steps in place (PyYAML reads the key `on` as True)."""
    return yaml.safe_load(text(flow))


def local_actions_used(flow: str | pathlib.Path) -> list[str]:
    """The `<component>/.github/actions/<name>` paths a workflow calls (repository-relative)."""
    return [m.group("path") for line in _path(flow).read_text(encoding="utf-8").splitlines()
            if (m := _LOCAL_USE.match(line))]
