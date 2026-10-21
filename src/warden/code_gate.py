"""The code gate: plain rules that decide whether a change WARDEN wrote may become a pull request (register B4).

WARDEN may one day open a pull request for a code fix: first a revert of the deployed change its evidence names, then a
small fix for a code-review finding on that change. A model may draft such a change; it never decides whether the
change goes anywhere. This module does, and it is pure: a change in, a verdict out - no network, no clock, no model.

What a change is: the files of a unified diff (`git diff` output, parsed by `parse_diff`), as `FileChange`s. What the
gate needs besides: the environment's `code_fix` mode (environments.yaml) and tier, the limits in
data/code_fix.yaml, for a new import the top-level modules the file and its application already import, and the
new text of every changed Python file (`sources`), which the gate parses: a Python file whose text it was not given,
or that does not parse, is refused.

The rules, each with an id a verdict lists (every one that fires, not just the first):

- CG0 the environment's mode: `off` refuses everything; only the nonprod tier is ever `auto` (the prod tier is refused
  at load and capped here, and so is a tier no one listed).
- CG1 size: an empty change, more lines than the limit (a revert has its own), more files than the limit.
- CG2 path shape: every path plain - no `..`, no absolute path, no quoting, no `.git` folder in any case.
- CG3 allowed paths: every path, a renamed file's old path too, matches data/code_fix.yaml's `allowed_paths`.
- CG4 never touched, whatever that list says: CODEOWNERS, workflows and every file CI or a test run executes on its
  own (`.github/`, `conftest.py`, `Makefile` ...), IAM and infrastructure (`iam/`, `terraform/`, `k8s/`, policies),
  secrets (key files, `.env`), WARDEN's own code and policy data, and a secret-shaped value in any added line.
- CG5 dependency manifests and lock files (pyproject.toml, requirements*.txt, uv.lock, package.json, Dockerfile ...).
- CG6 no new dependency and no code that runs other code or reaches the network. Read twice: each added line by
  pattern, and each changed Python file as Python reads it (`ast`), where an added line may not import a module the
  file or its application does not already import (unless `SAFE_IMPORTS` holds it), import or use a module that runs
  code or reaches the network (`DENIED_MODULES`, `os.system` and the like), name `exec`, `eval`, `compile`,
  `__import__`, `globals` or `vars`, reach an attribute by a computed name, or name an interpreter internal
  (`__globals__`, `__subclasses__` ...). An added Python line is ASCII only and declares no source encoding but utf-8:
  Python reads a fullwidth `exec` (U+FF45 for its e) as `exec`, and a `coding: utf-7` file as other text than the
  gate does.
- CG7 file kind: a binary file, a symbolic link, a submodule or a changed file mode.
- CG8 a fix must add a test: an added test function or assertion in a test file.
- CG9 no weakening: no new suppression (`noqa`, `nosec`, `type: ignore`, `pyre-ignore`, a skip or xfail, a warnings
  filter that ignores, a scanner's line marker ...) anywhere; in a test file, nothing that stops tests from running or
  failing (`__test__`, `pytestmark`, a `return` in a test, `sys.exit`, `os._exit`, `pytest.exit`, `getattr` on
  `pytest`); a fix removes no assertion, test function or test file.
- CG10 a revert is exactly the inverse of the commit it names: the same files, every added line the original's removed
  line and the other way round, in order, at the same lines.

A change every rule passes is `allowed`. In an environment whose mode is `propose`, a person merges it; under `auto`
(never the prod tier) it is only *eligible* to merge itself - the later checks (CI, Eldane, code review) decide that.
"""

from __future__ import annotations

import ast
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from functools import cache
from importlib import resources
from typing import Any

import yaml


class CodeFixMode(StrEnum):
    """`code_fix` in environments.yaml: whether WARDEN may write code-fix pull requests in an environment."""

    off = "off"          # never
    propose = "propose"  # a pull request a person merges
    auto = "auto"        # may merge itself once every check is green - never in the prod tier


class ChangeKind(StrEnum):
    revert = "revert"  # undo a deployed commit, exactly
    fix = "fix"        # a small change with its own test


class CodeGateError(RuntimeError):
    """data/code_fix.yaml, or a diff, is malformed. A malformed diff is never passed: the change is refused."""


PROD_TIER = "prod"
# Every tier an environment may name (environments.yaml; a misspelled `Prod` or `production` is refused at load). Only
# the nonprod tier is ever `auto`: anything else - prod, unknown, a tier no one listed - is capped at `propose`.
TIERS = frozenset({PROD_TIER, "nonprod", "unknown"})
AUTO_TIERS = frozenset({"nonprod"})
_ADDED, _MODIFIED, _DELETED, _RENAMED = "added", "modified", "deleted", "renamed"
_REGULAR = "100644"
_EXECUTABLE = "100755"


@dataclass(frozen=True)
class FileChange:
    """One file of a change. `added` and `removed` are the lines, in diff order, without their `+`/`-`; `hunks` (from
    `parse_diff`) each hunk's lines with their sign, context included, and `starts` each hunk's first line on the old
    and the new side (`@@ -old +new @@`), so a revert is checked where it applies too."""

    path: str
    status: str = _MODIFIED
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    old_path: str | None = None
    old_mode: str = _REGULAR
    new_mode: str = _REGULAR
    binary: bool = False
    hunks: tuple[tuple[str, ...], ...] = ()
    starts: tuple[tuple[int, int], ...] = ()

    @property
    def paths(self) -> tuple[str, ...]:
        return (self.path,) if self.old_path in (None, self.path) else (self.old_path, self.path)


@dataclass(frozen=True)
class Refusal:
    rule: str
    detail: str

    def __str__(self) -> str:
        return f"{self.rule}: {self.detail}"


@dataclass(frozen=True)
class CodeVerdict:
    mode: CodeFixMode
    refusals: tuple[Refusal, ...] = ()

    @property
    def allowed(self) -> bool:
        return not self.refusals

    @property
    def auto_merge_eligible(self) -> bool:
        """Only eligible: under `auto` a change still merges only after every later check is green."""
        return self.allowed and self.mode is CodeFixMode.auto

    @property
    def rules(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(r.rule for r in self.refusals))


# ------------------------------------------------------------------------------------------------ the limits (data)

_CEILING_LINES, _CEILING_FILES = 400, 20


@dataclass(frozen=True)
class GateLimits:
    max_changed_lines: int
    max_revert_lines: int
    max_files: int
    allowed_paths: tuple[str, ...]
    test_paths: tuple[str, ...]
    _allowed: tuple[re.Pattern[str], ...] = field(default=(), repr=False, compare=False)
    _tests: tuple[re.Pattern[str], ...] = field(default=(), repr=False, compare=False)

    def allows(self, path: str) -> bool:
        return any(rx.fullmatch(path) for rx in self._allowed)

    def is_test(self, path: str) -> bool:
        return any(rx.fullmatch(path) for rx in self._tests)


_GLOB = re.compile(r"[A-Za-z0-9_.*/-]+")


def glob_regex(glob: str) -> re.Pattern[str]:
    """A path glob as a regex: `**/` any folders (none too), `*` any name within one folder. Nothing else is special
    (`?` and `[x]` are themselves), so a glob means what it says."""
    out, i = [], 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out.append("(?:[^/]+/)*")
            i += 3
        elif glob[i] == "*":
            out.append("[^/]*")
            i += 1
        else:
            out.append(re.escape(glob[i]))
            i += 1
    return re.compile("".join(out))


def _globs(key: str, values: Any) -> tuple[str, ...]:
    if not isinstance(values, list) or not values:
        raise CodeGateError(f"code_fix.yaml: `{key}` must be a non-empty list of path globs")
    for glob in values:
        # Not one that names everything: a glob must start at a named folder or file.
        if not (isinstance(glob, str) and _GLOB.fullmatch(glob)) or glob.startswith(("*", "/")) or ".." in glob:
            raise CodeGateError(f"code_fix.yaml: `{key}` entry {glob!r} must be a relative path glob that starts "
                                "with a folder or file name")
    return tuple(values)


def _bounded(doc: dict[str, Any], key: str, ceiling: int) -> int:
    value = doc.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= ceiling:
        raise CodeGateError(f"code_fix.yaml: `{key}` must be a whole number from 1 to {ceiling}, not {value!r}")
    return value


def load_limits(text: str | None = None) -> GateLimits:
    """data/code_fix.yaml (or `text`), validated. A malformed file raises: no code fix without its limits."""
    if text is None:
        text = (resources.files("warden") / "data" / "code_fix.yaml").read_text(encoding="utf-8")
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise CodeGateError(f"code_fix.yaml is not valid YAML: {exc}") from exc
    if not isinstance(doc, dict) or doc.get("version") != 1:
        raise CodeGateError("code_fix.yaml must be a mapping with `version: 1`")
    allowed, tests = _globs("allowed_paths", doc.get("allowed_paths")), _globs("test_paths", doc.get("test_paths"))
    return GateLimits(max_changed_lines=_bounded(doc, "max_changed_lines", _CEILING_LINES),
                      max_revert_lines=_bounded(doc, "max_revert_lines", _CEILING_LINES),
                      max_files=_bounded(doc, "max_files", _CEILING_FILES), allowed_paths=allowed, test_paths=tests,
                      _allowed=tuple(map(glob_regex, allowed)), _tests=tuple(map(glob_regex, tests)))


@cache
def default_limits() -> GateLimits:
    return load_limits()


# ------------------------------------------------------------------------------------------- what is never touched

# Each a regex over the whole path. Code, not data: data/code_fix.yaml can widen `allowed_paths`, never these.
_NEVER: tuple[tuple[str, str], ...] = (
    (r"(?:.*/)?CODEOWNERS", "CODEOWNERS"),
    (r"(?:.*/)?\.github/.*", "GitHub workflows and repository settings"),
    (r"(?:.*/)?(?:\.gitlab-ci\.yml|\.circleci/.*|Jenkinsfile|azure-pipelines\.yml|\.pre-commit-config\.yaml)",
     "CI configuration"),
    # Files a test run or a build executes without being asked: a planted one runs in CI with CI's rights.
    ((r"(?:.*/)?(?:conftest\.py|pytest\.ini|tox\.ini|noxfile\.py|setup\.cfg|Makefile|sitecustomize\.py|"
      r"usercustomize\.py|[^/]*\.pth|\.gitattributes|\.gitmodules|\.gitignore)"), "files a test run or build executes"),
    (r"(?:iam|terraform|k8s|helm|manifests)/.*|.*\.tf|.*\.tfvars|.*\.hcl", "IAM and infrastructure"),
    (r"(?:.*/)?[^/]*(?:polic(?:y|ies)|rbac|role|trust)[^/]*\.(?:json|ya?ml)", "IAM and access policy"),
    # Any case: `.ENV`, `Server.KEY`, `ID_RSA`, `DB_Password.txt` are the same files to a person and to most tools.
    ((r"(?i:(?:.*/)?(?:\.env(?:\.[^/]*)?|[^/]*\.(?:pem|key|p12|pfx|jks|keystore|crt|asc|gpg)|id_(?:rsa|ed25519|ecdsa)"
      r"[^/]*|[^/]*(?:secret|credential|passw)[^/]*))"), "secrets and keys"),
    # WARDEN's own code, policy data and pins: WARDEN never writes the rules it is held to (self-target, P22).
    (r"src/warden/.*|scripts/.*|evals/.*|tests/.*|docs/safety-pins\.sha256", "WARDEN's own code, tests and policy"),
)
_NEVER_RX = tuple((re.compile(rx), why) for rx, why in _NEVER)

_MANIFESTS = re.compile(
    r"(?:.*/)?(?:pyproject\.toml|setup\.py|requirements[^/]*\.(?:txt|in)|constraints[^/]*\.txt|uv\.lock|"
    r"poetry\.lock|Pipfile(?:\.lock)?|pdm\.lock|environment\.ya?ml|package(?:-lock)?\.json|yarn\.lock|"
    r"pnpm-lock\.yaml|npm-shrinkwrap\.json|go\.(?:mod|sum)|Cargo\.(?:toml|lock)|Gemfile(?:\.lock)?|"
    r"composer\.(?:json|lock)|pom\.xml|build\.gradle(?:\.kts)?|[^/]*\.csproj|Dockerfile[^/]*|[^/]*\.dockerfile|"
    r"\.?(?:python|node|tool)-versions?|\.nvmrc|renovate\.json)")

_PLAIN_PATH = re.compile(r"[A-Za-z0-9_.][A-Za-z0-9_./-]{0,254}")


def path_refusal(path: str) -> str | None:
    """Why a path's shape is refused (CG2), or None."""
    parts = path.split("/")
    if not _PLAIN_PATH.fullmatch(path) or any(p in ("", ".", "..") for p in parts):
        return f"{path!r} is not a plain relative path"
    # Any case, and with Windows' trailing dots: `.GIT` and `.git.` are the same folder on a case-insensitive disk.
    if any(p.lower().rstrip(".") == ".git" for p in parts):
        return f"{path!r} is inside a .git folder"
    return None


def never_touched(path: str) -> str | None:
    """What a path is, if a change may never touch it (CG4), or None."""
    return next((why for rx, why in _NEVER_RX if rx.fullmatch(path)), None)


def is_manifest(path: str) -> bool:
    """A dependency manifest, lock file or image definition (CG5)."""
    return bool(_MANIFESTS.fullmatch(path))


# ---------------------------------------------------------------------------------------------- what added lines say

# New suppressions and skipped tests (owner, 2026-10-17: no new suppression without a reason; here, none at all).
_SUPPRESSION = re.compile(
    r"#\s*(?:noqa|nosec|type:\s*ignore|pragma:\s*no\s*(?:cover|branch)|pylint:\s*disable|nosemgrep|ruff:\s*noqa|"
    r"pyright:\s*ignore|mypy:\s*ignore|pyre-(?:ignore|fixme))|N[O]SONAR|"
    r"pytest\.(?:mark\.)?(?:skip|skipif|xfail)|pytest\.importorskip|\bSkipTest\b|unittest\.skip|@skip|"
    r"\bpytest\.exit\b|\bos\._exit\b|\b__test__\s*=|\bpytestmark\s*=|"
    r"(?:filterwarnings|simplefilter)\s*\(\s*(?:action\s*=\s*)?[rbuf]*[\"']ignore|"
    r"eslint-disable|@ts-(?:ignore|nocheck)|"
    r"lgtm\[|codeql\[|coderabbit:\s*ignore|sonar\.issue\.ignore", re.IGNORECASE)
# In a test file only: the application may stop itself (`sys.exit(2)` on a bad configuration); a test that exits
# stops the run before its assertions.
_TEST_EXIT = re.compile(r"\bsys\.exit\b|\bSystemExit\b")
# exec, eval and compile as calls of their own (not a method such as `cursor.execute(` or `re.compile(`): code from a
# string. Any mention of the builtins module reaches them another way (`builtins.exec`, `__builtins__["eval"]`).
_DYNAMIC_IMPORT = re.compile(r"__import__\s*\(|\bimportlib\b|\bimport_module\s*\(|\brunpy\b|\bpkgutil\b|"
                             r"(?<![\w.])(?:exec|eval|compile)\s*\(|\b__builtins__\b|\bbuiltins\b")
# Options may come between the tool and its verb (`pip -q install`, `"pip", "--quiet", "install"`).
_INSTALL = re.compile(r"\b(?:pip3?|uv|poetry|pipx|npm|yarn|pnpm|gem|cargo|go)(?:[\s'\",]+-[\w=.-]*)*[\s'\",]+"
                      r"(?:install|add|get)\b|\bensurepip\b|\bsite\.addsitedir\b", re.IGNORECASE)
# PEP 263's declaration, on any added line (only the first two count, so none other may hold one).
_CODING = re.compile(r"^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)")
_UTF8 = frozenset({"utf-8", "utf8", "utf_8"})
_IMPORT = re.compile(r"\s*(?:from\s+([A-Za-z_][\w.]*)\s+import\b|import\s+([A-Za-z_][^#]*))")
# A test function, an assertion or an expected exception: what CG8 asks a fix to add, and CG9 forbids it to remove.
_TEST_DEF = re.compile(r"\s*(?:async\s+)?def\s+test_\w*\s*\(|\s*assert\b")
_TEST_RAISES = re.compile(r"\bpytest\.raises\s*\(")


def is_test_line(line: str) -> bool:
    return bool(_TEST_DEF.match(line) or _TEST_RAISES.search(line))


def code_part(line: str) -> str:
    """A line up to its comment: a `#` inside a quoted string (`x = "#"; import leftpad`) does not start one. A line
    is kept whole when it holds a triple quote (it may close a string opened lines before) or when a quote follows
    the `#` (a triple-quoted `a" #` then `; import leftpad`): keeping more of a line can only add a refusal, never hide
    an import."""
    if '"""' in line or "'''" in line:
        return line
    at = _comment_at(line)
    return line if at < 0 or any(q in line[at:] for q in "'\"") else line[:at]


def _comment_at(line: str) -> int:
    """Where a line's `#` outside a quoted string is, or -1."""
    quote = ""
    escaped = False
    for i, ch in enumerate(line):
        if escaped:
            escaped = False
        elif quote and ch == "\\":
            escaped = True
        elif quote:
            quote = "" if ch == quote else quote
        elif ch in "'\"":
            quote = ch
        elif ch == "#":
            return i
    return -1


def imported_modules(line: str) -> set[str]:
    """The top-level modules the `import` and `from ... import` statements of one line name. Each piece after a `;` or
    a `:` is read as a statement (`try: import x`); a colon inside a string can only make a piece refused, never let
    one through. A relative import names none."""
    out: set[str] = set()
    for statement in re.split(r"[;:]", code_part(line)):
        m = _IMPORT.match(statement)
        if m and m.group(1):
            out.add(m.group(1).split(".")[0])
        elif m:
            out |= {name.split()[0].split(".")[0] for name in m.group(2).split(",") if name.split()}
    return out


def imports_in(source: str) -> frozenset[str]:
    """Every top-level module a file's source imports: what the caller passes as `known_imports`."""
    return frozenset(name for line in source.splitlines() for name in imported_modules(line))


def secret_kinds(line: str) -> list[str]:
    """The secret kinds the redactor finds in one added line (CG4)."""
    from .redaction import SECRET_KINDS, redact

    found = {p.strip("<>").rsplit("_", 1)[0] for p in redact(line).mapping}
    return sorted(found & SECRET_KINDS)


# --------------------------------------------------------------------------------------------------- the rules

def _size(kind: ChangeKind, files: tuple[FileChange, ...], limits: GateLimits) -> list[Refusal]:
    if not files:
        return [Refusal("CG1", "the change is empty")]
    out: list[Refusal] = []
    lines = sum(len(f.added) + len(f.removed) for f in files)
    limit = limits.max_revert_lines if kind is ChangeKind.revert else limits.max_changed_lines
    if lines > limit:
        out.append(Refusal("CG1", f"{lines} changed lines; a {kind} may change at most {limit}"))
    if len(files) > limits.max_files:
        out.append(Refusal("CG1", f"{len(files)} files; at most {limits.max_files}"))
    if lines == 0 and not any(f.status in (_ADDED, _DELETED, _RENAMED) for f in files):
        out.append(Refusal("CG1", "the change changes no line"))
    return out


def _path(path: str, limits: GateLimits) -> list[Refusal]:
    shape = path_refusal(path)
    if shape:
        return [Refusal("CG2", shape)]
    out: list[Refusal] = []
    why = never_touched(path)
    if why:
        out.append(Refusal("CG4", f"{path}: {why} - a person changes these"))
    if is_manifest(path):
        out.append(Refusal("CG5", f"{path}: a dependency manifest or image definition"))
    if not limits.allows(path):
        out.append(Refusal("CG3", f"{path} is outside the allowed paths"))
    return out


def _kind_of_file(f: FileChange) -> list[Refusal]:
    out: list[Refusal] = []
    if f.binary:
        out.append(Refusal("CG7", f"{f.path}: a binary file"))
    modes = {f.old_mode, f.new_mode} - {""}
    if modes - {_REGULAR, _EXECUTABLE}:
        out.append(Refusal("CG7", f"{f.path}: a symbolic link or submodule"))
    elif f.status in (_MODIFIED, _RENAMED) and f.old_mode != f.new_mode:
        out.append(Refusal("CG7", f"{f.path}: its file mode changes"))
    elif f.new_mode == _EXECUTABLE and f.status == _ADDED:
        out.append(Refusal("CG7", f"{f.path}: a new executable file"))
    return out


def _line(path: str, n: int, line: str, known: frozenset[str], *, test: bool = False) -> list[Refusal]:
    """CG4 secrets, CG6 new dependencies, CG9 suppressions, in one added line (`n` counts from 1); `test`: the line
    is in a test file."""
    out: list[Refusal] = []
    kinds = secret_kinds(line)
    if kinds:
        out.append(Refusal("CG4", f"{path} added line {n}: a secret-shaped value ({', '.join(kinds)})"))
    if _SUPPRESSION.search(line) or (test and _TEST_EXIT.search(line)):
        out.append(Refusal("CG9", f"{path} added line {n}: a suppression, a skipped test or a stopped test run"))
    if _DYNAMIC_IMPORT.search(line) or _INSTALL.search(line):
        out.append(Refusal("CG6", f"{path} added line {n}: a dynamic import or an install command"))
    if path.endswith(".py"):
        out += _python_text(path, n, line)
        if _continued_import(line):
            out.append(Refusal("CG6", f"{path} added line {n}: an import continued on the next line (`\\`), which "
                                      "the gate does not read"))
        new = sorted(imported_modules(line) - known - set(sys.stdlib_module_names) - {"__future__"})
        if new:
            out.append(Refusal("CG6", f"{path} added line {n}: imports {', '.join(new)}, which the repository does "
                                      "not use yet"))
    return out


def _continued_import(line: str) -> bool:
    """`import os, \\` with the next module on the next line: the gate reads one line at a time, so it is refused."""
    code = code_part(line).rstrip()
    return code.endswith("\\") and any(re.match(r"\s*(?:from|import)\b", piece)
                                       for piece in re.split(r"[;:]", code))


def _python_text(path: str, n: int, line: str) -> list[Refusal]:
    """CG6: an added Python line is ASCII (Python folds a fullwidth `exec` to `exec`, the gate's patterns do not) and
    declares no source encoding but utf-8 (under `coding: utf-7`, `+AAo-import x` is a second line Python runs)."""
    out: list[Refusal] = []
    if not line.isascii():
        out.append(Refusal("CG6", f"{path} added line {n}: a character outside ASCII in Python source"))
    coding = _CODING.match(line)
    if coding and coding.group(1).lower() not in _UTF8:
        out.append(Refusal("CG6", f"{path} added line {n}: a source encoding other than utf-8"))
    return out


# ---------------------------------------------------------------------------------------- what a Python file does

# Modules that run code from data or reach the network: never newly imported, and never used on an added line, even
# where the file already imports them (the traffic Lambda's urllib: a person changes that code).
DENIED_MODULES = frozenset({
    "asyncio", "builtins", "code", "codeop", "ctypes", "dill", "ftplib", "http", "imaplib", "imp", "importlib",
    "marshal", "multiprocessing", "pickle", "pkgutil", "poplib", "pty", "pydoc", "runpy", "shelve", "smtplib",
    "socket", "socketserver", "subprocess", "telnetlib", "timeit", "types", "urllib", "webbrowser", "xmlrpc",
    "zipimport",
})
# What an added import may name besides what the file and its application already import: the standard library's
# plain parts, and pytest in a test file.
SAFE_IMPORTS = frozenset({
    "__future__", "abc", "base64", "bisect", "collections", "contextlib", "copy", "dataclasses", "datetime", "decimal",
    "enum", "fractions", "functools", "hashlib", "heapq", "hmac", "itertools", "json", "logging", "math", "numbers",
    "random", "re", "secrets", "statistics", "string", "textwrap", "time", "typing", "uuid", "zoneinfo",
})
_TEST_IMPORTS = frozenset({"pytest"})
# Attributes of an allowed module that run a program, end the process or reach the import machinery.
_DENIED_ATTRS: Mapping[str, frozenset[str]] = {
    "os": frozenset({"system", "popen", "_exit", "startfile", "fork", "forkpty"}),
    "sys": frozenset({"modules", "meta_path", "path", "path_hooks", "path_importer_cache", "_getframe", "settrace",
                      "setprofile", "addaudithook"}),
    "operator": frozenset({"attrgetter", "methodcaller"}),
    "pytest": frozenset({"exit"}),
}
_DENIED_PREFIXES: Mapping[str, tuple[str, ...]] = {"os": ("exec", "spawn", "posix_spawn")}
# Names that run code from a string or reach every global: refused as names, so `(exec)(s)` and `f = eval` count too.
_CODE_NAMES = frozenset({"exec", "eval", "compile", "__import__", "globals", "locals", "vars", "breakpoint"})
_BY_NAME = frozenset({"getattr", "setattr", "delattr"})
# The interpreter's internals: the way out of every list above (`().__class__.__mro__[1].__subclasses__()`).
_INTERNALS = frozenset({
    "__builtins__", "__globals__", "__code__", "__subclasses__", "__mro__", "__bases__", "__base__", "__class__",
    "__dict__", "__loader__", "__spec__", "__import__", "__getattribute__", "__reduce__", "__reduce_ex__",
    "__closure__", "__func__", "__self__",
})
_INTERNAL_TEXT = re.compile("|".join(sorted(map(re.escape, _INTERNALS))))
# What stops a test from running or failing (CG9), as calls in a test file.
_TEST_STOPS = {"sys": frozenset({"exit"}), "os": frozenset({"_exit"}), "pytest": frozenset({"exit", "skip", "xfail",
                                                                                              "importorskip"})}
_IGNORE_WARNINGS = frozenset({"filterwarnings", "simplefilter"})


def added_line_numbers(f: FileChange) -> frozenset[int] | None:
    """The new-side line numbers of a file's added lines, from its hunks; None when its hunks' starts are unknown
    (a FileChange built by hand): then every line of the file counts as added."""
    if not f.hunks or len(f.starts) != len(f.hunks):
        return None
    out: set[int] = set()
    for (_old, new), hunk in zip(f.starts, f.hunks, strict=True):
        line = new
        for text in hunk:
            if text[:1] == "+":
                out.add(line)
            if text[:1] in ("+", " "):
                line += 1
    return frozenset(out)


@dataclass(frozen=True)
class _Seen:
    """One file's scan: the aliases its imports bind (`sp` -> `subprocess`, `run` -> `subprocess.run`), the modules it
    imports on lines the change keeps, and whether it is a test file."""

    path: str
    aliases: Mapping[str, str]
    kept: frozenset[str]
    test: bool


def _bound(node: ast.Import | ast.ImportFrom) -> dict[str, str]:
    """The names one import statement binds, each with the dotted name it stands for."""
    if isinstance(node, ast.Import):
        return {a.asname or a.name.split(".")[0]: a.name if a.asname else a.name.split(".")[0] for a in node.names}
    if node.module and not node.level:
        return {a.asname or a.name: f"{node.module}.{a.name}" for a in node.names}
    return {}


def _aliases(tree: ast.AST) -> dict[str, str]:
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import | ast.ImportFrom):
            out.update(_bound(node))
    return out


def _touched(node: ast.AST, added: frozenset[int] | None) -> bool:
    if added is None:
        return True
    start = getattr(node, "lineno", None)
    if start is None:
        return False
    end = getattr(node, "end_lineno", None) or start
    return any(n in added for n in range(start, end + 1))


def _dotted(node: ast.AST, aliases: Mapping[str, str]) -> str:
    """`a.b.c` as the dotted name it reaches through the file's imports (`sp.run` -> `subprocess.run`), or ""."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return ""
    parts.append(aliases.get(node.id, node.id))
    return ".".join(reversed(parts))


def _denied_name(dotted: str) -> str | None:
    """Why a dotted name an added line reaches is refused (CG6), or None."""
    top, _, rest = dotted.partition(".")
    attr = rest.split(".")[0]
    if top in DENIED_MODULES:
        return f"uses {top}, which runs code or reaches the network"
    if attr and (attr in _DENIED_ATTRS.get(top, ()) or (top in _DENIED_PREFIXES
                                                         and attr.startswith(_DENIED_PREFIXES[top]))):
        return f"uses {top}.{attr}"
    return None


def _imported(node: ast.Import | ast.ImportFrom) -> list[str]:
    """The modules an import statement names (none for a relative one: the application's own files)."""
    if isinstance(node, ast.ImportFrom):
        return [] if node.level else [node.module or ""]
    return [a.name for a in node.names]


def _import_refusals(node: ast.Import | ast.ImportFrom, seen: _Seen, known: frozenset[str]) -> list[str]:
    out: list[str] = []
    allowed = known | seen.kept | SAFE_IMPORTS | (_TEST_IMPORTS if seen.test else frozenset())
    for top in (name.split(".")[0] for name in _imported(node)):
        if top in DENIED_MODULES:
            out.append(f"imports {top}, which runs code or reaches the network")
        elif top not in allowed:
            out.append(f"imports {top}, which the file and its application do not import yet")
    if isinstance(node, ast.ImportFrom) and not node.level and (node.module or "") not in DENIED_MODULES:
        # `from os import system`: the name it binds is the attribute.
        out += [why for a in node.names if (why := _denied_name(f"{node.module}.{a.name}"))]
    return out


def _root(node: ast.AST) -> str:
    while isinstance(node, ast.Attribute | ast.Subscript | ast.Call):
        node = node.func if isinstance(node, ast.Call) else node.value
    return node.id if isinstance(node, ast.Name) else ""


def _by_name(name: str, node: ast.Call, seen: _Seen) -> list[tuple[str, str]]:
    """`getattr(x, name)`: refused with a computed name, or on a module (`getattr(os, "system")`,
    `getattr(pytest.mark, "skip")`: CG9)."""
    out: list[tuple[str, str]] = []
    attr = node.args[1] if len(node.args) > 1 else None
    if not (isinstance(attr, ast.Constant) and isinstance(attr.value, str)):
        out.append(("CG6", f"{name} with a computed name"))
    root = _root(node.args[0]) if node.args else ""
    if root in seen.aliases:
        module = seen.aliases[root]
        out.append(("CG9" if module.split(".")[0] == "pytest" else "CG6", f"{name} on the module {module}"))
    return out


def _call_refusals(node: ast.Call, seen: _Seen) -> list[tuple[str, str]]:
    """(rule, why) for one added call: a computed attribute, a warnings filter that ignores, a test stopped."""
    out: list[tuple[str, str]] = []
    func = node.func
    name = func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""
    if name in _BY_NAME and isinstance(func, ast.Name):
        out += _by_name(name, node, seen)
    first = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg == "action"), None)
    if (name in _IGNORE_WARNINGS and isinstance(first, ast.Constant) and isinstance(first.value, str)
            and first.value.startswith("ignore")):
        out.append(("CG9", f"a warnings filter that ignores ({name})"))
    dotted = _dotted(func, seen.aliases)
    top, _, attr = dotted.partition(".")
    if seen.test and attr in _TEST_STOPS.get(top, ()):
        out.append(("CG9", f"{dotted} in a test"))
    return out


def _node_refusals(node: ast.AST, seen: _Seen, known: frozenset[str]) -> list[tuple[str, str]]:
    """(rule, why) for one node an added line holds."""
    if isinstance(node, ast.Import | ast.ImportFrom):
        return [("CG6", why) for why in _import_refusals(node, seen, known)]
    if isinstance(node, ast.Call):
        return _call_refusals(node, seen)
    return [("CG6", why) for why in [_reference(node, seen)] if why]


def _reference(node: ast.AST, seen: _Seen) -> str | None:
    """Why a name, an attribute or a string an added line holds is refused (CG6), or None."""
    if isinstance(node, ast.Name):
        if node.id in _CODE_NAMES or node.id in _INTERNALS:
            return f"names {node.id}"
        return _denied_name(seen.aliases[node.id]) if node.id in seen.aliases else None
    if isinstance(node, ast.Attribute):
        return f"reaches {node.attr}" if node.attr in _INTERNALS else _denied_name(_dotted(node, seen.aliases))
    if isinstance(node, ast.Constant) and isinstance(node.value, str) and _INTERNAL_TEXT.search(node.value):
        return "a string naming an interpreter internal"
    return None


def _test_body_refusals(tree: ast.AST, seen: _Seen, added: frozenset[int] | None) -> list[tuple[str, str]]:
    """CG9 in a test file: `__test__` or `pytestmark` set, or a `return` added inside a test function."""
    out: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign | ast.AnnAssign | ast.AugAssign) and _touched(node, added):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = {t.id for t in targets if isinstance(t, ast.Name)}
            out += [("CG9", f"sets {n}") for n in sorted(names & {"__test__", "pytestmark"})]
        elif (seen.test and isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
              and node.name.startswith("test")):
            out += [("CG9", f"a return in the test {node.name}") for inner in _own_returns(node)
                    if _touched(inner, added)]
    return out


def _own_returns(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Return]:
    """A function's own `return`s: not those of a helper defined inside it."""
    out: list[ast.Return] = []
    todo: list[ast.AST] = list(func.body)
    while todo:
        node = todo.pop()
        if isinstance(node, ast.Return):
            out.append(node)
        elif not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.Lambda | ast.ClassDef):
            todo.extend(ast.iter_child_nodes(node))
    return out


def _source_matches(f: FileChange, lines: list[str], added: frozenset[int] | None) -> bool:
    """The text given for a file holds the diff's added lines, where the diff puts them (or anywhere, without
    starts): the gate parses what is committed, not a cleaner copy."""
    if added is None:
        return set(f.added) <= set(lines)
    ordered = sorted(added)
    return len(ordered) == len(f.added) and all(
        0 < n <= len(lines) and lines[n - 1] == text for n, text in zip(ordered, f.added, strict=True))


def python_refusals(f: FileChange, source: str | None, known: frozenset[str], *, test: bool) -> list[Refusal]:
    """CG6 and CG9 over a changed Python file as Python reads it: every node an added line holds."""
    if source is None:
        return [Refusal("CG6", f"{f.path}: its new text was not given, so the gate could not parse it")]
    added = added_line_numbers(f)
    if not _source_matches(f, source.splitlines(), added):
        return [Refusal("CG6", f"{f.path}: the text given is not the text the diff makes")]
    try:
        tree = ast.parse(source, filename=f.path)
    except (SyntaxError, ValueError):
        return [Refusal("CG6", f"{f.path}: its new text is not Python the gate can parse")]
    kept = frozenset(name.split(".")[0] for n in ast.walk(tree)
                     if isinstance(n, ast.Import | ast.ImportFrom) and not _touched(n, added) for name in _imported(n))
    seen = _Seen(path=f.path, aliases=_aliases(tree), kept=kept - {""}, test=test)
    found = [r for node in ast.walk(tree) if _touched(node, added) for r in _node_refusals(node, seen, known)]
    found += _test_body_refusals(tree, seen, added)
    return [Refusal(rule, f"{f.path}: {why}") for rule, why in dict.fromkeys(found)]


def _weakening(f: FileChange, limits: GateLimits) -> list[Refusal]:
    """CG9 for a fix: no test file deleted or renamed away, no assertion or test function removed."""
    if not any(limits.is_test(p) for p in f.paths):
        return []
    if f.status in (_DELETED, _RENAMED):
        return [Refusal("CG9", f"{f.path}: a test file is {f.status}")]
    gone = sum(1 for line in f.removed if is_test_line(line))
    return [Refusal("CG9", f"{f.path}: removes {gone} assertion or test line(s)")] if gone else []


def _adds_a_test(files: tuple[FileChange, ...], limits: GateLimits) -> list[Refusal]:
    """CG8: a fix adds a test function or an assertion in a test file."""
    for f in files:
        if limits.is_test(f.path) and any(is_test_line(line) for line in f.added):
            return []
    return [Refusal("CG8", "a fix must add a test (a test function or an assertion in a test file)")]


_INVERSE_STATUS = {_ADDED: _DELETED, _DELETED: _ADDED, _MODIFIED: _MODIFIED, _RENAMED: _RENAMED}
_SHA = re.compile(r"[0-9a-f]{40}")


def _segments(hunk: tuple[str, ...], *, flip: bool = False) -> tuple[Any, ...]:
    """A hunk as context lines and change runs (removed, added): git writes a run's removals first, so the inverse of
    `-a +b` is `-b +a`, not the same lines with their signs swapped. `flip` swaps each run's sides."""
    out: list[Any] = []
    removed: list[str] = []
    added: list[str] = []
    for line in (*hunk, " "):  # a closing context line ends the last run
        sign, text = line[:1], line[1:]
        if sign and sign in "+-":
            (removed if sign == "-" else added).append(text)
            continue
        if removed or added:
            out.append(("change", tuple(added), tuple(removed)) if flip else ("change", tuple(removed), tuple(added)))
            removed, added = [], []
        out.append(("context", line))
    return tuple(out[:-1])


def _inverse(f: FileChange) -> FileChange:
    renamed = f.status == _RENAMED
    return FileChange(path=f.old_path if renamed and f.old_path else f.path, status=_INVERSE_STATUS[f.status],
                      added=f.removed, removed=f.added, old_path=f.path if renamed else None, old_mode=f.new_mode,
                      new_mode=f.old_mode, binary=f.binary, hunks=f.hunks, starts=f.starts)


def _key(f: FileChange, *, flip: bool = False) -> tuple[Any, ...]:
    """What makes two file changes the same change: its paths, status, lines, modes, each hunk's context and runs, and
    where each hunk starts (`flip`: of an inverse, whose hunks and starts are still the original's - the inverse of
    `@@ -10 +12 @@` is `@@ -12 +10 @@`). A mode on the side where the file does not exist is ignored."""
    old = "" if f.status == _ADDED else f.old_mode
    new = "" if f.status == _DELETED else f.new_mode
    hunks = tuple(_segments(h, flip=flip) for h in f.hunks)
    starts = tuple((n, o) for o, n in f.starts) if flip else f.starts
    return (f.path, f.status, f.added, f.removed, f.old_path if f.status == _RENAMED else None, old, new, f.binary,
            hunks, starts)


def _exact_revert(files: tuple[FileChange, ...], reverts: str | None,
                  original: tuple[FileChange, ...] | None) -> list[Refusal]:
    """CG10: the change is exactly the inverse of the named commit's change."""
    if not (reverts and _SHA.fullmatch(reverts)):
        return [Refusal("CG10", "a revert must name the full commit it reverts")]
    if not original:
        return [Refusal("CG10", f"the change of commit {reverts[:12]} was not read")]
    want = sorted(_key(_inverse(f), flip=True) for f in original)
    have = sorted(_key(f) for f in files)
    if want != have:
        return [Refusal("CG10", f"the change is not exactly the inverse of commit {reverts[:12]}")]
    return []


def effective_mode(mode: CodeFixMode | str, tier: str) -> CodeFixMode:
    """The environment's mode as the gate obeys it: only the nonprod tier is ever `auto`, whatever was passed - the
    prod tier, an unknown one or a misspelled one (`Prod`, `production`) gets `propose`."""
    chosen = CodeFixMode(mode)
    return CodeFixMode.propose if chosen is CodeFixMode.auto and tier not in AUTO_TIERS else chosen


def check(files: tuple[FileChange, ...] | list[FileChange], *, kind: ChangeKind | str, mode: CodeFixMode | str,
          tier: str, known_imports: frozenset[str] = frozenset(), reverts: str | None = None,
          original: tuple[FileChange, ...] | None = None, limits: GateLimits | None = None,
          sources: Mapping[str, str] | None = None) -> CodeVerdict:
    """Every rule over one change. `known_imports`: the top-level modules the file's application already imports
    (`imports_in` over its files); `reverts` and `original`: for a revert, the commit and its own change; `sources`:
    the new text of every changed Python file the change keeps, by path - one missing is refused (CG6)."""
    files, kind, limits, sources = tuple(files), ChangeKind(kind), limits or default_limits(), sources or {}
    obeyed = effective_mode(mode, tier)
    out: list[Refusal] = []
    if obeyed is CodeFixMode.off:
        out.append(Refusal("CG0", "code fixes are off in this environment"))
    out += _size(kind, files, limits)
    for f in files:
        test = limits.is_test(f.path)
        for path in f.paths:
            out += _path(path, limits)
        out += _kind_of_file(f)
        for n, line in enumerate(f.added, 1):
            out += _line(f.path, n, line, known_imports, test=test)
        if f.path.endswith(".py") and f.status != _DELETED:
            out += python_refusals(f, sources.get(f.path), known_imports, test=test)
        if kind is ChangeKind.fix:
            out += _weakening(f, limits)
    out += _adds_a_test(files, limits) if kind is ChangeKind.fix else _exact_revert(files, reverts, original)
    return CodeVerdict(mode=obeyed, refusals=tuple(dict.fromkeys(out)))


# ------------------------------------------------------------------------------------------------ parsing a diff

_DIFF = re.compile(r"diff --git a/(\S+) b/(\S+)")
_HUNK = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
_MODE = re.compile(r"(old mode|new mode|new file mode|deleted file mode) (\d{6})")
# An unchanged mode is written only here: `index 1a..2b 120000` is a symbolic link's edit (CG7 needs it).
_INDEX = re.compile(r"index [0-9a-f]+\.\.[0-9a-f]+(?: (\d{6}))?")
_NO_NEWLINE = "\\ No newline at end of file"
_DEV_NULL = "/dev/null"
# Header lines that say nothing the gate reads.
_IGNORED = ("similarity index", "dissimilarity index")


class _File:
    """One file's header and lines as they are read."""

    def __init__(self, old: str, new: str) -> None:
        self.old, self.new, self.status = old, new, _MODIFIED
        self.modes = {"old": _REGULAR, "new": _REGULAR}
        self.mode_from = ""  # "header" (mode lines) or "index" (an index line's mode): never both
        self.binary = False
        self.added: list[str] = []
        self.removed: list[str] = []
        self.bodies: list[list[str]] = []
        self.starts: list[tuple[int, int]] = []
        self.hunks = 0
        self.left = self.right = 0  # lines still owed by the open hunk

    def feed(self, line: str) -> None:
        if self.left or self.right:
            self._body(line)
        elif line.startswith("@@"):
            self._hunk(line)
        elif not self.hunks:
            self._header(line)
        elif line != _NO_NEWLINE:
            raise CodeGateError(f"a diff line outside its hunk: {line[:80]!r}")

    def _mode(self, what: str, mode: str) -> None:
        if what == "new file mode":
            self.status, self.modes = _ADDED, {"old": "", "new": mode}
        elif what == "deleted file mode":
            self.status, self.modes = _DELETED, {"old": mode, "new": ""}
        else:
            self.modes[what.split()[0]] = mode

    def _header(self, line: str) -> None:
        m, index = _MODE.fullmatch(line), _INDEX.fullmatch(line)
        if m:
            self._mode_source("header")
            self._mode(*m.groups())
        elif index:
            self._index_mode(index.group(1))
        elif line.startswith(("Binary files ", "GIT binary patch")):
            self.binary = True
        elif not (self._names(line) or line.startswith(_IGNORED)):
            # A copy, or anything else: what the gate cannot read is never passed.
            raise CodeGateError(f"a diff header line the gate does not read: {line[:80]!r}")

    def _index_mode(self, mode: str | None) -> None:
        """An `index` line without a mode leaves the mode lines (or the regular default) as they are."""
        if mode:
            self._mode_source("index")
            self.modes = {"old": mode, "new": mode}

    def _mode_source(self, source: str) -> None:
        """git writes a mode either in `old/new mode` lines or at the end of the `index` line, never both: a patch with
        both could show the gate one mode while `git apply` sets the other, so it is refused."""
        if self.mode_from and self.mode_from != source:
            raise CodeGateError("a diff gives a file's mode both in mode lines and in its index line")
        self.mode_from = source

    def _names(self, line: str) -> bool:
        """`rename from/to`, `---` and `+++`: each must name the file the `diff --git` line names (`/dev/null` only for
        the side an added or deleted file does not have) - the gate checks the paths a patch tool would use."""
        for marker, want, absent in (("rename from ", self.old, None), ("rename to ", self.new, None),
                                     ("--- ", f"a/{self.old}", _ADDED), ("+++ ", f"b/{self.new}", _DELETED)):
            if line.startswith(marker):
                seen = line.removeprefix(marker)
                if seen != want and not (seen == _DEV_NULL and self.status == absent):
                    raise CodeGateError(f"a diff header names {seen[:80]!r}, not {want[:80]!r}")
                if marker == "rename from ":
                    self.status = _RENAMED
                return True
        return False

    def _hunk(self, line: str) -> None:
        m = _HUNK.match(line)
        if not m:
            raise CodeGateError(f"an unexpected diff line: {line[:80]!r}")
        self.hunks += 1
        self.bodies.append([])
        self.starts.append((int(m.group(1)), int(m.group(3))))
        self.left = int(m.group(2) if m.group(2) is not None else 1)
        self.right = int(m.group(4) if m.group(4) is not None else 1)

    def _body(self, line: str) -> None:
        sign, text = line[:1], line[1:]
        if line != _NO_NEWLINE:  # where git writes it depends on the hunk's end, so it is not part of the body
            self.bodies[-1].append(line)
        if sign == "-" and self.left:
            self.removed.append(text)
            self.left -= 1
        elif sign == "+" and self.right:
            self.added.append(text)
            self.right -= 1
        elif sign == " " and self.left and self.right:
            self.left, self.right = self.left - 1, self.right - 1
        elif line != _NO_NEWLINE:
            raise CodeGateError(f"a diff line outside its hunk: {line[:80]!r}")

    def done(self) -> FileChange:
        if self.left or self.right:
            raise CodeGateError(f"{self.new}: a hunk ends early")
        renamed = self.status == _RENAMED or self.old != self.new
        status = _RENAMED if renamed and self.status == _MODIFIED else self.status
        return FileChange(path=self.new, status=status, added=tuple(self.added), removed=tuple(self.removed),
                          old_path=self.old if renamed else None, old_mode=self.modes["old"],
                          new_mode=self.modes["new"], binary=self.binary,
                          hunks=tuple(tuple(body) for body in self.bodies), starts=tuple(self.starts))


def _start(line: str) -> _File:
    m = _DIFF.fullmatch(line)
    if not m:
        raise CodeGateError(f"a file header the gate cannot read (a quoted or spaced path?): {line[:80]!r}")
    return _File(m.group(1), m.group(2))


def parse_diff(text: str) -> tuple[FileChange, ...]:
    """The files of a `git diff` (no colour, no `--no-prefix`). Anything it does not recognise raises CodeGateError,
    so a diff it cannot read is never passed: a quoted path, a copy, a line outside its hunk, a hunk cut short."""
    files: list[FileChange] = []
    current: _File | None = None
    for line in text.removesuffix("\n").split("\n"):
        if line.startswith("diff --git "):
            if current:
                files.append(current.done())
            current = _start(line)
        elif current is not None:
            current.feed(line)
        elif line:
            raise CodeGateError("text before the first file of the diff")
    if current:
        files.append(current.done())
    return tuple(files)
