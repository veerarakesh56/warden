"""The code gate: plain rules that decide whether a change WARDEN wrote may become a pull request (register B4).

WARDEN may one day open a pull request for a code fix: first a revert of the deployed change its evidence names, then a
small fix for a code-review finding on that change. A model may draft such a change; it never decides whether the
change goes anywhere. This module does, and it is pure: a change in, a verdict out - no network, no clock, no model.

What a change is: the files of a unified diff (`git diff` output, parsed by `parse_diff`), as `FileChange`s. What the
gate needs besides: the environment's `code_fix` mode (environments.yaml) and tier, the limits in
data/code_fix.yaml, and for a new import, the top-level modules the repository already imports.

The rules, each with an id a verdict lists (every one that fires, not just the first):

- CG0 the environment's mode: `off` refuses everything; the prod tier is never `auto` (refused at load, capped here).
- CG1 size: an empty change, more lines than the limit (a revert has its own), more files than the limit.
- CG2 path shape: every path plain - no `..`, no absolute path, no quoting, no `.git` folder.
- CG3 allowed paths: every path, a renamed file's old path too, matches data/code_fix.yaml's `allowed_paths`.
- CG4 never touched, whatever that list says: CODEOWNERS, workflows and every file CI or a test run executes on its
  own (`.github/`, `conftest.py`, `Makefile` ...), IAM and infrastructure (`iam/`, `terraform/`, `k8s/`, policies),
  secrets (key files, `.env`), WARDEN's own code and policy data, and a secret-shaped value in any added line.
- CG5 dependency manifests and lock files (pyproject.toml, requirements*.txt, uv.lock, package.json, Dockerfile ...).
- CG6 no new dependency: an import the repository does not already use and the standard library does not hold, a
  dynamic import, or an install command in an added line.
- CG7 file kind: a binary file, a symbolic link, a submodule or a changed file mode.
- CG8 a fix must add a test: an added test function or assertion in a test file.
- CG9 no weakening: no new suppression (`noqa`, `nosec`, `type: ignore`, a skip or xfail, a scanner's line marker ...) anywhere; a fix
  removes no assertion, test function or test file.
- CG10 a revert is exactly the inverse of the commit it names: the same files, every added line the original's removed
  line and the other way round, in order.

A change every rule passes is `allowed`. In an environment whose mode is `propose`, a person merges it; under `auto`
(never the prod tier) it is only *eligible* to merge itself - the later checks (CI, Eldane, code review) decide that.
"""

from __future__ import annotations

import re
import sys
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
_ADDED, _MODIFIED, _DELETED, _RENAMED = "added", "modified", "deleted", "renamed"
_REGULAR = "100644"
_EXECUTABLE = "100755"


@dataclass(frozen=True)
class FileChange:
    """One file of a change. `added` and `removed` are the lines, in diff order, without their `+`/`-`; `hunks` (from
    `parse_diff`) each hunk's lines with their sign, context included, so a revert is checked where it applies too."""

    path: str
    status: str = _MODIFIED
    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    old_path: str | None = None
    old_mode: str = _REGULAR
    new_mode: str = _REGULAR
    binary: bool = False
    hunks: tuple[tuple[str, ...], ...] = ()

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
    if ".git" in parts:
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
    r"#\s*(?:noqa|nosec|type:\s*ignore|pragma:\s*no\s*cover|pylint:\s*disable|nosemgrep|ruff:\s*noqa|"
    r"pyright:\s*ignore|mypy:\s*ignore)|N[O]SONAR|"
    r"pytest\.(?:mark\.)?(?:skip|skipif|xfail)|pytest\.importorskip|\bSkipTest\b|unittest\.skip|@skip|"
    r"eslint-disable|@ts-(?:ignore|nocheck)|"
    r"lgtm\[|codeql\[|coderabbit:\s*ignore|sonar\.issue\.ignore", re.IGNORECASE)
# exec, eval and compile as calls of their own (not a method such as `cursor.execute(` or `re.compile(`): code from a
# string. Any mention of the builtins module reaches them another way (`builtins.exec`, `__builtins__["eval"]`).
_DYNAMIC_IMPORT = re.compile(r"__import__\s*\(|\bimportlib\b|\bimport_module\s*\(|\brunpy\b|\bpkgutil\b|"
                             r"(?<![\w.])(?:exec|eval|compile)\s*\(|\b__builtins__\b|\bbuiltins\b")
_INSTALL = re.compile(r"\b(?:pip3?|uv|poetry|pipx|npm|yarn|pnpm|gem|cargo|go)[\s'\",]+(?:install|add|get)\b|"
                      r"\bensurepip\b|\bsite\.addsitedir\b", re.IGNORECASE)
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


def _line(path: str, n: int, line: str, known: frozenset[str]) -> list[Refusal]:
    """CG4 secrets, CG6 new dependencies, CG9 suppressions, in one added line (`n` counts from 1)."""
    out: list[Refusal] = []
    kinds = secret_kinds(line)
    if kinds:
        out.append(Refusal("CG4", f"{path} added line {n}: a secret-shaped value ({', '.join(kinds)})"))
    if _SUPPRESSION.search(line):
        out.append(Refusal("CG9", f"{path} added line {n}: a suppression or a skipped test"))
    if _DYNAMIC_IMPORT.search(line) or _INSTALL.search(line):
        out.append(Refusal("CG6", f"{path} added line {n}: a dynamic import or an install command"))
    if path.endswith(".py"):
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
                      new_mode=f.old_mode, binary=f.binary, hunks=f.hunks)


def _key(f: FileChange, *, flip: bool = False) -> tuple[Any, ...]:
    """What makes two file changes the same change: its paths, status, lines, modes and each hunk's context and runs
    (`flip`: of an inverse, whose hunks are still the original's). A mode on the side where the file does not exist is
    ignored."""
    old = "" if f.status == _ADDED else f.old_mode
    new = "" if f.status == _DELETED else f.new_mode
    hunks = tuple(_segments(h, flip=flip) for h in f.hunks)
    return (f.path, f.status, f.added, f.removed, f.old_path if f.status == _RENAMED else None, old, new, f.binary,
            hunks)


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
    """The environment's mode as the gate obeys it: the prod tier is never `auto`, whatever was passed."""
    chosen = CodeFixMode(mode)
    return CodeFixMode.propose if chosen is CodeFixMode.auto and tier == PROD_TIER else chosen


def check(files: tuple[FileChange, ...] | list[FileChange], *, kind: ChangeKind | str, mode: CodeFixMode | str,
          tier: str, known_imports: frozenset[str] = frozenset(), reverts: str | None = None,
          original: tuple[FileChange, ...] | None = None, limits: GateLimits | None = None) -> CodeVerdict:
    """Every rule over one change. `known_imports`: the top-level modules the repository already imports
    (`imports_in` over its files); `reverts` and `original`: for a revert, the commit and its own change."""
    files, kind, limits = tuple(files), ChangeKind(kind), limits or default_limits()
    obeyed = effective_mode(mode, tier)
    out: list[Refusal] = []
    if obeyed is CodeFixMode.off:
        out.append(Refusal("CG0", "code fixes are off in this environment"))
    out += _size(kind, files, limits)
    for f in files:
        for path in f.paths:
            out += _path(path, limits)
        out += _kind_of_file(f)
        for n, line in enumerate(f.added, 1):
            out += _line(f.path, n, line, known_imports)
        if kind is ChangeKind.fix:
            out += _weakening(f, limits)
    out += _adds_a_test(files, limits) if kind is ChangeKind.fix else _exact_revert(files, reverts, original)
    return CodeVerdict(mode=obeyed, refusals=tuple(dict.fromkeys(out)))


# ------------------------------------------------------------------------------------------------ parsing a diff

_DIFF = re.compile(r"diff --git a/(\S+) b/(\S+)")
_HUNK = re.compile(r"@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@")
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
        self.left = int(m.group(1) if m.group(1) is not None else 1)
        self.right = int(m.group(2) if m.group(2) is not None else 1)

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
                          hunks=tuple(tuple(body) for body in self.bodies))


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
