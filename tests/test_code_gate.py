"""The code gate (register B4): every rule fires on the change it exists for, and a small, tested change passes."""

from __future__ import annotations

import pytest
from tests.fakes import AWS_ACCESS_KEY_ID

from warden.code_gate import (
    ChangeKind,
    CodeFixMode,
    CodeGateError,
    FileChange,
    check,
    default_limits,
    effective_mode,
    glob_regex,
    imported_modules,
    imports_in,
    is_manifest,
    load_limits,
    never_touched,
    parse_diff,
    path_refusal,
)
from warden.environments import (
    EnvironmentPolicies,
    EnvironmentPolicyError,
    default_environment_policies,
)

APP = "scenarios/fullstack/app/app.py"
TEST = "tests/test_orders_fix.py"
SHA = "0123456789abcdef0123456789abcdef01234567"
KNOWN = frozenset({"warden", "pytest", "boto3", "redis"})


def app_change(added=("    return total or 0",), removed=("    return total",), path=APP, **kw) -> FileChange:
    return FileChange(path=path, added=tuple(added), removed=tuple(removed), **kw)


def added_test(added=("def test_empty_order_totals_zero():", "    assert total([]) == 0"), path=TEST,
                **kw) -> FileChange:
    return FileChange(path=path, status=kw.pop("status", "added"), added=tuple(added), old_mode="", **kw)


def gate(files, *, kind="fix", mode="propose", tier="nonprod", **kw):
    return check(files, kind=kind, mode=mode, tier=tier, known_imports=kw.pop("known_imports", KNOWN), **kw)


def rules(files, **kw) -> tuple[str, ...]:
    return gate(files, **kw).rules


# ------------------------------------------------------------------------------------------------ the good change

def test_a_small_fix_with_its_test_passes():
    verdict = gate([app_change(), added_test()])
    assert verdict.allowed, verdict.refusals
    assert verdict.mode is CodeFixMode.propose
    assert not verdict.auto_merge_eligible


def test_under_auto_a_passing_change_is_only_eligible_to_merge():
    assert gate([app_change(), added_test()], mode="auto").auto_merge_eligible


# ------------------------------------------------------------------------------------------------------- CG0 mode

def test_cg0_off_refuses_even_a_good_change():
    verdict = gate([app_change(), added_test()], mode="off")
    assert verdict.rules == ("CG0",)
    assert not verdict.allowed


@pytest.mark.parametrize("tier", ["prod"])
def test_cg0_the_prod_tier_is_never_auto_even_if_asked(tier):
    verdict = gate([app_change(), added_test()], mode="auto", tier=tier)
    assert verdict.mode is CodeFixMode.propose
    assert not verdict.auto_merge_eligible


def test_effective_mode_caps_only_auto_in_prod():
    assert effective_mode("auto", "nonprod") is CodeFixMode.auto
    assert effective_mode("propose", "prod") is CodeFixMode.propose
    assert effective_mode("off", "prod") is CodeFixMode.off


def test_an_unknown_mode_is_an_error():
    with pytest.raises(ValueError, match="sometimes"):
        gate([app_change(), added_test()], mode="sometimes")


# ------------------------------------------------------------------------------------------------------- CG1 size

def test_cg1_an_empty_change_is_refused():
    assert "CG1" in rules([])


def test_cg1_too_many_lines():
    limit = default_limits().max_changed_lines
    big = app_change(added=[f"x{i} = {i}" for i in range(limit)], removed=["x = 0"])
    assert "CG1" in rules([big, added_test()])


def test_cg1_exactly_at_the_limit_passes():
    limit = default_limits().max_changed_lines
    fits = app_change(added=[f"x{i} = {i}" for i in range(limit - 2)], removed=[])
    assert "CG1" not in rules([fits, added_test()])


def test_cg1_too_many_files():
    files = [app_change(path=f"scenarios/fullstack/app/m{i}.py") for i in range(default_limits().max_files)]
    assert "CG1" in rules([*files, added_test()])


def test_cg1_a_change_that_changes_no_line():
    assert "CG1" in rules([app_change(added=(), removed=())], kind="revert", reverts=SHA,
                          original=(app_change(added=(), removed=()),))


def test_cg1_a_revert_has_its_own_larger_limit():
    limits = default_limits()
    assert limits.max_revert_lines > limits.max_changed_lines
    original = app_change(added=[f"y{i} = {i}" for i in range(limits.max_changed_lines + 5)], removed=[])
    revert = app_change(added=[], removed=original.added)
    assert gate([revert], kind="revert", reverts=SHA, original=(original,)).allowed


# ------------------------------------------------------------------------------------------------- CG2 path shape

@pytest.mark.parametrize("path", ["../etc/passwd", "/etc/passwd", "scenarios//app.py", "scenarios/./app.py",
                                  "scenarios/fullstack/app/.git/config", '"quoted.py"', "space d.py", "",
                                  "-flag.py", "scenarios/fullstack/app/naïve.py"])
def test_cg2_a_path_that_is_not_plain_is_refused(path):
    assert path_refusal(path)
    assert "CG2" in rules([app_change(path=path), added_test()])


def test_cg2_a_plain_path_is_fine():
    assert path_refusal(APP) is None


# ---------------------------------------------------------------------------------------------- CG3 allowed paths

@pytest.mark.parametrize("path", ["README.md", "scenarios/runner.py", "scenarios/fullstack/sql/bootstrap.sql",
                                  "scenarios/fullstack/app/sub/app.py", "tests/integration/test_x.py",
                                  "scenarios/fullstack/app/app.js"])
def test_cg3_a_path_outside_the_list_is_refused(path):
    assert "CG3" in rules([app_change(path=path), added_test()])


def test_cg3_a_renamed_files_old_path_must_be_allowed_too():
    moved = app_change(path=APP, status="renamed", old_path="scenarios/runner.py")
    assert "CG3" in rules([moved, added_test()])


def test_cg3_lambdas_in_any_folder_are_allowed():
    assert "CG3" not in rules([app_change(path="scenarios/fullstack/lambdas/checkout/app.py"), added_test()])


# ---------------------------------------------------------------------------------------------- CG4 never touched

@pytest.mark.parametrize("path", [
    ".github/workflows/ci-tool.yml", ".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS", ".github/dependabot.yml",
    ".gitlab-ci.yml", ".pre-commit-config.yaml", "conftest.py", "tests/conftest.py", "scenarios/fullstack/app/conftest.py",
    "Makefile", "setup.cfg", "tox.ini", "pytest.ini", "sitecustomize.py", "scenarios/fullstack/app/evil.pth",
    ".gitattributes", "iam/dev/deploy.json", "terraform/modules/warden-runtime/iam.tf", "k8s/rbac.yaml",
    "scenarios/fullstack/app/main.tf", "scenarios/fullstack/app/bucket-policy.json", "scenarios/fullstack/app/trust.yaml",
    ".env", "scenarios/fullstack/app/.env.local", "scenarios/fullstack/app/server.pem", "deploy.key", "id_rsa",
    "scenarios/fullstack/app/secrets.py", "scenarios/fullstack/app/credentials.py",
    "src/warden/code_gate.py", "src/warden/data/code_fix.yaml", "src/warden/data/environments.yaml",
    "scripts/safety_pins.py", "docs/safety-pins.sha256", "evals/test_safety.py"])
def test_cg4_what_is_never_touched(path):
    assert never_touched(path)
    assert "CG4" in rules([app_change(path=path), added_test()])


def test_cg4_widening_the_allowed_paths_cannot_let_one_in():
    wide = load_limits("version: 1\nmax_changed_lines: 60\nmax_revert_lines: 200\nmax_files: 6\n"
                       "allowed_paths: ['.github/**/*', 'src/**/*', 'iam/**/*', 'tests/test_*.py']\ntest_paths: ['tests/test_*.py']\n")
    for path in (".github/workflows/x.yml", "src/warden/approvals.py", "iam/dev/deploy.json"):
        verdict = gate([app_change(path=path), added_test()], limits=wide)
        assert verdict.rules == ("CG4",), path


def test_cg4_a_secret_in_an_added_line():
    leaky = app_change(added=(f'KEY = "{AWS_ACCESS_KEY_ID}"',))
    verdict = gate([leaky, added_test()])
    assert "CG4" in verdict.rules
    assert AWS_ACCESS_KEY_ID not in " ".join(map(str, verdict.refusals))  # the verdict never repeats the secret


def test_cg4_an_ordinary_line_is_not_a_secret():
    assert "CG4" not in rules([app_change(added=("    return sum(o.amount for o in orders)",)), added_test()])


# -------------------------------------------------------------------------------------------- CG5 manifests

@pytest.mark.parametrize("path", ["pyproject.toml", "uv.lock", "requirements.txt", "requirements-dev.txt",
                                  "scenarios/fullstack/app/requirements.in", "scenarios/fullstack/app/requirements.txt",
                                  "scenarios/fullstack/app/Dockerfile", "Dockerfile.runtime", "package.json",
                                  "package-lock.json", "yarn.lock", "go.mod", "go.sum", "Cargo.toml", "Gemfile.lock",
                                  "setup.py", "poetry.lock", "Pipfile", "constraints.txt", ".python-version",
                                  "scenarios/fullstack/app/pyproject.toml"])
def test_cg5_dependency_manifests(path):
    assert is_manifest(path)
    assert "CG5" in rules([app_change(path=path), added_test()])


def test_cg5_ordinary_code_is_not_a_manifest():
    assert not is_manifest(APP)


# ------------------------------------------------------------------------------------------- CG6 new dependencies

@pytest.mark.parametrize("line", ["import requests", "from requests import get", "import os, requests",
                                  "    import numpy as np", "from leftpad.core import pad", "import json, yaml as y"])
def test_cg6_an_import_the_repository_does_not_use(line):
    assert "CG6" in rules([app_change(added=(line,)), added_test()])


@pytest.mark.parametrize("line", ["import os", "from collections import Counter", "import boto3",
                                  "from warden.models import ActionKind", "from . import handler",
                                  "from .handler import run", "from __future__ import annotations",
                                  "import json, logging"])
def test_cg6_the_standard_library_known_and_relative_imports_pass(line):
    assert "CG6" not in rules([app_change(added=(line,)), added_test()])


@pytest.mark.parametrize("line", ["mod = __import__('requests')", "import importlib", "x = import_module(name)",
                                  "import runpy", "os.system('pip install requests')", "# run: uv add httpx",
                                  "subprocess.run(['npm', 'install', 'x'])", "import ensurepip"])
def test_cg6_dynamic_imports_and_install_commands(line):
    assert "CG6" in rules([app_change(added=(line,)), added_test()])


def test_cg6_an_import_in_a_test_file_counts_too():
    assert "CG6" in rules([app_change(), added_test(added=("import hypothesis2", "def test_x():", "    assert 1"))])


def test_imported_modules_reads_each_shape():
    assert imported_modules("import a.b, c as d") == {"a", "c"}
    assert imported_modules("from x.y import z") == {"x"}
    assert imported_modules("from . import z") == set()
    assert imported_modules("x = 1  # import nothing") == set()


def test_imports_in_collects_a_files_top_level_modules():
    assert imports_in("import os\nfrom redis import Redis\n\nx = 1\n") == {"os", "redis"}


# ------------------------------------------------------------------------------------------------- CG7 file kind

def test_cg7_a_binary_file():
    assert "CG7" in rules([app_change(binary=True, added=(), removed=()), added_test()])


@pytest.mark.parametrize("mode", ["120000", "160000"])
def test_cg7_a_symlink_or_submodule(mode):
    refusals = gate([app_change(old_mode=mode, new_mode=mode), added_test()]).refusals
    assert [r.detail for r in refusals if r.rule == "CG7"] == [f"{APP}: a symbolic link or submodule"]


def test_cg7_a_mode_change():
    assert "CG7" in rules([app_change(old_mode="100644", new_mode="100755"), added_test()])


def test_cg7_a_new_executable_file():
    added = FileChange(path="scenarios/fullstack/app/tool.py", status="added", added=("x = 1",), old_mode="",
                       new_mode="100755")
    assert "CG7" in rules([added, added_test()])


# ------------------------------------------------------------------------------------------------- CG8 tests

def test_cg8_a_fix_without_a_test_is_refused():
    assert rules([app_change()]) == ("CG8",)


def test_cg8_a_test_file_with_no_test_in_it_is_not_a_test():
    assert "CG8" in rules([app_change(), added_test(added=("import os", "x = 1"))])


def test_cg8_a_test_line_outside_a_test_file_does_not_count():
    assert "CG8" in rules([app_change(added=("def test_inline():", "    assert True"))])


@pytest.mark.parametrize("line", ["def test_zero():", "async def test_zero():", "    assert x == 0",
                                  "    with pytest.raises(ValueError):"])
def test_cg8_each_shape_of_test_counts(line):
    assert "CG8" not in rules([app_change(), added_test(added=(line,))])


def test_cg8_a_revert_needs_no_new_test():
    original = app_change(added=("    return total",), removed=("    return total or 0",))
    revert = app_change()
    assert gate([revert], kind="revert", reverts=SHA, original=(original,)).allowed


# --------------------------------------------------------------------------------------------- CG9 weakening

@pytest.mark.parametrize("line", ["x = 1  # noqa: E501", "y = 2  # nosec B101", "z = f()  # type: ignore",
                                  "if x:  # pragma: no cover", "@pytest.mark.skip(reason='flaky')",
                                  "@pytest.mark.xfail", "pytest.skip('later')", "a = 1  # NO" + "SONAR",
                                  "# pylint: disable=all", "@unittest.skip('x')", "// eslint-disable-next-line"])
def test_cg9_a_new_suppression_anywhere(line):
    assert "CG9" in rules([app_change(added=(line,)), added_test()])


@pytest.mark.parametrize("line", ["    assert total([]) == 0", "def test_empty():", "    with pytest.raises(KeyError):"])
def test_cg9_a_fix_may_not_remove_a_test_or_an_assertion(line):
    weaker = FileChange(path="tests/test_orders.py", added=("    pass",), removed=(line,))
    assert "CG9" in rules([app_change(), weaker, added_test()])


@pytest.mark.parametrize("status", ["deleted", "renamed"])
def test_cg9_a_fix_may_not_delete_or_move_a_test_file(status):
    gone = FileChange(path="tests/test_orders.py", status=status, removed=("x = 1",),
                      old_path="tests/test_old_orders.py" if status == "renamed" else None)
    assert "CG9" in rules([app_change(), gone, added_test()])


def test_cg9_removing_ordinary_lines_from_a_test_is_fine():
    tidy = FileChange(path="tests/test_orders.py", added=("x = 2",), removed=("x = 1",))
    assert "CG9" not in rules([app_change(), tidy, added_test()])


# ------------------------------------------------------------------------------------------------- CG10 revert

def test_cg10_an_exact_inverse_passes():
    original = (FileChange(path=APP, added=("a = 2",), removed=("a = 1",)),
                FileChange(path="scenarios/fullstack/app/new.py", status="added", added=("b = 1",), old_mode=""))
    revert = (FileChange(path=APP, added=("a = 1",), removed=("a = 2",)),
              FileChange(path="scenarios/fullstack/app/new.py", status="deleted", removed=("b = 1",), new_mode=""))
    assert gate(revert, kind="revert", reverts=SHA, original=original).allowed


def test_cg10_a_revert_with_one_extra_line_is_refused():
    original = (app_change(added=("a = 2",), removed=("a = 1",)),)
    sneaky = (app_change(added=("a = 1", "b = 3"), removed=("a = 2",)),)
    assert gate(sneaky, kind="revert", reverts=SHA, original=original).rules == ("CG10",)


def test_cg10_a_revert_with_lines_in_another_order_is_refused():
    original = (app_change(added=("a = 2", "b = 2"), removed=()),)
    shuffled = (app_change(added=(), removed=("b = 2", "a = 2")),)
    assert "CG10" in rules(shuffled, kind="revert", reverts=SHA, original=original)


def test_cg10_a_revert_of_another_file_is_refused():
    original = (app_change(path="scenarios/fullstack/app/other.py"),)
    assert "CG10" in rules((app_change(added=original[0].removed, removed=original[0].added),), kind="revert",
                           reverts=SHA, original=original)


def test_cg10_a_renamed_file_reverts_back():
    original = (FileChange(path="scenarios/fullstack/app/b.py", status="renamed", old_path=APP),)
    revert = (FileChange(path=APP, status="renamed", old_path="scenarios/fullstack/app/b.py"),)
    assert gate(revert, kind="revert", reverts=SHA, original=original).allowed


@pytest.mark.parametrize("sha", [None, "", "abc123", SHA.upper(), SHA + "0"])
def test_cg10_a_revert_must_name_its_full_commit(sha):
    original = (app_change(),)
    assert "CG10" in rules((app_change(added=original[0].removed, removed=original[0].added),), kind="revert",
                           reverts=sha, original=original)


def test_cg10_a_revert_without_the_original_change_is_refused():
    assert "CG10" in rules((app_change(),), kind="revert", reverts=SHA, original=None)


def test_a_revert_still_obeys_the_path_rules():
    original = (FileChange(path=".github/workflows/ci.yml", added=("on: push",), removed=("on: pull_request",)),)
    revert = (FileChange(path=".github/workflows/ci.yml", added=("on: pull_request",), removed=("on: push",)),)
    verdict = gate(revert, kind="revert", reverts=SHA, original=original)
    assert {"CG3", "CG4"} <= set(verdict.rules)


def test_every_rule_that_fires_is_listed_not_just_the_first():
    manifest = app_change(path="pyproject.toml", added=("x = 1  # noqa",))
    code = app_change(path="scenarios/other.py", added=("import requests",))
    assert {"CG0", "CG3", "CG5", "CG6", "CG8", "CG9"} <= set(rules([manifest, code], mode="off"))


# --------------------------------------------------------------------------------------------------- the limits

def test_the_shipped_limits_load():
    limits = default_limits()
    assert limits.allows(APP)
    assert limits.is_test(TEST)
    assert not limits.allows("src/warden/verifier.py")


@pytest.mark.parametrize("text, match", [
    ("[]", "mapping"),
    ("version: 2", "version"),
    (": :", "YAML"),
    ("version: 1\nmax_changed_lines: 0", "max_changed_lines"),
    ("version: 1\nmax_changed_lines: true", "max_changed_lines"),
    ("version: 1\nmax_changed_lines: 401", "max_changed_lines"),
])
def test_malformed_limits_are_refused(text, match):
    body = text
    if "allowed_paths" not in text and text.startswith("version: 1"):
        body = text + "\nallowed_paths: [a/*.py]\ntest_paths: [tests/test_*.py]\nmax_revert_lines: 1\nmax_files: 1"
        if "max_changed_lines" not in text:
            body += "\nmax_changed_lines: 1"
    with pytest.raises(CodeGateError, match=match):
        load_limits(body)


@pytest.mark.parametrize("glob", ["**/*.py", "*", "/abs/*.py", "../up/*.py", "a b/*.py", "", 3])
def test_a_glob_that_names_everything_or_escapes_is_refused(glob):
    text = (f"version: 1\nmax_changed_lines: 1\nmax_revert_lines: 1\nmax_files: 1\nallowed_paths: [{glob!r}]\n"
            "test_paths: [tests/test_*.py]\n")
    with pytest.raises(CodeGateError, match="allowed_paths"):
        load_limits(text)


def test_an_empty_allowed_list_is_refused():
    with pytest.raises(CodeGateError, match="allowed_paths"):
        load_limits("version: 1\nmax_changed_lines: 1\nmax_revert_lines: 1\nmax_files: 1\nallowed_paths: []\n"
                    "test_paths: [tests/test_*.py]\n")


@pytest.mark.parametrize("glob, path, matches", [
    ("a/*.py", "a/x.py", True), ("a/*.py", "a/b/x.py", False), ("a/**/*.py", "a/x.py", True),
    ("a/**/*.py", "a/b/c/x.py", True), ("a/?.py", "a/x.py", False), ("a/[x].py", "a/x.py", False),
    ("a/x.py", "a/x_py", False), ("a/*.py", "a/x.pyc", False)])
def test_glob_semantics(glob, path, matches):
    assert bool(glob_regex(glob).fullmatch(path)) is matches


# --------------------------------------------------------------------------------------------------- parse_diff

DIFF = """diff --git a/scenarios/fullstack/app/app.py b/scenarios/fullstack/app/app.py
index 1111111..2222222 100644
--- a/scenarios/fullstack/app/app.py
+++ b/scenarios/fullstack/app/app.py
@@ -10,3 +10,3 @@ def total(orders):
     x = 1
-    return total
+    return total or 0
     # end
diff --git a/tests/test_orders_fix.py b/tests/test_orders_fix.py
new file mode 100644
index 0000000..3333333
--- /dev/null
+++ b/tests/test_orders_fix.py
@@ -0,0 +1,2 @@
+def test_empty_order_totals_zero():
+    assert total([]) == 0
\\ No newline at end of file
"""


def test_parse_diff_reads_a_git_diff():
    files = parse_diff(DIFF)
    assert files == (app_change(), added_test(new_mode="100644"))
    assert gate(files).allowed


def test_parse_diff_reads_deletes_renames_modes_and_binaries():
    text = ("diff --git a/x.py b/x.py\ndeleted file mode 100644\nindex 1..0\n--- a/x.py\n+++ /dev/null\n"
            "@@ -1 +0,0 @@\n-a = 1\n"
            "diff --git a/old.py b/new.py\nsimilarity index 100%\nrename from old.py\nrename to new.py\n"
            "diff --git a/run.py b/run.py\nold mode 100644\nnew mode 100755\n"
            "diff --git a/logo.png b/logo.png\nindex 1..2 100644\nBinary files a/logo.png and b/logo.png differ\n")
    deleted, renamed, moded, binary = parse_diff(text)
    assert (deleted.status, deleted.removed, deleted.new_mode) == ("deleted", ("a = 1",), "")
    assert (renamed.status, renamed.old_path, renamed.path) == ("renamed", "old.py", "new.py")
    assert (moded.old_mode, moded.new_mode) == ("100644", "100755")
    assert binary.binary


@pytest.mark.parametrize("text", [
    'diff --git "a/sp ace.py" "b/sp ace.py"\n',                                     # quoted path
    "junk\ndiff --git a/x.py b/x.py\n",                                            # text before the first file
    "diff --git a/x.py b/y.py\ncopy from x.py\ncopy to y.py\n",                     # a copy
    "diff --git a/x.py b/x.py\n@@ -1,2 +1,2 @@\n-a\n+b\n",                           # a hunk cut short
    "diff --git a/x.py b/x.py\n@@ -1 +1 @@\n-a\n+b\n+c\n",                          # a line past its hunk
    "diff --git a/x.py b/x.py\n@@ -1 +1 @@\n-a\n+b\nnew mode 100755\n",             # a header after a hunk
    "diff --git a/x.py b/x.py\n@@ nonsense @@\n",                                    # a broken hunk header
    "diff --git a/x.py b/x.py\nsomething else\n",                                     # an unknown header line
    "diff --git a/x.py b/x.py\n@@ -1,2 +1,2 @@\n a\n\n",                              # a stripped blank line
])
def test_parse_diff_refuses_what_it_cannot_read(text):
    with pytest.raises(CodeGateError):
        parse_diff(text)


def test_an_empty_diff_is_an_empty_change_and_refused():
    assert parse_diff("") == ()
    assert "CG1" in rules(parse_diff(""))


# -------------------------------------------------------------------------------- code_fix in environments.yaml

def test_shipped_environments_code_fix_modes():
    pol = default_environment_policies()
    assert pol.for_env("dev").code_fix == "propose"
    assert pol.for_env("prod").code_fix == "propose"
    assert pol.for_env("nowhere").code_fix == "off"


def test_no_prod_tier_environment_is_ever_auto():
    """The invariant: whatever environments.yaml ships, a prod-tier environment's code fixes are merged by a person."""
    pol = default_environment_policies()
    for env in pol.known_environments:
        p = pol.for_env(env)
        if p.tier == "prod":
            assert p.code_fix != "auto", env


def _policy(env_block: str, default_block: str = "") -> str:
    return f"version: 1\ndefault:\n  tier: unknown\n{default_block}environments:\n  x:\n{env_block}"


def test_auto_in_a_prod_tier_environment_is_refused_at_load(tmp_path):
    path = tmp_path / "env.yaml"
    path.write_text(_policy("    tier: prod\n    code_fix: auto\n"), encoding="utf-8")
    with pytest.raises(EnvironmentPolicyError, match="never merges code on its own"):
        EnvironmentPolicies.load(path)


def test_auto_in_a_nonprod_environment_loads(tmp_path):
    path = tmp_path / "env.yaml"
    path.write_text(_policy("    tier: nonprod\n    code_fix: auto\n"), encoding="utf-8")
    assert EnvironmentPolicies.load(path).for_env("x").code_fix == "auto"


@pytest.mark.parametrize("value, match", [("off", "quote it"), ("yes", "quote it"), ("'sometimes'", "sometimes")])
def test_a_code_fix_value_that_is_not_a_mode_is_refused(tmp_path, value, match):
    path = tmp_path / "env.yaml"
    path.write_text(_policy(f"    tier: nonprod\n    code_fix: {value}\n"), encoding="utf-8")
    with pytest.raises(EnvironmentPolicyError, match=match):
        EnvironmentPolicies.load(path)


def test_the_default_never_gets_code_fixes(tmp_path):
    path = tmp_path / "env.yaml"
    path.write_text(_policy("    tier: nonprod\n", "  code_fix: propose\n"), encoding="utf-8")
    with pytest.raises(EnvironmentPolicyError, match="never gets code fixes"):
        EnvironmentPolicies.load(path)


def test_an_unlisted_environment_inherits_off(tmp_path):
    path = tmp_path / "env.yaml"
    path.write_text(_policy("    tier: nonprod\n    code_fix: propose\n"), encoding="utf-8")
    assert EnvironmentPolicies.load(path).for_env("elsewhere").code_fix == "off"


def test_the_kind_must_be_known():
    with pytest.raises(ValueError, match="rewrite"):
        check([app_change()], kind="rewrite", mode="propose", tier="nonprod")


def test_change_kinds():
    assert {k.value for k in ChangeKind} == {"revert", "fix"}
