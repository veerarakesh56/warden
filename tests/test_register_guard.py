"""The full run's register guard (tests/conftest.py) - itself under test (sixth review, 2026-10-01: flipping
its directory check turned it off and no test failed)."""
from __future__ import annotations

import pathlib
import types

import conftest

CITED = {("tests/test_a.py", "test_one"), ("tests/test_b.py", "test_two")}
PASSED = {"setup:passed", "call:passed", "teardown:passed"}


def test_evidence_that_ran_and_passed_is_accepted():
    reports = {"tests/test_a.py::test_one": set(PASSED), "tests/test_b.py::test_two[x]": set(PASSED)}
    assert conftest.missing_evidence(reports, CITED) == []


def test_skipped_failed_absent_or_rebound_evidence_is_refused():
    base = {"tests/test_a.py::test_one": set(PASSED)}
    for states in ({"skipped"}, {"setup:passed", "call:failed"}, {*PASSED, "not-genuine"}):
        reports = {**base, "tests/test_b.py::test_two": states}
        assert conftest.missing_evidence(reports, CITED) == ["tests/test_b.py::test_two"], states
    assert conftest.missing_evidence(base, CITED) == ["tests/test_b.py::test_two"]  # never ran


def _config(args, base=None, **options):
    defaults = {"collectonly": False, "keyword": "", "markexpr": "", "lf": False, "deselect": None}
    values = {**defaults, **options}
    return types.SimpleNamespace(args=args, getoption=lambda name, default=None: values.get(name, default),
                                 invocation_params=types.SimpleNamespace(dir=base or pathlib.Path.cwd()))


def test_only_a_whole_run_of_the_suite_is_judged():
    tests = pathlib.Path(conftest.__file__).resolve().parent
    assert conftest._full_run(_config(["tests"], base=tests.parent))
    assert conftest._full_run(_config([str(tests)]))
    assert conftest._full_run(_config(["tests/."], base=tests.parent))  # sixth review: these ran unjudged
    assert conftest._full_run(_config(["."], base=tests.parent))
    assert conftest._full_run(_config(["evals", "tests"]))
    assert not conftest._full_run(_config(["tests"], collectonly=True))  # nothing runs: nothing to judge
    assert not conftest._full_run(_config(["tests"], keyword="redaction"))
    assert not conftest._full_run(_config(["tests"], deselect=["tests/test_a.py::test_one"]))
    assert not conftest._full_run(_config(["tests/test_a.py"], base=tests.parent))


def test_a_rebound_test_is_not_genuine(pytester=None):
    """`globals()["test_x"] = lambda: None` is collected under the name, but it is not the function the file
    defines - and the guard must see that."""
    import inspect
    import pathlib

    item = types.SimpleNamespace(originalname="test_x", module=types.SimpleNamespace(__name__=__name__),
                                 path=pathlib.Path(__file__), user_properties=[], function=lambda: None)
    conftest.pytest_collection_modifyitems(None, None, [item])
    assert item.user_properties == [("warden_genuine", False)]

    def test_x():
        pass

    item2 = types.SimpleNamespace(originalname="test_x", module=types.SimpleNamespace(__name__=__name__),
                                  path=pathlib.Path(inspect.getsourcefile(test_x)), user_properties=[], function=test_x)
    conftest.pytest_collection_modifyitems(None, None, [item2])
    assert item2.user_properties == [("warden_genuine", True)]
