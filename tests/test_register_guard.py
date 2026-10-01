"""The full run's register guard (tests/conftest.py) - itself under test (sixth review, 2026-10-01: flipping
its directory check turned it off and no test failed)."""
from __future__ import annotations

import pathlib
import types

import conftest

CITED = {("tests/test_a.py", "test_one"), ("tests/test_b.py", "test_two")}
PASSED = {"setup:passed", "call:passed", "teardown:passed", "body-ran"}


def test_evidence_that_ran_and_passed_is_accepted():
    reports = {"tests/test_a.py::test_one": set(PASSED), "tests/test_b.py::test_two[x]": set(PASSED)}
    assert conftest.missing_evidence(reports, CITED) == []


def test_skipped_failed_absent_or_rebound_evidence_is_refused():
    base = {"tests/test_a.py::test_one": set(PASSED)}
    for states in ({"skipped"}, {"setup:passed", "call:failed"}, {*PASSED, "not-genuine"}, PASSED - {"body-ran"}):
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


def sample_evidence():
    """The `def` a cited test's file defines: the guard watches for THIS code object starting."""
    return 1


def _call_watched(monkeypatch, called):
    """Run conftest's pytest_pyfunc_call wrapper around `called()`, as pytest would, for a cited test named
    sample_evidence in this file; return what it recorded."""
    item = types.SimpleNamespace(nodeid="tests/test_register_guard.py::sample_evidence", originalname="sample_evidence",
                                 path=pathlib.Path(__file__), user_properties=[])
    monkeypatch.setattr(conftest, "_cited", lambda: frozenset({("tests/test_register_guard.py", "sample_evidence")}))
    gen = conftest.pytest_pyfunc_call(item)
    next(gen)
    called()
    try:
        gen.send(True)
    except StopIteration:
        pass
    return dict(item.user_properties)["warden_body_ran"]


def test_only_the_body_the_file_defines_counts(monkeypatch):
    """Seventh review (2026-10-01): judged at collection, five bypasses passed the full run with an `assert False`
    body. At call time only the start of the file's own `def` counts."""
    import functools

    assert _call_watched(monkeypatch, sample_evidence) is True

    swapped = types.FunctionType((lambda: None).__code__, {}, "sample_evidence")  # a `__code__` swap

    def _noop():
        pass

    _noop.__name__ = _noop.__qualname__ = "sample_evidence"  # a renamed no-op bound under the name

    @functools.wraps(sample_evidence)
    def wrapper():  # a wraps-wrapper that never calls the body
        return None

    for fake in (swapped, _noop, wrapper, lambda: None):  # the last: a hook or fixture that answers for the call
        assert _call_watched(monkeypatch, fake) is False, fake


def test_the_guard_judges_the_controllers_whole_run(monkeypatch):
    """Seventh review: its wiring could be cut with its own tests green - exitstatus never set, the not-genuine
    state never recorded, the worker check inverted."""
    tests = pathlib.Path(conftest.__file__).resolve().parent
    monkeypatch.setattr(conftest, "_REPORTS", {})
    monkeypatch.setattr(conftest, "_cited", lambda: frozenset({("tests/test_a.py", "test_one")}))

    report = types.SimpleNamespace(nodeid="tests/test_a.py::test_one", skipped=False, when="call", outcome="passed",
                                   user_properties=[("warden_genuine", False), ("warden_body_ran", True)])
    conftest.pytest_runtest_logreport(report)
    assert {"call:passed", "not-genuine", "body-ran"} <= conftest._REPORTS["tests/test_a.py::test_one"]

    plugins = types.SimpleNamespace(get_plugin=lambda name: None)
    controller = _config(["tests"], base=tests.parent)
    controller.pluginmanager = plugins
    session = types.SimpleNamespace(config=controller, exitstatus=0)
    conftest.pytest_sessionfinish(session, 0)
    assert session.exitstatus == 1  # the not-genuine evidence fails the run

    worker = _config(["tests"], base=tests.parent)
    worker.pluginmanager, worker.workerinput = plugins, {}
    session = types.SimpleNamespace(config=worker, exitstatus=0)
    conftest.pytest_sessionfinish(session, 0)
    assert session.exitstatus == 0  # a worker sees only its share: the controller judges
