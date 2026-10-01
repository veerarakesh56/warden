"""The full run's register guard (tests/conftest.py) - itself under test (sixth review, 2026-10-01: flipping
its directory check turned it off and no test failed)."""
from __future__ import annotations

import contextlib
import pathlib
import sys
import types

import pytest

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
    for mode in ("showfixtures", "show_fixtures_per_test", "setuponly", "setupplan"):  # eighth review
        assert not conftest._full_run(_config(["tests"], **{mode: True})), mode
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
    """The `def` a cited test's file defines: the guard watches for THIS code object starting and returning."""
    return 1


def sample_failing():
    """A cited body that fails: its failure must not become evidence because something swallowed it."""
    raise AssertionError("the body failed")


def _call_watched(monkeypatch, request, called, name="sample_evidence"):
    """Run conftest's pytest_pyfunc_call wrapper around `called()`, as pytest would, for a cited test of this file;
    return what it recorded."""
    item = types.SimpleNamespace(nodeid=f"tests/test_register_guard.py::{name}", originalname=name,
                                 path=pathlib.Path(__file__), user_properties=[], config=request.config,
                                 module=sys.modules[__name__])
    monkeypatch.setattr(conftest, "_cited", lambda: frozenset({("tests/test_register_guard.py", name)}))
    gen = conftest.pytest_pyfunc_call(item)
    next(gen)
    with contextlib.suppress(AssertionError):
        called()
    try:
        gen.send(True)
    except StopIteration:
        pass
    return dict(item.user_properties)["warden_body_ran"]


@pytest.mark.skipif(sys.version_info < (3, 12), reason="sys.monitoring is Python 3.12+; 3.11 says so at the run's end")
@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")  # the thread case, on purpose
def test_only_the_body_the_file_defines_counts(monkeypatch, request):
    """Seventh review (2026-10-01): judged at collection, five bypasses passed the full run with an `assert False`
    body; eighth review: judged by a start of code with the def's file, line and name, eight more did. Only the
    file's own code object, started, returned and never unwound, counts."""
    import functools
    import threading

    assert _call_watched(monkeypatch, request, sample_evidence) is True

    swapped = types.FunctionType((lambda: None).__code__, {}, "sample_evidence")  # a `__code__` swap
    first = sample_evidence.__code__.co_firstlineno
    same_place = types.FunctionType((lambda: None).__code__.replace(co_name="sample_evidence", co_firstlineno=first),
                                    {})  # the def's name and line, another body
    padded = compile("\n" * (first - 1) + "def sample_evidence():\n    return 1\n", __file__, "exec")
    namespace: dict = {}
    exec(padded, namespace)  # noqa: S102 - the reviewer's compile() at the def's line

    def _make():
        def sample_evidence():  # a nested def under the name
            return 1
        return sample_evidence

    def _noop():
        pass

    _noop.__name__ = _noop.__qualname__ = "sample_evidence"  # a renamed no-op bound under the name

    @functools.wraps(sample_evidence)
    def wrapper():  # a wraps-wrapper that never calls the body
        return None

    for fake in (swapped, same_place, namespace["sample_evidence"], _make(), _noop, wrapper, lambda: None):
        assert _call_watched(monkeypatch, request, fake) is False, fake

    # A body that started and failed, its failure swallowed - by a wrapper, by a hook, in a thread.
    def swallowing():
        with contextlib.suppress(AssertionError):
            sample_failing()

    def in_a_thread():
        t = threading.Thread(target=sample_failing)
        t.start()
        t.join()

    for fake in (sample_failing, swallowing, in_a_thread):
        assert _call_watched(monkeypatch, request, fake, name="sample_failing") is False, fake


@pytest.mark.skipif(sys.version_info < (3, 12), reason="sys.monitoring is Python 3.12+")
def test_deleting_sys_monitoring_does_not_turn_the_check_off(monkeypatch, request):
    """Eighth review: an autouse fixture `monkeypatch.delattr(sys, "monitoring")` made every body "unverifiable"."""
    monkeypatch.delattr(sys, "monitoring")
    assert _call_watched(monkeypatch, request, sample_evidence) is True  # the module captured it at import
    monkeypatch.setattr(conftest, "_MONITORING", None)
    assert _call_watched(monkeypatch, request, sample_evidence) is False  # gone on 3.12+: no evidence


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
