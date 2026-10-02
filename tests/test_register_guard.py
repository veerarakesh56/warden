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
                                 path=pathlib.Path(__file__), user_properties=[], function=lambda: None,
                                 nodeid="tests/test_register_guard.py::test_x")
    conftest.pytest_collection_modifyitems(None, None, [item])
    assert conftest._GENUINE[item.nodeid] is False

    def test_x():
        pass

    item2 = types.SimpleNamespace(originalname="test_x", module=types.SimpleNamespace(__name__=__name__),
                                  path=pathlib.Path(inspect.getsourcefile(test_x)), user_properties=[], function=test_x,
                                  nodeid="tests/test_register_guard.py::test_x2")
    conftest.pytest_collection_modifyitems(None, None, [item2])
    assert conftest._GENUINE[item2.nodeid] is True


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
    return conftest._RAN.pop(item.nodeid)


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
                                   user_properties=[], warden_genuine=False, warden_body_ran=True)
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


def sample_twice():
    return 1


def sample_twice():  # noqa: F811 - the reviewer's `def`, `del`, `def` under one name
    return 1


class _Shadow:
    @staticmethod
    def sample_evidence():
        return 1


def sample_slow():
    """Still running when the call ends: it started, and neither returned nor raised yet."""
    import time

    time.sleep(0.5)


_FLAKY = {"calls": 0}


def sample_flaky():
    """Fails the first time it runs, passes the second."""
    _FLAKY["calls"] += 1
    assert _FLAKY["calls"] % 2 == 0


def test_a_second_def_under_the_name_is_no_evidence(monkeypatch, request):
    """Ninth review (2026-10-01): every function the file defined under the name counted - a same-named
    staticmethod in a class, or a second module-level def - so a body other than the cited one was evidence."""
    assert _call_watched(monkeypatch, request, sample_twice, name="sample_twice") is False
    assert _call_watched(monkeypatch, request, _Shadow.sample_evidence) is False
    assert _call_watched(monkeypatch, request, sample_evidence) is True


def test_user_properties_cannot_forge_or_strip_the_guards_verdicts(monkeypatch):
    """Ninth review: an autouse fixture appending ("warden_body_ran", True) - or removing ("warden_genuine", False) -
    changed the verdict. The guard puts its verdicts on the report from its own records."""
    monkeypatch.setattr(conftest, "_REPORTS", {})
    forged = types.SimpleNamespace(nodeid="tests/test_a.py::test_one", skipped=False, when="call", outcome="passed",
                                   user_properties=[("warden_genuine", True), ("warden_body_ran", True)])
    conftest.pytest_runtest_logreport(forged)
    assert conftest._REPORTS["tests/test_a.py::test_one"] == {"call:passed", "not-genuine"}

    item = types.SimpleNamespace(nodeid="tests/test_a.py::test_two")
    monkeypatch.setitem(conftest._GENUINE, item.nodeid, False)
    monkeypatch.setitem(conftest._RAN, item.nodeid, False)
    gen = conftest.pytest_runtest_makereport(item, types.SimpleNamespace(when="call"))
    next(gen)
    report = types.SimpleNamespace(user_properties=[("warden_genuine", True), ("warden_body_ran", True)])
    try:
        gen.send(report)
    except StopIteration as done:
        report = done.value
    assert report.warden_genuine is False and report.warden_body_ran is False


def test_the_guards_callbacks_replayed_by_a_wrapper_are_no_evidence(monkeypatch, request):
    """Ninth review: register_callback hands back the guard's callbacks; a wrapper called them itself with the
    genuine code object, and the body never ran."""
    import functools

    @functools.wraps(sample_evidence)
    def replays():
        mon = sys.monitoring
        for tool in (4, 3):
            if mon.get_tool(tool) == "warden-register-guard":
                start = mon.register_callback(tool, mon.events.PY_START, None)
                ret = mon.register_callback(tool, mon.events.PY_RETURN, None)
                mon.register_callback(tool, mon.events.PY_START, start)
                mon.register_callback(tool, mon.events.PY_RETURN, ret)
                start(sample_evidence.__code__, 0)
                ret(sample_evidence.__code__, 0, 1)

    assert _call_watched(monkeypatch, request, replays) is False


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_the_guard_needs_a_return_from_the_body_and_no_unwind_and_a_free_tool(monkeypatch, request):
    """Ninth review (mutation): dropping the "returned" check, ignoring the unwind, counting any code's return, using
    tool 4 only and dropping restart_events each passed every guard test. Each has its own shape here."""
    import threading

    def unjoined():  # the body starts and is still running when the call ends: never returned
        threading.Thread(target=sample_slow, daemon=True).start()
        sample_evidence()  # another code object returns meanwhile

    assert _call_watched(monkeypatch, request, unjoined, name="sample_slow") is False

    def retried():  # the body fails, its failure is swallowed, and it is run again until it passes
        _FLAKY["calls"] = 0
        with contextlib.suppress(AssertionError):
            sample_flaky()
        sample_flaky()

    assert _call_watched(monkeypatch, request, retried, name="sample_flaky") is False

    mon = sys.monitoring
    if mon.get_tool(4) is None:
        mon.use_tool_id(4, "a debugger")
        try:
            assert _call_watched(monkeypatch, request, sample_evidence) is True  # tool 3 instead
        finally:
            mon.free_tool_id(4)

    # A body the guard disabled while watching another test must start again when it is the one watched.
    assert _call_watched(monkeypatch, request, sample_evidence, name="sample_failing") is False
    assert _call_watched(monkeypatch, request, sample_evidence) is True


def test_a_blank_keyword_and_cache_show_are_judged_rightly():
    """Ninth review: `-k " "` (set by a conftest) selects every test but turned judging off; `--cache-show` runs no
    test and printed the red line."""
    tests = pathlib.Path(conftest.__file__).resolve().parent
    assert conftest._full_run(_config(["tests"], base=tests.parent, keyword=" "))
    assert conftest._full_run(_config(["tests"], base=tests.parent, markexpr="  "))
    assert not conftest._full_run(_config(["tests"], base=tests.parent, cacheshow=True))


def test_an_explicit_list_of_every_test_file_is_judged_and_a_partial_one_is_not():
    """Register R7-O4: `pytest $(find tests -name 'test_*.py')` runs the whole suite, and ran unjudged."""
    tests = pathlib.Path(conftest.__file__).resolve().parent
    every = sorted(str(f) for f in tests.rglob("test_*.py") if "__pycache__" not in f.parts)
    assert conftest._full_run(_config(every))
    assert not conftest._full_run(_config(every[1:]))  # one file short: a partial run
    assert not conftest._full_run(_config([*every[1:], every[0] + "::test_one"]))  # one test of a file, not the file
