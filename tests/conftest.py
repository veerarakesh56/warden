"""Make the test suite hermetic regardless of the ambient environment.

The Makefile exports ``WARDEN_MOCK=1`` for ``make test``, but a bare ``pytest`` inherits the shell.
If a real provider key (``GEMINI_API_KEY``, ``ANTHROPIC_API_KEY``, ...) happens to be exported, the
pipeline tests resolve a *live* provider and either spend money or fail on auth — a footgun that has
bitten in practice. Tests must never depend on ambient credentials.

``setdefault`` (not overwrite) so an integration run that deliberately sets ``WARDEN_MOCK=0`` to
exercise the live path is still honoured; this only supplies the default the Makefile otherwise would.
"""

import functools
import logging
import os
import pathlib
import sys

import pytest

os.environ.setdefault("WARDEN_MOCK", "1")


@pytest.fixture(autouse=True)
def _root_logger_restored():
    """Every CLI command installs the log gate on the root logger. Each test starts and ends with the
    root logger as it was, so no test depends on which ran before it (fourth review: one did)."""
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)



def pytest_configure(config):
    """Under pytest-xdist, start Temporal's time-skipping test server once in the controller, before any
    worker exists: the SDK downloads its binary on first use to one shared path, and several workers doing
    that at once failed with "Text file busy" (CI, 2026-09-30, commit 14e32e1). Workers then find it."""
    if hasattr(config, "workerinput") or not config.getoption("numprocesses", default=None):
        return
    import asyncio

    from temporalio.testing import WorkflowEnvironment

    async def warm() -> None:
        env = await WorkflowEnvironment.start_time_skipping()
        await env.shutdown()

    asyncio.run(warm())


# Evidence must have run (fifth review, 2026-10-01). tests/test_register.py refuses the skips it can see in
# the source, but pytest has more ways to skip than any source check can list (a decorator split over two
# lines, `raise unittest.SkipTest`, an empty parametrize, a skipping fixture...). So the full run itself
# checks: every test a DONE-local register row cites must have run its body and passed - not skipped, not
# xfailed, not missing. Only a full run (`pytest`, `pytest tests evals`, no -k/-m) is judged.
_REPORTS: dict[str, set[str]] = {}


def pytest_collection_modifyitems(session, config, items):
    """Each test says whether it is the function its file defines under its name. A cited test rebound to
    another function - `globals()["test_x"] = lambda: None`, which no linter sees - passed vacuously and the
    guard counted it (sixth review, 2026-10-01). user_properties reach the controller under xdist too."""
    import inspect

    for item in items:
        fn = getattr(item, "function", None)
        try:
            genuine = (fn is not None and fn.__name__ == item.originalname
                       and fn.__module__ == item.module.__name__
                       and pathlib.Path(inspect.getsourcefile(fn) or "").resolve() == pathlib.Path(item.path).resolve())
        except (TypeError, OSError):
            genuine = False
        _GENUINE[item.nodeid] = genuine


@functools.cache
def _cited() -> frozenset[tuple[str, str]]:
    from test_register import CI_ONLY, cited_tests

    # A CI-only test skips here; its CI job runs it and fails on any skip (test_register.CI_ONLY).
    return frozenset((file, test) for file, test in cited_tests() if file not in CI_ONLY)


# Captured when the suite starts: an autouse fixture deleting `sys.monitoring` turned the check off (eighth review).
_MONITORING = getattr(sys, "monitoring", None)
_TOOLS = (4, 3)  # free sys.monitoring tool ids: 0-2 and 5 are the debugger, coverage, profiler and optimizer
_DEFINED: dict[str, dict[str, list]] = {}
# The guard's own verdicts, kept here and put on the reports by its own hook - not in user_properties, which any
# fixture can append to or strip (ninth review: an autouse fixture appending ("warden_body_ran", True) passed).
_GENUINE: dict[str, bool] = {}
_RAN: dict[str, bool | None] = {}


def _defined(module, config) -> dict[str, list]:
    """The code objects the test file itself defines at module level - never a def nested in a function or in a
    class - compiled exactly as pytest loaded the file (its assertion rewriting included). A code object with the
    def's file, line and name but another body (`code.replace(...)`, `compile()` padded to the line, a nested def
    bound under the name) is not equal to these (eighth review, 2026-10-01). A cited test is `file::name`, so a
    class's methods were never one - and a class's same-named staticmethod counted (ninth review)."""
    import types

    origin = str(module.__spec__.origin)
    if origin not in _DEFINED:
        if config.getoption("assertmode", default="rewrite") == "rewrite":
            from _pytest.assertion.rewrite import _rewrite_test

            _, code = _rewrite_test(pathlib.Path(origin), config)
        else:
            code = compile(pathlib.Path(origin).read_bytes(), origin, "exec", dont_inherit=True)
        found: dict[str, list] = {}
        for const in code.co_consts:
            if isinstance(const, types.CodeType) and const.co_flags & 0x1:  # CO_OPTIMIZED: a module-level function
                found.setdefault(const.co_name, []).append(const)
        _DEFINED[origin] = found
    return _DEFINED[origin]


@pytest.hookimpl(wrapper=True)
def pytest_pyfunc_call(pyfuncitem):
    """Did the body the file defines run, return and never raise? Judged at collection, a rebound name passed
    (sixth review); judged by a start of code with the def's file, line and name, a fake code object, or a body
    that raised with the failure swallowed by a wrapper, a hook or a thread passed (seventh and eighth reviews).
    Only cited tests are watched, during their call: the start, return and unwind of the code objects equal to
    those the file defines."""
    if (pyfuncitem.nodeid.split("::", 1)[0], pyfuncitem.originalname) not in _cited():
        return (yield)
    if _MONITORING is None:  # deleted before the suite started: no evidence (Python 3.12+ always has it)
        _RAN[pyfuncitem.nodeid] = False
        return (yield)
    mon, name = _MONITORING, pyfuncitem.originalname
    # A name the file defines twice is no evidence: `def test_x(): assert False`, `del test_x`, `def test_x(): pass`
    # passed with the second body (ninth review).
    expected = _defined(pyfuncitem.module, pyfuncitem.config).get(name, [])
    expected = expected if len(expected) == 1 else []
    seen = {"started": 0, "returned": 0, "unwound": 0}
    watched: list = []

    def started(code, _offset):
        if code.co_name == name and any(code == e for e in expected):
            seen["started"] += 1
            watched.append(code)
            return None
        return mon.DISABLE

    # Called by the interpreter, the callback's caller is the frame of the code that returned; a wrapper that took
    # the callbacks back from register_callback and called them itself is not (ninth review). A replayed start
    # alone is no evidence: only the body's own return counts.
    def returned(code, _offset, _value):
        if any(code is w for w in watched) and sys._getframe(1).f_code is code:
            seen["returned"] += 1
            return None
        return mon.DISABLE

    def unwound(code, _offset, _exc):
        if any(code is w for w in watched):
            seen["unwound"] += 1

    tool = next((t for t in _TOOLS if mon.get_tool(t) is None), None)
    if tool is None:  # every id we may use is taken: no evidence rather than a crash that hides the result
        _RAN[pyfuncitem.nodeid] = False
        return (yield)
    events = mon.events
    mon.use_tool_id(tool, "warden-register-guard")
    try:
        mon.restart_events()
        mon.register_callback(tool, events.PY_START, started)
        mon.register_callback(tool, events.PY_RETURN, returned)
        mon.register_callback(tool, events.PY_UNWIND, unwound)
        mon.set_events(tool, events.PY_START | events.PY_RETURN | events.PY_UNWIND)
        return (yield)
    finally:
        mon.set_events(tool, 0)
        for event in (events.PY_START, events.PY_RETURN, events.PY_UNWIND):
            mon.register_callback(tool, event, None)
        mon.free_tool_id(tool)
        _RAN[pyfuncitem.nodeid] = seen["started"] > 0 and seen["returned"] > 0 and seen["unwound"] == 0


@pytest.hookimpl(wrapper=True)
def pytest_runtest_makereport(item, call):
    """The guard's verdicts on the report, set here; xdist carries a report's attributes to the controller."""
    report = yield
    report.warden_genuine = _GENUINE.get(item.nodeid, False)
    if call.when == "call":
        report.warden_body_ran = _RAN.pop(item.nodeid, False)
    return report


def pytest_runtest_logreport(report):
    states = _REPORTS.setdefault(report.nodeid, set())
    states.add("skipped" if report.skipped else f"{report.when}:{report.outcome}")
    if getattr(report, "warden_genuine", False) is not True:
        states.add("not-genuine")
    if report.when == "call" and getattr(report, "warden_body_ran", False) is True:
        states.add("body-ran")


def _full_run(config) -> bool:
    """Judged: a run of the whole `tests` directory - however the path is spelled (`tests`, `tests/.`, `.`, an
    absolute path; sixth review, 2026-10-01) - nothing filtered, and something actually run."""
    here = pathlib.Path(__file__).resolve().parent
    base = pathlib.Path(getattr(getattr(config, "invocation_params", None), "dir", None) or pathlib.Path.cwd())

    def covers(arg: str) -> bool:
        path = (base / arg.split("::", 1)[0]).resolve()
        return path in (here, here.parent)

    # Modes that run no test bodies are not judged: they printed the red evidence line (`--fixtures`) or failed the
    # run (`--setup-plan`) - eighth review.
    if any(config.getoption(o, default=False) for o in ("showfixtures", "show_fixtures_per_test", "setuponly",
                                                        "setupplan", "cacheshow")):
        return False
    # A blank `-k " "` selects every test (pytest strips it): it is no filter, and must not turn judging off (ninth).
    return (not config.getoption("collectonly", default=False)
            and not str(config.getoption("keyword", default="") or "").strip()
            and not str(config.getoption("markexpr", default="") or "").strip()
            and not config.getoption("lf", default=False) and not config.getoption("deselect", default=None)
            and (any(covers(a) for a in config.args) or _every_test_file(config.args, base, here)))


def _every_test_file(args, base: pathlib.Path, here: pathlib.Path) -> bool:
    """A shell-expanded list of every test file (`pytest $(find tests -name 'test_*.py')`) runs the whole suite as
    much as `pytest tests` does, and is judged too (register R7-O4)."""
    given = [(base / a).resolve() for a in args if "::" not in a]
    files = [f for f in here.rglob("test_*.py") if "__pycache__" not in f.parts]
    return bool(files) and all(any(g == f or g in f.parents for g in given) for f in files)


def missing_evidence(reports: dict[str, set[str]], cited: set[tuple[str, str]]) -> list[str]:
    """Each cited test that did not run its own body and pass: skipped, xfailed, failed, absent, rebound, or its
    `def`'s code never started during the call."""
    missing = []
    for file, func in sorted(cited):
        ran = [states for nodeid, states in reports.items()
               if nodeid == f"{file}::{func}" or nodeid.startswith(f"{file}::{func}[")]
        if not ran or any("skipped" in st or "call:passed" not in st or "not-genuine" in st
                          or "body-ran" not in st for st in ran):
            missing.append(f"{file}::{func}")
    return missing


def pytest_sessionfinish(session, exitstatus):
    config = session.config
    if hasattr(config, "workerinput") or not _full_run(config):
        return
    missing = missing_evidence(_REPORTS, set(_cited()))
    if missing:
        reporter = config.pluginmanager.get_plugin("terminalreporter")
        if reporter:
            reporter.write_line(f"REGISTER EVIDENCE DID NOT RUN AND PASS: {missing}", red=True)
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
