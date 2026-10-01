"""Make the test suite hermetic regardless of the ambient environment.

The Makefile exports ``WARDEN_MOCK=1`` for ``make test``, but a bare ``pytest`` inherits the shell.
If a real provider key (``GEMINI_API_KEY``, ``ANTHROPIC_API_KEY``, ...) happens to be exported, the
pipeline tests resolve a *live* provider and either spend money or fail on auth — a footgun that has
bitten in practice. Tests must never depend on ambient credentials.

``setdefault`` (not overwrite) so an integration run that deliberately sets ``WARDEN_MOCK=0`` to
exercise the live path is still honoured; this only supplies the default the Makefile otherwise would.
"""

import ast
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
        item.user_properties.append(("warden_genuine", genuine))


@functools.cache
def _cited() -> frozenset[tuple[str, str]]:
    from test_register import cited_tests

    return frozenset(cited_tests())


@functools.cache
def _def_lines(path: str) -> dict[str, frozenset[int]]:
    """Each function the file defines, by name: the line its code object starts at (the first decorator's)."""
    found: dict[str, set[int]] = {}
    for node in ast.walk(ast.parse(pathlib.Path(path).read_text(encoding="utf-8"))):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            found.setdefault(node.name, set()).add(node.decorator_list[0].lineno if node.decorator_list else node.lineno)
    return {name: frozenset(lines) for name, lines in found.items()}


_TOOL = 4  # a free sys.monitoring tool id: 0-2 and 5 are the debugger, coverage, profiler and optimizer


@pytest.hookimpl(wrapper=True)
def pytest_pyfunc_call(pyfuncitem):
    """Did the body the file defines run? A swapped `__code__`, another function bound under the name, a wrapper,
    a hook that answers for the call, a fixture swapping `request.node.obj`: each passed the full run with an
    `assert False` body (seventh review, 2026-10-01). Only cited tests are watched, during their call: the start of
    the code object whose file, first line and name are the `def`'s."""
    if (pyfuncitem.nodeid.split("::", 1)[0], pyfuncitem.originalname) not in _cited():
        return (yield)
    if not hasattr(sys, "monitoring"):  # Python 3.11: cannot be checked, and says so
        pyfuncitem.user_properties.append(("warden_body_ran", None))
        return (yield)
    path = pathlib.Path(pyfuncitem.path).resolve()
    name, lines, ran = pyfuncitem.originalname, _def_lines(str(path)).get(pyfuncitem.originalname, frozenset()), []
    mon = sys.monitoring

    def started(code, _offset):
        if code.co_name == name and code.co_firstlineno in lines and pathlib.Path(code.co_filename).resolve() == path:
            ran.append(True)
        return mon.DISABLE

    mon.use_tool_id(_TOOL, "warden-register-guard")
    try:
        mon.restart_events()
        mon.register_callback(_TOOL, mon.events.PY_START, started)
        mon.set_events(_TOOL, mon.events.PY_START)
        return (yield)
    finally:
        mon.set_events(_TOOL, 0)
        mon.register_callback(_TOOL, mon.events.PY_START, None)
        mon.free_tool_id(_TOOL)
        pyfuncitem.user_properties.append(("warden_body_ran", bool(ran)))


def pytest_runtest_logreport(report):
    states = _REPORTS.setdefault(report.nodeid, set())
    states.add("skipped" if report.skipped else f"{report.when}:{report.outcome}")
    if ("warden_genuine", False) in report.user_properties:
        states.add("not-genuine")
    if report.when == "call" and ("warden_body_ran", True) in report.user_properties:
        states.add("body-ran")
    if report.when == "call" and ("warden_body_ran", None) in report.user_properties:
        states.add("body-unverifiable")


def _full_run(config) -> bool:
    """Judged: a run of the whole `tests` directory - however the path is spelled (`tests`, `tests/.`, `.`, an
    absolute path; sixth review, 2026-10-01) - nothing filtered, and something actually run."""
    here = pathlib.Path(__file__).resolve().parent
    base = pathlib.Path(getattr(getattr(config, "invocation_params", None), "dir", None) or pathlib.Path.cwd())

    def covers(arg: str) -> bool:
        path = (base / arg.split("::", 1)[0]).resolve()
        return path in (here, here.parent)

    return (not config.getoption("collectonly", default=False)
            and not config.getoption("keyword", default="") and not config.getoption("markexpr", default="")
            and not config.getoption("lf", default=False) and not config.getoption("deselect", default=None)
            and any(covers(a) for a in config.args))


def missing_evidence(reports: dict[str, set[str]], cited: set[tuple[str, str]]) -> list[str]:
    """Each cited test that did not run its own body and pass: skipped, xfailed, failed, absent, rebound, or its
    `def`'s code never started during the call."""
    missing = []
    for file, func in sorted(cited):
        ran = [states for nodeid, states in reports.items()
               if nodeid == f"{file}::{func}" or nodeid.startswith(f"{file}::{func}[")]
        if not ran or any("skipped" in st or "call:passed" not in st or "not-genuine" in st
                          or not ({"body-ran", "body-unverifiable"} & st) for st in ran):
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
