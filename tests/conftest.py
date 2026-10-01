"""Make the test suite hermetic regardless of the ambient environment.

The Makefile exports ``WARDEN_MOCK=1`` for ``make test``, but a bare ``pytest`` inherits the shell.
If a real provider key (``GEMINI_API_KEY``, ``ANTHROPIC_API_KEY``, ...) happens to be exported, the
pipeline tests resolve a *live* provider and either spend money or fail on auth — a footgun that has
bitten in practice. Tests must never depend on ambient credentials.

``setdefault`` (not overwrite) so an integration run that deliberately sets ``WARDEN_MOCK=0`` to
exercise the live path is still honoured; this only supplies the default the Makefile otherwise would.
"""

import logging
import os

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


def pytest_runtest_logreport(report):
    _REPORTS.setdefault(report.nodeid, set()).add(
        "skipped" if report.skipped else f"{report.when}:{report.outcome}")


def _full_run(config) -> bool:
    args = [a.replace("\\", "/").rstrip("/") for a in config.args]
    return (not config.getoption("keyword", default="") and not config.getoption("markexpr", default="")
            and not config.getoption("lf", default=False) and not config.getoption("deselect", default=None)
            and "tests" in [a.rsplit("/", 1)[-1] for a in args])


def pytest_sessionfinish(session, exitstatus):
    config = session.config
    if hasattr(config, "workerinput") or not _full_run(config):
        return
    from test_register import cited_tests

    missing = []
    for file, func in sorted(cited_tests()):
        ran = [states for nodeid, states in _REPORTS.items()
               if nodeid == f"{file}::{func}" or nodeid.startswith(f"{file}::{func}[")]
        if not ran or any("skipped" in st or "call:passed" not in st for st in ran):
            missing.append(f"{file}::{func}")
    if missing:
        reporter = config.pluginmanager.get_plugin("terminalreporter")
        if reporter:
            reporter.write_line(f"REGISTER EVIDENCE DID NOT RUN AND PASS: {missing}", red=True)
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
