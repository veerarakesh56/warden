"""Shared by tests/ and evals/: the injection detector is a stand-in that flags nothing, unless a test sets its own.

Every environment scans for injections (src/warden/data/environments.yaml tripwire "on",
register R47, 2026-10-14). Without this, every pipeline test would load the real Prompt Guard 2 where it is cached
(minutes per run) and report it unavailable where it is not (CI), so no test would depend on what it names. For the
whole session: module-wide fixtures run the pipeline before any per-test fixture. Tests of the detector patch it
themselves; `real_classifier` hands one the real loader.
"""

import pytest

_REAL: list = []


def _flags_nothing(texts, batch_size=16):
    return [[{"label": "MALICIOUS", "score": 0.0}, {"label": "BENIGN", "score": 1.0}] for _ in texts]


@pytest.fixture(autouse=True, scope="session")
def _tripwire_stand_in():
    from warden import tripwire

    _REAL.append(tripwire._classifier)
    patch = pytest.MonkeyPatch()
    patch.setattr(tripwire, "_classifier", lambda: _flags_nothing)
    yield
    patch.undo()


@pytest.fixture
def real_classifier():
    """The detector's own loader (tripwire._classifier), which the stand-in above replaces everywhere else."""
    return _REAL[0]
