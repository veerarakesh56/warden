"""Register O3: a remediation's Temporal history stays bounded, whatever a caller asks for."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from test_remediation_workflow import (  # noqa: F401 - fixtures
    REQ,
    _approve_with,
    _run,
    owner,
    world,
)
from warden import activities
from warden.activities import FixRequest


@pytest.mark.parametrize("field", ["approval_ttl_minutes", "recover_within_minutes"])
@pytest.mark.parametrize("value", [0, -1, 10**6])
def test_a_window_outside_its_bounds_is_refused(field, value):
    with pytest.raises(ValidationError):
        FixRequest(**{**REQ, field: value})


def test_the_longest_verify_window_keeps_the_history_far_under_temporals_limits(world, owner):  # noqa: F811
    world["platform"].healthy_after = None  # never recovers: every check of the longest window runs
    out = _run(world, _approve_with(owner), recover_within_minutes=activities.MAX_RECOVER_WITHIN_MINUTES)
    assert out.status == "rolled_back"
    events = world["history"].events
    size = len(world["history"].to_json())
    assert len(events) < 5_000 and size < 5_000_000, (len(events), size)  # Temporal's hard limits: 50k / 50 MB
