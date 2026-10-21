from __future__ import annotations

import pytest

from helios_ai._mock import MockAnthropic


@pytest.fixture
def fake_client() -> MockAnthropic:
    return MockAnthropic()
