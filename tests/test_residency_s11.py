"""Register S11: data residency. Only redacted, typed facts reach a model (the quarantine); where the model
processed them is recorded with every diagnosis, read from the Bedrock inference profile itself."""

from __future__ import annotations

import pytest

from warden.llm import LLMClient
from warden.providers import BedrockProvider


@pytest.mark.parametrize(("model", "where"), [
    ("in.anthropic.claude-sonnet-5", "India (geography profile)"),
    ("global.anthropic.claude-sonnet-5", "any commercial AWS Region (global profile)"),
    ("eu.anthropic.claude-sonnet-5", "European Union (geography profile)"),
])
def test_a_geography_profile_names_where_it_may_process(model, where):
    assert BedrockProvider(model=model, client=object()).geography == where


def test_an_in_region_model_is_processed_in_the_configured_region(monkeypatch):
    monkeypatch.setattr("warden.environments.region", lambda: "test-region-1")
    assert BedrockProvider(model="anthropic.claude-sonnet-5", client=object()).geography == "test-region-1 only (in-Region model)"


def test_every_diagnosis_records_where_the_model_processed_it():
    from warden import graph
    from warden.cli import DEMO_ALERTS
    from warden.models import Alert

    report = graph.run(Alert(**DEMO_ALERTS["inc-002"]), llm=LLMClient(mock=True))
    [diag] = [a for a in report.audit if a.get("node") == "diagnose"]
    assert diag["provenance"]["processed_in"] == "nowhere (mock)"


def test_a_provider_without_a_known_geography_says_so():
    class Plain:
        name, model, version = "anthropic", "claude-sonnet-5", "x"

    assert LLMClient(provider=Plain(), mock=False).processed_in == "set by the provider, outside WARDEN's configuration"
