import json
from pathlib import Path

import pytest

from helios_ai.models import FailureChain

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize("fixture", ["az_outage_chain.json", "region_outage_chain.json"])
def test_failure_chain_round_trip(fixture: str) -> None:
    raw = json.loads((FIXTURES / fixture).read_text())
    chain = FailureChain.model_validate(raw)
    assert chain.scenario
    assert len(chain.failures) >= 1
    for f in chain.failures:
        assert f.id
        assert f.kind
        assert f.reason
    assert chain.model_dump() == raw


def test_az_outage_fixture_details() -> None:
    raw = json.loads((FIXTURES / "az_outage_chain.json").read_text())
    chain = FailureChain.model_validate(raw)
    assert chain.scenario == "lose-us-east-1a"
    ids = [f.id for f in chain.failures]
    assert "aws_instance.web" in ids
    assert "aws_subnet.public_a" in ids


def test_inspect_doc_round_trips_real_rust_output() -> None:
    """The Pydantic mirror must accept the JSON `helios inspect` actually emits."""
    from helios_ai.models import InspectDoc

    raw = json.loads((FIXTURES / "az_outage_inspect.json").read_text())
    doc = InspectDoc.model_validate(raw)

    assert doc.scenario == "lose-us-east-1a"
    assert len(doc.graph.nodes) > 0
    assert len(doc.graph.edges) > 0
    assert len(doc.chain.failures) > 0

    # Edge.dep.kind is one of the known variants.
    for e in doc.graph.edges:
        assert e.dep.kind in ("Contains", "MemberOf", "Spread", "Egress")
        assert e.dep.via  # non-empty attr name

    # Round-trip: dump → reload → equal. `by_alias=True` re-emits `from`.
    redumped = doc.model_dump(by_alias=True)
    assert redumped == raw


def test_skipped_resources_from_simulate_json_are_accepted() -> None:
    """`helios simulate --json` lists unsupported resources; `helios explain` must still read it."""
    raw = {
        "scenario": "s",
        "failures": [],
        "skipped": [{"type": "aws_sns_topic", "count": 1, "addresses": ["aws_sns_topic.t"]}],
    }
    chain = FailureChain.model_validate(raw)
    assert chain.skipped[0].type == "aws_sns_topic"
    assert chain.model_dump() == raw


def test_dep_doc_accepts_spread_and_rejects_unknown_kinds() -> None:
    from pydantic import ValidationError

    from helios_ai.models import DepDoc

    assert DepDoc.model_validate({"kind": "Spread", "via": "subnet_ids"}).kind == "Spread"
    assert DepDoc.model_validate({"kind": "Egress", "via": "nat_gateway_id"}).kind == "Egress"
    with pytest.raises(ValidationError):
        DepDoc.model_validate({"kind": "Nearby", "via": "x"})


def test_glossary_covers_spread_rules_and_resource_loss() -> None:
    from helios_ai.glossary import AVAILABILITY_MODEL_GLOSSARY as g

    for term in (
        "Spread",
        "Egress",
        "AnySurvivor",
        "FailsIfAnyDown",
        "resource-loss",
        "aws_eks_node_group",
        "Inconclusive",
    ):
        assert term in g, term


def test_glossary_mentions_every_model_variant() -> None:
    from helios_ai.glossary import AVAILABILITY_MODEL_GLOSSARY

    for variant in ("SingleAz", "MultiAz", "Regional", "GlobalEdge"):
        assert variant in AVAILABILITY_MODEL_GLOSSARY, variant
    # Must be large enough to benefit from prompt caching (~1024 tokens min).
    assert len(AVAILABILITY_MODEL_GLOSSARY) > 2000
