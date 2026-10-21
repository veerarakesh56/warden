"""Pydantic mirrors of the Rust `helios_engine` types.

Field names and shapes MUST match `FailureChain` / `FailedResource` in
`helios/crates/helios-engine/src/report.rs`, `FixProposal` / `FixEdit`
in `helios/crates/helios-engine/src/fix.rs`, and `InspectDoc` family in
`helios/crates/helios-engine/src/inspect.rs`. When the Rust structs change,
this file changes in the same PR.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class FailedResource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    kind: str
    reason: str


class Skipped(BaseModel):
    """Resources of one type Helios does not model: absent from the graph, NOT assumed healthy."""

    model_config = ConfigDict(extra="forbid")

    type: str
    count: int
    addresses: list[str]


class ChainDoc(BaseModel):
    """The Rust `FailureChain` exactly, as nested in `helios inspect` output."""

    model_config = ConfigDict(extra="forbid")

    scenario: str
    failures: list[FailedResource]


class FailureChain(ChainDoc):
    """`helios simulate --json` output: the chain plus the input's unsupported resources."""

    skipped: list[Skipped] = Field(default_factory=list)


class FixEdit(BaseModel):
    """A single structural edit on a resource's Terraform attrs.

    Only `op: "set_attr"` exists; adding or removing a resource is not implemented, and the
    engine refuses an edit that would move one (helios-engine fix::PLACEMENT_KEYS).
    """

    model_config = ConfigDict(extra="forbid")

    op: Literal["set_attr"]
    resource_id: str
    key: str
    value: Any


class FixProposal(BaseModel):
    """A candidate remediation — the engine re-simulates to verify it."""

    model_config = ConfigDict(extra="forbid")

    scenario_name: str
    explanation: str
    edits: list[FixEdit]


class NodeDoc(BaseModel):
    """One resource in the inspect graph."""

    model_config = ConfigDict(extra="forbid")

    id: str
    kind: str
    attrs: Any


class DepDoc(BaseModel):
    """Tagged dependency edge weight: kind ∈ {Contains, MemberOf, Spread, Egress}, via = attr."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["Contains", "MemberOf", "Spread", "Egress"]
    via: str


class EdgeDoc(BaseModel):
    """One directed edge: source/target Terraform addresses + dep weight."""

    # Rust emits `from`; alias the Python attribute to avoid the keyword clash.
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    from_: str = Field(alias="from")
    to: str
    dep: DepDoc


class GraphDoc(BaseModel):
    """Flat node + edge lists keyed on Terraform addresses."""

    model_config = ConfigDict(extra="forbid")

    nodes: list[NodeDoc]
    edges: list[EdgeDoc]


class InspectDoc(BaseModel):
    """Top-level `helios inspect` output: scenario + graph + resulting chain."""

    model_config = ConfigDict(extra="forbid")

    scenario: str
    graph: GraphDoc
    chain: ChainDoc
    skipped: list[Skipped] = Field(default_factory=list)
