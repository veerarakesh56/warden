// TS mirror of the helios-engine `InspectDoc` family. Field shapes must match
// `crates/helios-engine/src/inspect.rs` and the Pydantic mirror in
// `helios-ai/src/helios_ai/models.py`. Update all three together.

export interface InspectDoc {
  scenario: string;
  graph: GraphDoc;
  chain: FailureChain;
}

export interface GraphDoc {
  nodes: NodeDoc[];
  edges: EdgeDoc[];
}

export interface NodeDoc {
  id: string;
  kind: string;
  attrs: unknown;
}

export interface EdgeDoc {
  from: string;
  to: string;
  dep: DepDoc;
}

export interface DepDoc {
  kind: "Contains" | "MemberOf" | "Spread" | "Egress";
  via: string;
}

export interface FailureChain {
  scenario: string;
  failures: FailedResource[];
}

export interface FailedResource {
  id: string;
  kind: string;
  reason: string;
}
