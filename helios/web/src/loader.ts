import type { InspectDoc, FailedResource } from "./types";

/**
 * Parse a string as an InspectDoc, throwing a friendly error if the shape is
 * wrong. The validation is intentionally minimal — the Rust producer is the
 * authority; this just guards against the user dropping in an unrelated JSON
 * file (a FailureChain alone, or a Terraform plan).
 */
export function parseInspect(raw: string): InspectDoc {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    throw new Error(
      `Not valid JSON: ${e instanceof Error ? e.message : String(e)}`,
    );
  }

  if (typeof parsed !== "object" || parsed === null) {
    throw new Error("Top-level JSON must be an object.");
  }
  const doc = parsed as Record<string, unknown>;

  if (typeof doc.scenario !== "string") {
    throw new Error("Missing string field `scenario` — is this a `helios inspect` output?");
  }
  if (typeof doc.graph !== "object" || doc.graph === null) {
    throw new Error("Missing object field `graph` — drop in `helios inspect` output, not a FailureChain.");
  }
  if (typeof doc.chain !== "object" || doc.chain === null) {
    throw new Error("Missing object field `chain`.");
  }

  const graph = doc.graph as Record<string, unknown>;
  if (!Array.isArray(graph.nodes) || !Array.isArray(graph.edges)) {
    throw new Error("`graph` must have array fields `nodes` and `edges`.");
  }

  return parsed as InspectDoc;
}

/** Index failures by Terraform address for fast lookup during render. */
export function failuresById(doc: InspectDoc): Map<string, FailedResource> {
  const m = new Map<string, FailedResource>();
  for (const f of doc.chain.failures) {
    m.set(f.id, f);
  }
  return m;
}
