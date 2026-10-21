import { describe, expect, it } from "vitest";
import { parseInspect, failuresById } from "../loader";
import sample from "../../public/sample.json";

describe("parseInspect", () => {
  it("accepts the real `helios inspect` JSON", () => {
    const doc = parseInspect(JSON.stringify(sample));
    expect(doc.scenario).toBe("lose-us-east-1a");
    expect(doc.graph.nodes.length).toBeGreaterThan(0);
    expect(doc.graph.edges.length).toBeGreaterThan(0);
    expect(doc.chain.failures.length).toBeGreaterThan(0);
  });

  it("rejects a bare FailureChain (missing graph field)", () => {
    const chain = JSON.stringify({
      scenario: "x",
      failures: [],
    });
    expect(() => parseInspect(chain)).toThrow(/graph/);
  });

  it("rejects non-JSON input", () => {
    expect(() => parseInspect("not json")).toThrow(/Not valid JSON/);
  });

  it("rejects null", () => {
    expect(() => parseInspect("null")).toThrow(/object/);
  });

  it("rejects a graph without nodes/edges arrays", () => {
    const bad = JSON.stringify({
      scenario: "x",
      graph: { nodes: "oops", edges: [] },
      chain: { scenario: "x", failures: [] },
    });
    expect(() => parseInspect(bad)).toThrow(/nodes.*edges/);
  });
});

describe("failuresById", () => {
  it("indexes failures by terraform address", () => {
    const doc = parseInspect(JSON.stringify(sample));
    const m = failuresById(doc);
    expect(m.size).toBe(doc.chain.failures.length);
    for (const f of doc.chain.failures) {
      expect(m.get(f.id)?.reason).toBe(f.reason);
    }
  });
});
