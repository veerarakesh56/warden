import { describe, expect, it } from "vitest";
import { GRAPH_STYLE } from "../Graph";

describe("GRAPH_STYLE", () => {
  it("draws Spread edges medium and dotted, distinct from Contains and MemberOf", () => {
    const edgeStyle = (dep: string) =>
      GRAPH_STYLE.find((s) => s.selector === `edge[dep = "${dep}"]`)?.style as
        | Record<string, unknown>
        | undefined;
    expect(edgeStyle("Spread")).toEqual({ width: 2, "line-style": "dotted" });
    expect(edgeStyle("Contains")?.["line-style"]).toBe("solid");
    expect(edgeStyle("MemberOf")?.["line-style"]).toBe("dashed");
    expect(edgeStyle("Egress")).toMatchObject({ width: 2, "line-color": "#e36209" });
  });
});
