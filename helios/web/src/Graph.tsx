import { useEffect, useRef } from "react";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import type { InspectDoc } from "./types";
import { failuresById } from "./loader";

export const GRAPH_STYLE: cytoscape.StylesheetStyle[] = [
  {
    selector: "node",
    style: {
      "background-color": "#dfe2e5",
      label: "data(label)",
      "font-size": "10px",
      "text-valign": "bottom",
      "text-margin-y": 4,
      "border-width": 1,
      "border-color": "#586069",
      width: 36,
      height: 36,
    },
  },
  {
    selector: 'node[failed = "yes"]',
    style: {
      "background-color": "#d73a49",
      "border-color": "#cb2431",
      "border-width": 3,
      color: "#cb2431",
      "font-weight": "bold",
    },
  },
  {
    selector: 'node[kind = "Vpc"]',
    style: { shape: "round-rectangle", width: 60, height: 36 },
  },
  {
    selector: 'node[kind = "Subnet"]',
    style: { shape: "diamond" },
  },
  {
    selector: "edge",
    style: {
      "curve-style": "bezier",
      "target-arrow-shape": "triangle",
      "line-color": "#959da5",
      "target-arrow-color": "#959da5",
    },
  },
  {
    selector: 'edge[dep = "Contains"]',
    style: { width: 3, "line-style": "solid" },
  },
  {
    selector: 'edge[dep = "MemberOf"]',
    style: { width: 1, "line-style": "dashed" },
  },
  {
    selector: 'edge[dep = "Spread"]',
    style: { width: 2, "line-style": "dotted" },
  },
  {
    selector: 'edge[dep = "Egress"]',
    style: { width: 2, "line-style": "dashed", "line-color": "#e36209", "target-arrow-color": "#e36209" },
  },
];

interface GraphProps {
  doc: InspectDoc;
  onSelect: (nodeId: string | null) => void;
}

/**
 * Single-page cytoscape canvas. Failed resources render red; healthy ones
 * pastel by kind. Contains edges thick + solid, MemberOf thin + dashed, Spread (placement
 * group members) medium + dotted, Egress (a subnet's NAT) medium + dashed orange.
 */
export function Graph({ doc, onSelect }: GraphProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;
    const failed = failuresById(doc);

    const elements: ElementDefinition[] = [
      ...doc.graph.nodes.map((n) => ({
        data: {
          id: n.id,
          label: n.id.replace(/^aws_/, ""),
          kind: n.kind,
          failed: failed.has(n.id) ? "yes" : "no",
        },
      })),
      ...doc.graph.edges.map((e) => ({
        data: {
          id: `${e.from}->${e.to}`,
          source: e.from,
          target: e.to,
          dep: e.dep.kind,
        },
      })),
    ];

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: GRAPH_STYLE,
      layout: { name: "breadthfirst", directed: true, padding: 20, spacingFactor: 1.2 },
    });

    cy.on("tap", "node", (evt) => onSelect(evt.target.id() as string));
    cy.on("tap", (evt) => {
      if (evt.target === cy) onSelect(null);
    });

    cyRef.current = cy;
    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [doc, onSelect]);

  return <div ref={containerRef} className="cy-container" data-testid="cy-container" />;
}
