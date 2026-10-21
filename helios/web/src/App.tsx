import { useState } from "react";
import { Graph } from "./Graph";
import { parseInspect, failuresById } from "./loader";
import type { InspectDoc, NodeDoc } from "./types";

export function App() {
  const [doc, setDoc] = useState<InspectDoc | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [pasted, setPasted] = useState("");

  function load(raw: string) {
    try {
      setDoc(parseInspect(raw));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setDoc(null);
    }
  }

  function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    file.text().then(load);
  }

  async function loadSample() {
    const r = await fetch("/sample.json");
    load(await r.text());
  }

  const failed = doc ? failuresById(doc) : null;
  const selectedNode: NodeDoc | undefined =
    doc && selected ? doc.graph.nodes.find((n) => n.id === selected) : undefined;
  const selectedFailure = doc && selected ? doc.chain.failures.find((f) => f.id === selected) : undefined;

  return (
    <div className="app">
      <header className="app-header">
        <h1>Helios viewer</h1>
        <input type="file" accept="application/json" onChange={onFile} />
        <button type="button" onClick={loadSample}>Load sample</button>
        {doc && (
          <span className="scenario-label">
            Scenario: <code>{doc.scenario}</code> · {failed?.size ?? 0} failure(s)
          </span>
        )}
      </header>

      {!doc && !error && (
        <section className="empty-state">
          <p>
            Drop a <code>helios inspect</code> JSON file (or paste it below) to render the resource graph.
          </p>
          <textarea
            placeholder='Paste JSON here…'
            value={pasted}
            onChange={(e) => setPasted(e.target.value)}
            rows={12}
          />
          <button type="button" disabled={!pasted.trim()} onClick={() => load(pasted)}>
            Render
          </button>
        </section>
      )}

      {error && (
        <section className="error" role="alert">
          <strong>Couldn't load:</strong> {error}
        </section>
      )}

      {doc && (
        <main className="layout">
          <Graph doc={doc} onSelect={setSelected} />
          <aside className="detail-pane">
            {selectedNode ? (
              <>
                <h2>{selectedNode.id}</h2>
                <p>
                  <strong>Kind:</strong> {selectedNode.kind}
                </p>
                {selectedFailure && (
                  <p className="failed-reason">
                    <strong>Failure:</strong> {selectedFailure.reason}
                  </p>
                )}
                <details>
                  <summary>attrs</summary>
                  <pre>{JSON.stringify(selectedNode.attrs, null, 2)}</pre>
                </details>
              </>
            ) : (
              <p>Select a node to inspect its attrs and failure reason.</p>
            )}
          </aside>
        </main>
      )}
    </div>
  );
}
