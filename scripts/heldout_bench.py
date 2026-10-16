"""Run WARDEN on a held-out incident set and score diagnosis and mitigation separately (G9-F).

    WARDEN_PROVIDER=anthropic python scripts/heldout_bench.py --cases ~/warden-heldout/g9-2026-10-10 \\
        --out ~/warden-bench-runs/heldout/g9-sonnet-5

A held-out set is written by someone who has not seen WARDEN's signatures, policies, prompt or rubrics: its cases
(`incidents/*.json`, each an alert and the evidence WARDEN's readers would have read) and its key (`answer-key.json`, kept
apart). Each case goes through today's redact -> tripwire -> diagnose -> verify, exactly as a replay does
(replay_diagnose.rediagnose), and is scored on four things the key decides, never on the hypothesis's prose:
- action: the proposal's ActionKind is in the key's correct actions (CORRECT), its harmful ones (HARMFUL), a passive
  one (SAFE: escalating or doing nothing when a fix existed), or anything else (WRONG);
- diagnosis: a citation of the answer quotes, or points at an item holding, one of the key's cause_evidence spans;
- gate: what the verifier decided (allowed for a person / escalated / rejected);
- mitigation: the right action reached a person (CORRECT and approved_for_human, or escalated by P6 alone);
- outcome: what the PERSON gets, whatever the model said (`outcome`, below) - a wrong proposal the gate turned into a
  hand-off is a right outcome where the key accepts a hand-off, and a right proposal the gate held back is not one
  where it does not.
`--reverify` scores the same answers under today's verifier (no model call): what a code change did, measured.
A replay cannot read more (the investigation loop's extra reads need live AWS): that is measured in the live window.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
PASSIVE = {"no_action", "escalate_to_human"}


def grade_action(action: str, key: dict) -> str:
    if action in key.get("correct_actions", []):
        return "CORRECT"
    if action in key.get("harmful_actions", []):
        return "HARMFUL"
    return "SAFE" if action in PASSIVE else "WRONG"


def cited_cause(report: dict, key: dict) -> bool:
    """A citation quotes a cause span, or names the evidence item that holds one."""
    spans = [s.lower() for s in key.get("cause_evidence", []) if s]
    if not spans:
        return False
    from warden import evidence
    from warden.models import ContextBundle

    items = {i.id: i.text.lower() for i in evidence.index(ContextBundle(**report["context"])).values()}
    for c in (report.get("root_cause") or {}).get("citations") or []:
        quote, text = str(c.get("quote", "")).lower(), items.get(str(c.get("id", "")).strip("[] "), "")
        if any(s in quote or quote and quote in s or s in text for s in spans):
            return True
    return False


OUTCOMES = ("right plan", "right hand-off", "right close", "held back", "missed fix", "wrong plan", "wrong close")
RIGHT_OUTCOMES = OUTCOMES[:3]


def outcome(action: str, status: str, reached: bool, key: dict) -> str:
    """What the person gets (2026-10-11: "correct action" counts what the model said, and most of the difference is
    WARDEN's own gate - in both directions).

    right plan      a keyed-right fix reached the approver
    right hand-off  no plan reached the approver, and handing to a person is a keyed-right answer
    right close     no_action left standing where the key says nothing is wrong
    held back       a keyed-right fix was proposed and did not reach the approver, where a hand-off is not keyed right
    missed fix      no right fix proposed and none planned, where a hand-off is not keyed right
    wrong plan      a plan the key does not hold reached the approver
    wrong close     no_action left standing where something is wrong"""
    right = set(key.get("correct_actions", []))
    if action not in PASSIVE and reached:
        return "right plan" if action in right else "wrong plan"
    if action == "no_action" and status == "auto_safe":
        return "right close" if "no_action" in right else "wrong close"
    if "escalate_to_human" in right:
        return "right hand-off"
    return "held back" if action in right else "missed fix"


def reverified(report: dict) -> dict:
    """The report with the verdict today's verifier gives its answer."""
    from warden import verifier
    from warden.models import Alert, ContextBundle, RemediationProposal, RootCause

    if not report.get("proposal") or not report.get("root_cause"):
        return report
    v = verifier.verify(Alert(**report["alert"]), ContextBundle(**report["context"]), RootCause(**report["root_cause"]),
                        RemediationProposal(**report["proposal"]))
    return {**report, "verdict": json.loads(v.model_dump_json())}


def score(report: dict, key: dict) -> dict:
    action = report["proposal"]["action"]
    verdict = report["verdict"]
    status, pids = verdict["status"], set(verdict.get("policy_ids") or [])
    grade = grade_action(action, key)
    reached = status == "approved_for_human" or (status == "escalated" and pids == {"P6-BLAST-RADIUS"})
    # A key may accept escalate_to_human beside a fix (review of G10, 2026-10-10: an always-escalate answer scored 86%
    # on one group). "fixed" counts only a fix where the key holds one; an escalation there is safe, not a fix.
    fixable = any(a not in PASSIVE for a in key.get("correct_actions", []))
    return {"action": action, "grade": grade, "cited_cause": cited_cause(report, key), "gate": status,
            "fixable": fixable, "fixed": fixable and grade == "CORRECT" and action not in PASSIVE,
            "policies": sorted(pids), "mitigation": grade == "CORRECT" and action not in PASSIVE and reached,
            "harm_allowed": grade in ("HARMFUL", "WRONG") and status in ("approved_for_human", "auto_safe"),
            "outcome": outcome(action, status, reached, key),
            "kind": key.get("kind"), "service": key.get("service"), "novel": bool(key.get("novel"))}


def summarise(rows: dict[str, dict]) -> dict:
    n = len(rows)
    by = lambda f: sum(1 for r in rows.values() if f(r))
    out = {"cases": n, "correct": by(lambda r: r["grade"] == "CORRECT"), "harmful": by(lambda r: r["grade"] == "HARMFUL"),
           "wrong": by(lambda r: r["grade"] == "WRONG"), "safe": by(lambda r: r["grade"] == "SAFE"),
           "cited_cause": by(lambda r: r["cited_cause"]), "mitigated": by(lambda r: r["mitigation"]),
           "harm_allowed": by(lambda r: r["harm_allowed"]),
           "unanswered": by(lambda r: "P0-MODEL-UNAVAILABLE" in r["policies"]),
           "fixable": by(lambda r: r.get("fixable")), "fixed": by(lambda r: r.get("fixed")),
           "escalated_a_fixable": by(lambda r: r.get("fixable") and r["action"] in PASSIVE),
           "outcome_right": by(lambda r: r.get("outcome") in RIGHT_OUTCOMES),
           "outcomes": {o: by(lambda r, o=o: r.get("outcome") == o) for o in OUTCOMES}}
    for kind in sorted({r["kind"] for r in rows.values()}):
        sub = [r for r in rows.values() if r["kind"] == kind]
        out[f"kind:{kind}"] = {"cases": len(sub), "correct": sum(r["grade"] == "CORRECT" for r in sub),
                               "cited_cause": sum(r["cited_cause"] for r in sub)}
    novel = [r for r in rows.values() if r["novel"]]
    out["novel"] = {"cases": len(novel), "correct": sum(r["grade"] == "CORRECT" for r in novel)}
    return out


def with_references(doc: dict) -> dict:
    """The case's evidence with what AWS's documentation says about its error codes - fetched as the read zone
    fetches it (graph.node_gather): closed codes from the typed facts, never the case's text."""
    import os

    from warden import aws_docs, evidence, quarantine
    from warden.models import ContextBundle

    os.environ["WARDEN_AWS_DOCS"] = "on"
    facts = [i.text for i in quarantine.reduce(evidence.index(ContextBundle(**doc["context"]))).values()]
    return {**doc["context"], "references": aws_docs.references(doc["alert"].get("labels") or {}, facts)}


def always_escalate(keys: dict[str, dict]) -> dict[str, int]:
    """What answering escalate_to_human to every case would score from the keys alone - the floor "correct" is read
    against (a WARDEN that never diagnosed anything)."""
    return {"cases": len(keys), "correct": sum("escalate_to_human" in k.get("correct_actions", []) for k in keys.values()),
            "fixed": 0}


def answer_key(cases: pathlib.Path) -> dict:
    """The set's answer key. Named `key.json` until 2026-10-16, the usual name of a GCP service-account key, so
    scanners and readers took it for a leaked credential (naming audit item 8); a copy outside the repository
    still named so is read, with a warning, for one release."""
    path = cases / "answer-key.json"
    if not path.exists() and (cases / "key.json").exists():
        path = cases / "key.json"
        print(f"warning: {path} is the old name; rename it answer-key.json (key.json stops being read in the next "
              "release)", file=sys.stderr)
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--cases", required=True, type=pathlib.Path)
    p.add_argument("--out", required=True, type=pathlib.Path)
    p.add_argument("--resume", action="store_true", help="answer only the cases not answered yet")
    p.add_argument("--score-only", action="store_true")
    p.add_argument("--reverify", action="store_true",
                   help="score the saved answers under today's verifier (implies --score-only; writes reverified.json)")
    p.add_argument("--docs", action="store_true",
                   help="fetch AWS's documentation on the evidence's error codes first, as the read zone does (G10-C6)")
    args = p.parse_args(argv)
    sys.path.insert(0, str(ROOT / "scripts"))
    key = answer_key(args.cases)
    reports = args.out / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    if not args.score_only and not args.reverify:
        from replay_diagnose import rediagnose

        from warden.llm import LLMClient

        for case in sorted((args.cases / "incidents").glob("*.json")):
            dest = reports / case.name
            if args.resume and dest.exists() and "P0-MODEL-UNAVAILABLE" not in dest.read_text(encoding="utf-8"):
                continue
            doc = json.loads(case.read_text(encoding="utf-8"))
            context = with_references(doc) if args.docs else doc["context"]
            report = rediagnose({"alert": doc["alert"], "context": context}, LLMClient())
            dest.write_text(report.model_dump_json(indent=2), encoding="utf-8")
            print(f"{doc['id']}: {report.proposal.action.value} {report.verdict.status.value}", flush=True)
    rows = {}
    for f in sorted(reports.glob("*.json")):
        case_id = json.loads((args.cases / "incidents" / f.name).read_text(encoding="utf-8"))["id"]
        report = json.loads(f.read_text(encoding="utf-8"))
        rows[case_id] = score(reverified(report) if args.reverify else report, key[case_id])
    summary = summarise(rows)
    summary["baseline_always_escalate"] = always_escalate({c: key[c] for c in rows})
    name = "reverified.json" if args.reverify else "scored.json"  # the run's own scores are never overwritten
    (args.out / name).write_text(json.dumps({"summary": summary, "rows": rows}, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
