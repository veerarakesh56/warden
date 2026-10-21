"""`warden records list|show`: WARDEN's records for an operator's terminal (owner update 3, U3-6) - the incidents,
their plans, who decided with what note, what tried to steer WARDEN and how each ended, as the records page shows
them, so a laptop session can read them without a browser sign-in.

Read only, by construction, not by promise:
- the audit is opened through ReadOnlyAudit, which has the log's read methods and no append, checkpoint or schema
  step; its store runs SELECT statements only, opens a SQLite file read-only (`mode=ro`, never created) and marks a
  PostgreSQL session read-only before its first query;
- no signing key is loaded (nothing is signed), and the command loads only the audit's DSN from the environment's
  store (settings.ONLY).

The same redaction as the records page: an approver by their name, never the approver list's id (records.record's
`shown` and `named`). And more than the page: every text is masked again with WARDEN's own patterns
(redaction.redact_many) before it is printed, so a value the pipeline masks - an e-mail, an address, an account id, a
key - is a placeholder here even where a row holds it in clear. Nothing here reads the privacy lane's vault or its
reveal path: a masked value is never shown through the CLI. A person reveals one on the records page, signed in and
recorded.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import sqlite3
import threading
import urllib.parse
from collections.abc import Callable
from datetime import datetime
from typing import Any

from . import audit, gate, links, records, redaction

# Fields that are WARDEN's own identifiers, times and states, printed as they are: masking an incident id (it can be
# UUID-shaped) would make `records show <id>` impossible to follow. Every other string is masked.
_KEEP = frozenset({"id", "at", "first", "last", "made", "status", "kind", "environment", "workflow_id", "plan_hash",
                   "audit_head", "tier", "entry", "step", "how", "what", "where", "severity", "with", "words",
                   "links_away"})
_INCIDENT = re.compile(r"[A-Za-z0-9._-]{1,120}")  # approval_page._INCIDENT_ID's shape
LIMIT_MAX = 500
_SELECT = re.compile(r"\s*SELECT\s", re.IGNORECASE)


class ReadOnlyStore:
    """The audit's store, for reading: SELECT only, on a SQLite file opened read-only or a PostgreSQL session whose
    transactions are read-only. The same `pg` and `run` the log's read methods use (audit._Store)."""

    def __init__(self, target: str | pathlib.Path) -> None:
        self._lock = threading.RLock()
        self.pg = audit._is_postgres(target)
        if self.pg:
            self.db = audit._pg_connect(str(target))
            # Before anything is read: the server refuses any write in this session, whatever the role may do.
            self.db.execute("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY")
        else:
            path = pathlib.Path(target)
            if not path.is_file():
                raise FileNotFoundError(f"no audit file at {path}")
            # mode=ro: SQLite opens it for reading only, and never creates it (audit._Store creates the tables).
            self.db = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True, check_same_thread=False)

    def run(self, sql: str, params: tuple | list = ()) -> Any:
        if not _SELECT.match(sql):
            raise PermissionError("the records reader runs SELECT statements only")
        with self._lock:
            return audit._Rows(self.db.execute(sql.replace("?", "%s") if self.pg else sql, params))

    def close(self) -> None:
        self.db.close()


class ReadOnlyAudit:
    """WARDEN's audit, for reading: the log's own read methods over a ReadOnlyStore, and no way to write."""

    entries = audit.AuditLog.entries
    intact = audit.AuditLog.intact
    signed_through = audit.AuditLog.signed_through
    head = audit.AuditLog.head

    def __init__(self, store: ReadOnlyStore) -> None:
        self.store = store

    def close(self) -> None:
        self.store.close()


def open_read_only() -> ReadOnlyAudit:
    """The audit runtime.open_audit opens - WARDEN_AUDIT_DSN, else the SQLite file WARDEN_AUDIT_DB - for reading."""
    dsn = os.environ.get("WARDEN_AUDIT_DSN", "").strip()
    if dsn:
        if not audit._is_postgres(dsn):
            raise RuntimeError("WARDEN_AUDIT_DSN must be a postgresql:// DSN")
        return ReadOnlyAudit(ReadOnlyStore(dsn))
    db = pathlib.Path(os.environ.get("WARDEN_AUDIT_DB") or "~/.warden/audit.db").expanduser()
    return ReadOnlyAudit(ReadOnlyStore(db))


# ------------------------------------------------------------------ what is printed


def _iso(t: datetime | None) -> str:
    return t.isoformat() if t else ""


def summary(r: records.Record) -> dict[str, Any]:
    """One incident as the list shows it."""
    return {"id": r.id, "first": _iso(r.first), "last": _iso(r.last), "status": r.status,
            "environment": r.environment, "service": r.service, "alarm": r.alarm, "flagged": bool(r.flags)}


def detail(r: records.Record, *, evidence: bool = False) -> dict[str, Any]:
    """One incident as its page shows it: the summary, the decisions (approvers by name), what tried to steer WARDEN,
    what WARDEN told people, every step, the report - and with `evidence`, what its model was shown."""
    steps, told = [], []
    for e in r.rows:
        if e["kind"] == "remediation.announce":
            b = e["body"]
            where = ("kept here, not posted" if b.get("recorded_only")
                     else "posted in the alerts channel" if b.get("delivered") else "not delivered")
            said = str(b.get("said") or "")
            told.append({"at": _iso(e["at"]), "what": records.TOLD.get(str(b.get("what")), "How the fix ended"),
                         "where": where, "said": r.named(said) if r.named else said})
        if e["kind"] in records._QUIET:
            continue
        step = (records.TOLD.get(str(e["body"].get("what")), "Told people how the fix ended")
                if e["kind"] == "remediation.announce" else records._step(e))
        brief = records._brief(e, r.shown)
        steps.append({"at": _iso(e["at"]), "step": step, "details": r.named(brief) if r.named else brief})
    plan = {k: v for k, v in r.plan.items() if k != "made"}
    linked = [{"words": links.WORDS.get(k.get("side"), str(k.get("side"))), "with": str(k.get("with")),
               "by": _who(r, str(k.get("approver"))), "at": str(k.get("at") or ""), "note": str(k.get("note") or "")}
              for k in r.links]
    found = [{"words": str(k.get("words")), "with": str(k.get("with"))} for k in r.found]
    proven = None
    if r.proven:
        at = r.proven.get("verified_at")
        proven = {"entry": r.proven.get("entry"), "target": r.proven.get("target"), "with": r.proven.get("incident"),
                  "at": _iso(at) if isinstance(at, datetime) else str(at or ""),
                  "links_away": len(r.proven.get("path") or ())}
    out = {**summary(r), "severity": r.severity, "alert_says": r.summary, "hypothesis": r.hypothesis,
           "confidence": r.confidence, "action": r.action, "target": r.target, "verdict": r.verdict,
           "policies": r.policies, "plan": plan, "no_plan": r.no_plan, "also": r.also, "questions": r.asked,
           "decisions": [{**d, "at": _iso(d.get("at"))} for d in r.decisions], "links": linked, "proven": proven,
           "found": found, "flags": r.flags, "told": told,
           "steps": steps, "report": r.report, "integrity": records.integrity(r), "audit_head": r.head,
           "signed_ok": r.signed_ok, "unsigned": r.unsigned, "broken": r.broken}
    if evidence:
        out["evidence"] = r.evidence
    return out


def _who(r: records.Record, approver: str) -> str:
    """Who linked a record, by name; never the list's id (records.linked)."""
    name = r.shown(approver) if r.shown else ""
    return name if name and name != approver else "an approver"


def _walk(data: Any, key: str = "") -> Any:
    """Every string a reader would see (not WARDEN's own ids, times and states), in order."""
    if isinstance(data, dict):
        for k, v in data.items():
            yield from _walk(v, k)
    elif isinstance(data, list):
        for v in data:
            yield from _walk(v, key)
    elif isinstance(data, str) and key not in _KEEP:
        yield data


def _replace(data: Any, texts: Any, key: str = "") -> Any:
    if isinstance(data, dict):
        return {k: _replace(v, texts, k) for k, v in data.items()}
    if isinstance(data, list):
        return [_replace(v, texts, key) for v in data]
    if isinstance(data, str):
        return gate.strip_controls(next(texts) if key not in _KEEP else data)
    return data


def masked(data: Any) -> Any:
    """`data` with every reader-facing string masked by WARDEN's own patterns, in one placeholder namespace, and no
    control character anywhere. New placeholders continue after the ones already in the record, so a `<EMAIL_1>` the
    pipeline placed and one placed here never name two values with one label."""
    texts = list(_walk(data))
    seed: dict[str, str] = {}
    for found in redaction._PLACEHOLDER.findall("\n".join(texts)):
        kind, _, n = found.strip("<>").rpartition("_")
        for i in range(1, int(n) + 1):
            seed.setdefault(f"<{kind}_{i}>", f"\x00{kind}{i}\x00")  # holds the number only: never in any text
    clean, _ = redaction.redact_many(texts, seed)
    return _replace(data, iter(clean))


def _when(iso: str) -> str:
    from .environments import both_times

    try:
        return both_times(datetime.fromisoformat(iso), seconds=False) if iso else "-"
    except ValueError:
        return "-"  # a time a row wrote in no form WARDEN writes


def list_text(rows: list[dict[str, Any]], matched: int, total: int) -> list[str]:
    lines = [f"{_when(s['first'])}  {s['status']:<30} {s['environment'] or '-'}/{s['service'] or '-'}  "
             f"{s['alarm'] or s['id']}{'  [flagged]' if s['flagged'] else ''}  ({s['id']})" for s in rows]
    return [*lines, f"{len(rows)} shown of {matched} matching ({total} incident(s) on the record)"]


def _lines(text: str, indent: str) -> list[str]:
    return [f"{indent}{line}" for line in str(text or "").splitlines() if line.strip()]


def _fix_plan(d: dict[str, Any]) -> str:
    plan = d["plan"]
    if plan:
        return f"{plan.get('entry')} on {plan.get('target')} - risk {plan.get('tier')}"
    return f"None: {d['no_plan']}" if d["no_plan"] else ""


def _fact_lines(d: dict[str, Any]) -> list[str]:
    confidence = f" (confidence {d['confidence']:.2f})" if isinstance(d["confidence"], int | float) else ""
    policies = f" ({', '.join(d['policies'])})" if d["policies"] else ""
    asked = f"{d['questions']} question(s) in the discussion channel" if d["questions"] else ""
    facts = [("Incident", d["id"]), ("Status", d["status"]), ("Alarm", d["alarm"]),
             ("Where", " / ".join(x for x in (d["environment"], d["service"]) if x)), ("Severity", d["severity"]),
             ("Alert says", d["alert_says"]), ("First seen", _when(d["first"])), ("Last step", _when(d["last"])),
             ("WARDEN thinks", d["hypothesis"] + confidence if d["hypothesis"] else ""),
             ("Safety check", d["verdict"].replace("_", " ") + policies if d["verdict"] else ""),
             ("Fix plan", _fix_plan(d)), ("Also fired", "; ".join(d["also"])), ("Discussion", asked),
             ("Signed record", d["integrity"].removeprefix("Signed record: "))]
    return [f"{k + ':':<15}{' '.join(str(v).split())}" for k, v in facts if v]


def _decision_lines(d: dict[str, Any]) -> list[str]:
    out = ["Decisions:"]
    if not d["decisions"]:
        return [*out, "  none on the record"]
    for x in d["decisions"]:
        hasty = " - quick decision" if x.get("hasty") else ""
        out.append(f"  {x['what']} by {x['who']} with their {x['how']} at {_when(x['at'])}{hasty}")
        out += _lines(x.get("note"), "    note: ")
    return out


def _link_lines(d: dict[str, Any]) -> list[str]:
    out = []
    for k in d["links"]:
        out.append(f"Linked: this incident {k['words']} {k['with']} - linked by {k['by']} at {_when(k['at'])}")
        out += _lines(k["note"], "    note: ")
    if d["proven"]:
        f = d["proven"]
        out.append(f"Proven fix on a linked record: {f['entry']} on {f['target']} was applied and verified in "
                   f"{f['with']} at {_when(f['at'])} ({f['links_away']} link(s) away) - a fact for a person to weigh; "
                   "WARDEN does not apply it on that account")
    return out + [f"Related (WARDEN found it): this incident {k['words']} {k['with']}" for k in d["found"]]


def _told_lines(d: dict[str, Any]) -> list[str]:
    if not d["told"]:
        return []
    out = ["What WARDEN told people:"]
    for t in d["told"]:
        out.append(f"  {t['what']} - {_when(t['at'])} - {t['where']}")
        out += _lines(t["said"], "    ")
    return out


def _step_line(s: dict[str, Any]) -> str:
    details = f" - {' '.join(s['details'].split())}" if s["details"] else ""
    return f"  {_when(s['at'])}  {s['step']}{details}"


def show_text(d: dict[str, Any]) -> list[str]:
    out = [*_fact_lines(d), *_decision_lines(d), *_link_lines(d), "Anything that tried to steer WARDEN:"]
    out += [f"  {f}" for f in d["flags"]] or ["  nothing on the record"]
    out += [*_told_lines(d), "Every step on the record:", *(_step_line(s) for s in d["steps"])]
    if d["report"]:
        out += ["", "Complete findings:", *d["report"].splitlines()]
    if d.get("evidence"):
        out += ["", "The evidence WARDEN read, exactly as its model was shown it:", *d["evidence"].splitlines()]
    return out


# ------------------------------------------------------------------ the command


def _policy() -> Any:
    from . import runtime_base

    try:
        return runtime_base.approver_policy()
    except Exception as exc:
        # Without the list, a refusal's text would name an approver by the list's id: nothing is shown instead.
        raise SystemExit("records: the approver list could not be read (WARDEN_APPROVERS, or WARDEN_ENV's SSM "
                         f"parameter): {type(exc).__name__}; nothing is shown without it, so nobody is named by "
                         "the list's id") from exc


def _query(args: Any) -> records.Query | None:
    pairs = [(k, v) for k, v in (("env", args.env), ("status", args.status), ("service", args.service),
                                 ("from", args.since), ("to", args.until), ("q", args.text)) if v]
    return records.parse_query(urllib.parse.urlencode(pairs))


def command(args: Any, out: Callable[..., None], *, log: Any = None, policy: Any = None) -> int:
    """`warden records list` or `warden records show <incident>`; `out` prints one line through the terminal gate.
    `log` and `policy` are for tests: the command opens the audit read-only and reads the approver list itself."""
    policy = policy if policy is not None else _policy()
    own = log is None
    log = open_read_only() if own else log
    try:
        if args.records_cmd == "list":
            return _list(args, out, log, policy)
        return _show(args, out, log, policy)
    finally:
        if own:
            log.close()


def _emit(data: Any, lines: Callable[[Any], list[str]], as_json: bool, out: Callable[..., None]) -> None:
    clean = masked(data)
    if as_json:
        out(json.dumps(clean, indent=2, ensure_ascii=False, default=str))
        return
    for line in lines(clean):
        out(line)


def _list(args: Any, out: Callable[..., None], log: Any, policy: Any) -> int:
    asked = _query(args)
    if asked is None or not 1 <= args.limit <= LIMIT_MAX:
        out("records: a filter is not one the records read: an environment or service name, a status the records "
            f"say, days as YYYY-MM-DD with the first before the last, text up to {records.TEXT_MAX} characters, "
            f"and a limit from 1 to {LIMIT_MAX}", err=True)
        return 2
    ids, loaded, total = records.matching(log, asked, None, policy)
    rows = []
    for i in ids[:args.limit]:
        r = loaded.get(i) or records.record(log, i, policy, light=True)
        if r is not None:
            rows.append(summary(r))
    if args.json:
        _emit({"incidents": rows, "matched": len(ids), "total": total}, list, True, out)
    else:
        _emit(rows, lambda clean: list_text(clean, len(ids), total), False, out)
    return 0


def _show(args: Any, out: Callable[..., None], log: Any, policy: Any) -> int:
    incident = str(args.incident)
    r = (records.record(log, incident, policy)
         if _INCIDENT.fullmatch(incident) and not incident.startswith("discuss-") else None)
    if r is None:
        out("records: no incident on the record under that id", err=True)
        return 1
    _emit(detail(r, evidence=args.evidence), show_text, args.json, out)
    return 0
