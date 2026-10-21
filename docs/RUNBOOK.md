# Runbook

The one page to start from when running WARDEN. It links the detailed pages rather than repeating them:
day-two operations are in [OPERATIONS.md](OPERATIONS.md), and what to do when WARDEN itself is the incident is in
[RUNBOOK-WARDEN-INCIDENT.md](RUNBOOK-WARDEN-INCIDENT.md). Written 2026-10-21 from `main`.

## How to run

| What | How | Details |
|---|---|---|
| Try it with no cloud and no key | `WARDEN_MOCK=1 warden demo --verbose` (five recorded incidents, a mock model) | README.md, "Quick start" |
| The workflows on a laptop | a local Temporal server, `WARDEN_MOCK=1 warden worker`, then `warden intake event.json` | README.md, "Run the workflows locally" |
| Set it up in your own AWS and GitHub | roles, environments, secrets, Temporal Cloud, Slack | [SETUP.md](SETUP.md) |
| WARDEN's cloud runtime (`ops`) | Actions -> *Runtime · ops* -> `image`, `plan`, `apply`, `restart`, `pause` or `resume` | `.github/workflows/runtime.yml`; [OPERATIONS.md](OPERATIONS.md), "Pause and resume" |
| The dev full-stack lab | Actions -> *Deploy · dev* -> `part: infra`, `infra_action: pause` or `resume` | [OPERATIONS.md](OPERATIONS.md); [FULLSTACK-LAB.md](FULLSTACK-LAB.md) |
| Inject and revert one lab fault | `python -m scenarios.fullstack_cli soak`, `inject <fault>`, `verify <fault>`, `revert <fault>` | [FULLSTACK-LAB.md](FULLSTACK-LAB.md) section 6 |
| The filmed demo | one fs-07 fix in dev, or the labelled sample variant | [DEMO.md](DEMO.md) |
| Qualify a model (paid; the owner's laptop) | `scripts/qualify_provider.py --out <a new directory outside the repository>` | [BENCHMARKS.md](BENCHMARKS.md); [USE-CASE.md](USE-CASE.md#success-criteria) |
| Rotate a secret or key | per-secret steps | [OPERATIONS.md](OPERATIONS.md), "Secret and key rotation" |

Who approves: in prod, always a person with a passkey; in dev, Eldane (an AI critic) for T1/T2 plans, with a person's
"no" winning for five minutes and until the apply starts. After a demotion, dev needs a person again until an approver
re-enables it with `warden autonomy enable` ([OPERATIONS.md](OPERATIONS.md), "Dev autonomy").

## Monitoring

| Signal | What it means | Where |
|---|---|---|
| `warden-<env>-heartbeat-missing` | no worker completed a round trip through Temporal | `terraform/modules/warden-runtime/` alarms; [RUNBOOK-WARDEN-INCIDENT.md](RUNBOOK-WARDEN-INCIDENT.md) section 2 |
| `warden-<env>-synthetic-missing` | the daily synthetic incident (every 24 h, `src/warden/runtime.py`) did not succeed through the diagnosis path | the same module |
| `warden-<env>-killswitch-on` | every fix is stopped | the same module |
| `warden-<env>-unapproved-actor` | an actor role was used with no approval on the record: treat as a credential compromise | [RUNBOOK-WARDEN-INCIDENT.md](RUNBOOK-WARDEN-INCIDENT.md) section 3 |
| `warden-<env>-approvers-changed` | the approver list changed | the same module |
| `warden-<env>-worker-errors`, `-lambda-errors`, `-lambda-throttles`, `-alarm-dlq`, `-audit-db-cpu`, `-audit-db-connections`, `-audit-db-storage` | the runtime's own health | the same module |
| Every incident and what happened to it | `https://<the approval domain>/r` (Sign in with Slack) | [OPERATIONS.md](OPERATIONS.md), "WARDEN's records" |
| Model calls, tokens and cost per day | `warden usage --days 30` (from the audit) | `src/warden/cli.py`; [COST.md](COST.md) |
| Dev autonomy and its demotions | `warden autonomy status --environment dev` | [OPERATIONS.md](OPERATIONS.md), "Dev autonomy" |
| The kill switch | `warden killswitch status` | [RUNBOOK-WARDEN-INCIDENT.md](RUNBOOK-WARDEN-INCIDENT.md) section 0 |
| Is the record intact | `warden audit verify` / `warden audit show <incident-id>`; the records page's "Signed record" line | [RUNBOOK-WARDEN-INCIDENT.md](RUNBOOK-WARDEN-INCIDENT.md) section 2 |
| Is any model qualified on today's prompt | `providers.qualified` has a row whose `prompt` equals `prompt.sha` | `src/warden/data/providers.yaml`; [DEMO.md](DEMO.md) has a one-line check |

## Known limitations

- **Production is rules-only until the laptop re-qualifies a model.** The diagnosis prompt pinned in
  `src/warden/data/providers.yaml` (`prompt.sha`) is marked "NOT YET QUALIFIED": every `qualified` row was measured on
  an earlier prompt, and a row counts only for the prompt it was measured with (`src/warden/providers.py`
  `qualified()`). So every model is refused, and each incident gets the rules-only diagnosis and goes to a person with
  no fix plan (register M19). Open PR #132 changes the prompt again, and so its hash; after it merges, the laptop
  qualifies once on the prompt then pinned (`scripts/qualify_provider.py`), records the row in `providers.yaml`, and
  only then does a model diagnose again. Read the current hash from `providers.yaml`; this page does not repeat it.
- The only model ever qualified for production is Claude Sonnet 5.5 (17 of 30, the bar exactly); Claude Opus 5.5 is
  not (15 of 30). The golden set is 30 incidents, and two runs of one model differ by about 2 ([USE-CASE.md](USE-CASE.md)).
- Eldane and the diagnosis are the same model family, which can share blind spots; what is done about it is in
  `src/warden/eldane.py`.
- The full-stack lab ran each fault once; no full-stack score is published, and its faults were designed by WARDEN's
  builders ([FULLSTACK-LAB.md](FULLSTACK-LAB.md) sections 7-8).
- Redis is read only through AWS APIs and CloudWatch (ElastiCache is VPC-only).
- The cloud audit database is reachable only from inside the runtime's VPC: `warden audit verify` on it needs
  `WARDEN_AUDIT_DSN` there; the records page checks signatures when it opens.
- How long `resume` takes has not been measured yet; AWS starts a stopped RDS database again after 7 days
  ([OPERATIONS.md](OPERATIONS.md), "Pause and resume").
- Model cost per incident is known from September token counts and October spend, not from today's prompt
  ([COST.md](COST.md)).

## Escalation

| When | Who or what | How |
|---|---|---|
| Any incident with no qualified model, a spent budget or a provider outage | the on-call person | WARDEN sends the rules-only report to the environment's Slack channel; nothing is changed |
| A plan in prod | an approver with a passkey | the approval page; it waits up to `approval_wait_hours` (default 72) and then expires with nothing changed |
| A plan in dev that Eldane approved and a person disagrees with | any approver | deny on the approval page with a passkey, within five minutes or until the apply starts; this also demotes dev to L1 |
| A fix that did not recover | WARDEN undoes it itself where the catalogue entry has an undo, ends `rolled_back` or `not_recovered`, and tells a person | [RUNBOOK-WARDEN-INCIDENT.md](RUNBOOK-WARDEN-INCIDENT.md) section 3 |
| WARDEN may be the cause, is down, or is being steered | the on-call person | [RUNBOOK-WARDEN-INCIDENT.md](RUNBOOK-WARDEN-INCIDENT.md): kill switch first, then the record |
| A question about an incident | anyone | `@WARDEN` with the incident id in the discussion channel ([OPERATIONS.md](OPERATIONS.md)) |
| Paging | PagerDuty's Events API v2 when its routing key is set (decision D13), and the runtime's self-alarms | [OPERATIONS.md](OPERATIONS.md); `terraform/modules/warden-runtime/paging.tf` |
