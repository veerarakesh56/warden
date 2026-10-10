# G10 held-out benchmark: DATA group

**Author:** an independent benchmark-author agent (Claude Opus 5.5, Claude Code), 2026-10-10.
**Scope:** Aurora/RDS (PostgreSQL and MySQL), DynamoDB, ElastiCache (Redis and Serverless Valkey), MemoryDB, OpenSearch, Redshift, S3, EFS.

## Contents

- `incidents/g10-data-NN.json` holds 41 cases as `{id, alert, context}`. Each is what WARDEN's stack backend would gather for one CloudWatch alarm.
- `key.json` holds the answer key per id: `kind`, `service`, `novel`, `cause`, `cause_evidence`, `correct_actions`, `harmful_actions` and `target`.
- `generator/gen.py` builds both from the case definitions.
- `generator/validate.py` checks every case against WARDEN's own models and exits 1 on any problem.

Run them from `generator/` (on Git Bash, give PYTHONPATH as one path, not a `;` list):

    PYTHONPATH=C:\work\warden-g1\src C:\work\warden\.venv\Scripts\python.exe gen.py
    PYTHONPATH=C:\work\warden-g1\src C:\work\warden\.venv\Scripts\python.exe validate.py

The validator checks these things:

- `Alert(**alert)` loads with no `rejected_labels`.
- `ContextBundle(**context)` loads.
- Every action is an `ActionKind`.
- Every `cause_evidence` string appears verbatim in an item text of `warden.evidence.index(ContextBundle(...))`, which is what WARDEN shows. Tool errors are matched in their reduced T form (for example `logs dynamodb: access denied on DescribeTable`), not their raw text.
- LOG lines are in time order, and no case id appears inside the evidence.
- LOG and EVENT lines fall within 15 minutes either side of the alert.
- CHANGE lines fall inside the 6-hour change window.
- Every no-fault key is exactly `[no_action, escalate_to_human]`, and every incomplete key is exactly `[escalate_to_human]`.

## Mix

| kind | count |
|---|---|
| fault | 23 |
| multi_fault | 6 |
| no_fault | 6 |
| incomplete | 6 |

- **Novel cases:** 18 of 41 (44%). They are:
  - Postgres:
    - transaction ID wraparound pinned by a 3-day idle transaction (04)
    - lock queue behind an ALTER TABLE (02)
    - an inactive logical replication slot filling storage (05)
  - Aurora:
    - Serverless v2 ACU ceiling set by a change (06, 29)
  - MySQL:
    - Aurora MySQL lock queue, blocker unreadable (08)
    - RDS burstable instance out of CPU credits (31)
  - DynamoDB:
    - hot partition shown by key-range throttles (12)
    - GSI back-pressure (13)
    - max on-demand throughput cap (14)
  - Caches:
    - Redis big-key HGETALL (16)
    - MemoryDB noeviction OOM (17)
    - ElastiCache Serverless ECPU limit (18)
  - Other stores:
    - OpenSearch flood-stage watermark (19)
    - Redshift WLM queue saturation (20)
    - S3 prefix SlowDown (21, 30)
    - EFS switched to bursting throughput and out of credits (24)
- **Decoys:** unrelated changes or deploys appear in 01, 07, 10, 12 and 35. In 33 and 36 a planned change is the reason nothing is wrong.

## Independence rules followed

- **Files read in `C:\work\warden-g1\src\warden` (read only):**
  - `aws_stack.py`, `aws_describe.py` and `resources.py`
  - `aws_backend.py`, `database.py` and `tools.py`
  - `quarantine.py`, `evidence.py` and `models.py`
  - `k8s_backend.py` was allowed but not opened.
- **Never opened:**
  - `data/`, `fixtures/`, `scenarios/` and `platforms/`
  - `verifier.py`, `grounding.py`, `graph.py`, `catalog.py`, `resolver.py`
  - `knowledge.py`, `playbook.py`, `runbook.py`, `investigation.py`
  - `docs/`, `tests/`, `evals/` and `scripts/`
  - `~/warden-bench-runs`, the g9 held-out set and `~/.claude`
- **Imports:** the scripts import only `warden.resources.labels_for`, `warden.models` and `warden.evidence.index`. The last was used once, to see how WARDEN classifies each generated line.
  - In one negative-test run, a `;`-joined PYTHONPATH loaded the main checkout's older copies of those same modules. That run was discarded and redone against the g1 copies.
- Nothing under `C:\work` was modified. No AWS or network calls were made, and no secrets are used.

## Assumptions that matter

1. **How an alarm becomes an alert.** I did not read the ingest module. I set the fields as follows:
   - `name` is the alarm name.
   - `service` is the main resource.
   - `summary` is description-like text.
   - `labels` are `resources.labels_for(namespace, dimensions)` plus `alarm`.
2. **Lambda logs and deploys only come through metric-math alarms.** Data services have no log reader. The only way an alarm brings in Lambda logs and deploys is a metric-math alarm that also names `AWS/Lambda FunctionName`.
   - Those cases (03, 07, 08, 16, 17, 21, 27, 28, 30) therefore have an `ALARM metric-math` line.
   - They have no `alarm_*` or `alarm_sibling_*` metrics, because the reader reads none for metric math.
3. **Database sessions.**
   - In the Aurora PostgreSQL cases, `WARDEN_STACK_DB_WRITER_DSN` and `WARDEN_STACK_DB_READER_DSN` are assumed to point at the alarmed cluster.
   - In the Aurora MySQL cases (08, 38), they are assumed unset. The stack's database reader is PostgreSQL-only (`_default_db`), so this shows up as a tool error.
   - In case 03, WARDEN's own writer read fails, because every connection slot is taken. This is realistic.
4. **ElastiCache node alarms produce a `STATE elasticache_node` line only.** `labels_for` gives `elasticache_node`, not the `elasticache` label the replication-group reader needs. So there are no `REPLGROUP`, `SG` or `EVENT elasticache` lines.
5. **Sibling metrics use the `Maximum` statistic.** The values were chosen with that in mind. For example, DynamoDB's `ConsumedWriteCapacityUnits` Maximum is per request, so it is small. The `ddb_consumed_*` keys carry the per-second rate instead.
6. **Lambda evidence is simulated, then read the way WARDEN reads it.** For each Lambda case the generator produces the function's invocations at a set rate, with START, app lines, END and REPORT for each. It then applies `AwsBackend.logs` (near window first, 200 events a page, 10 pages, newest 120 lines plus 30 older error lines, with its exact truncation tool errors) and the stack's lambda reader (START and END dropped). Logs Insights counts and Lambda metrics come from the same stream, so concurrency follows Little's law. A busy function therefore shows only lines from about 07:55, the start of the near window. Lambda logs avoid multi-line Python tracebacks. A traceback would make WARDEN download the deployment package and emit CODE and SOURCE lines, and I could not fake that package faithfully.
7. **AWS metric names come from my own knowledge, not live research**, because network access was not allowed. These are the newer ones:
   - `WriteKeyRangeThroughputThrottleEvents`
   - `WriteMaxOnDemandThroughputThrottleEvents`
   - `WriteProvisionedThroughputThrottleEvents`
   - `ThrottledCmds`
   - `ElastiCacheProcessingUnits`
   - `OldestReplicationSlotLag`
   - `ReplicationSlotDiskUsage`
8. **Placeholders.** `ClientId=111122223333` is AWS's documentation example account. Endpoint URLs carry a literal `<region>`.
9. **Empty reads.** `empty_reads` is set where `gather()` would set it: cases 39, 40, 41 and 42 have no metrics, and case 43 has no logs and no metrics.
10. **Judgment calls in the key.**
    - **Case 22, S3 bucket policy:** `revert_change` and `escalate_to_human` are both accepted. WARDEN's catalogue may leave resource policies to a person.
    - **Case 05, replication slot:** `escalate_to_human` is the fix and `scale_up` only buys time. Both are accepted.
    - **Case 08, MySQL metadata lock:** only `escalate_to_human` is accepted, because there is no MySQL session read to target.
    - **Multi-fault keys** list one action per fault. Any of them addresses part of the incident.
    - **`harmful_actions`** means wrong and risky, for example `clear_cache` on MemoryDB or `cancel_query` against an anti-wraparound autovacuum.
11. **Case 33's CHANGE line is classified untrusted.** WARDEN's own `_SQUASHED_STEER` filter demotes `CHANGE ... FailoverDBCluster ...` from a trusted C item to an untrusted L item, because "failover" is a steering word. That is what WARDEN would see, so it was left as is.

## Review fixes applied 2026-10-10

These fixes come from `REVIEW.md`. Ids and severities are unchanged, and `validate.py` reports 0 problems.

- **Systemic, Lambda cases 03, 07, 08, 16, 17, 21, 27, 28, 30:** log volume, time order, truncation and concurrency now come from the simulation and reader emulation described in assumption 6.
  - Each case now carries the reader's own `[output truncated]` tool errors: "stopped after 10 pages" and "kept the newest 120 lines".
  - Every LOG line is in time order.
  - Invocations, errors, Insights counts, max duration and concurrency all derive from the same stream, so Little's law holds.
  - REPORT lines have no trailing tab.
- **Systemic, CHANGE lines:** Lambda CHANGE triples are newest-first, as CloudTrail returns them (UpdateAlias, then PublishVersion, then UpdateFunctionCode).
- **Systemic, deploy times:** each deploy's `at` is 2 s before its PublishVersion (cases 03, 07, 16, 21, 27, 30).
- **28 (HIGH):** recs-api is now un-aliased (`alias_live=-`), so it runs `$LATEST`. The 07:33 UpdateFunctionConfiguration really is the live 3 s timeout, and `revert_change` stands. `alias_live=-` was added to the cause_evidence.
- **03:** the cause is reworded to a 20-connection pool per container times concurrency, plus idle warm containers. The cause_evidence now uses `POOL_SIZE=20` instead of the "db pool" lines.
- **04:** the xmin holder now ran `UPDATE ledger_entries ...`, so it holds an xid. MaximumUsedTransactionIDs is lowered to 1.118e9, and the cause_evidence follows.
- **07:**
  - Two parallel-worker lines were added (pids 40213 and 40214), and `long_running_queries` is now 3.
  - The cause now says 3 of 4 vCPUs.
  - The query text is built from a full query and cut by the same `left(query, 120)` the reader applies.
- **08:** the cause is reworded to what the evidence supports (lock waits on orders, blocker unreadable), and the README novel entry is renamed to match.
- **16:** `FEED_SOURCE` is now shown as a name only, as `_env_items` prints it.
- **27, 30:** `scale_up` is now accepted, as in case 11. The summaries no longer name the faults ("... errors, metric math").
- **31:** `cpusurpluscreditbalance` is now 1150. The cause now says a 2-vCPU class in Unlimited mode, not credit throttling.
- **36:** `alarm_sibling_es_nodes` is now 12 (old and new data nodes plus dedicated masters during blue/green).
- **Small inconsistencies:**
  - **02:** connections-held counts are now 221 idle, 126 and 110 active.
  - **15:** the cause says ~9k keys per minute, and BytesUsedForCache is 1.05e10.
  - **17:** `AvailabilityMode=multiaz`, and the log error count is simulated.
  - **22:** `alarm_4xxerrors` is now 58000.
  - **24:** the summary now says 1 GB.
  - **26:** DB load is now 7.4 with lock at 0.6.
  - **33:** the failover moved to 07:56.
  - **35:** the replicationlag sibling on the primary was removed.
  - **39, 41:** AccessDenied texts now use AWS's full form with a neutral session name (`inc-0001`).
  - **42:** the error is now `InternalServiceError`.
- **Harmful lists:** inapplicable or harmless actions were dropped.
  - `clear_cache` on S3 or RDS: 01, 22, 25, 31.
  - `failover_replica` on DynamoDB, EFS, OpenSearch, Redshift, serverless cache and single-AZ RDS: 11-14, 18, 19, 20, 24, 27, 30, 31, 41.
  - `revert_change` of tag writes: 01, 10, 35.
  - `scale_down` on on-demand tables: 12, 14. Case 14 now has an empty harmful list.
- **Coordinator rule:** cause_evidence is checked against `evidence.index` item texts. Cases 38-43 now quote the reduced tool-error form, for example `logs alarm metrics: throttled on GetMetricData` and `logs efs: timed out`.

**Not applied:**
- **Reworded "lowered" causes in 06, 11, 14, 29, 31.** These are key prose only, the keys already accept the capacity action, and scoring is unaffected.
- **`scale_up` for 14 and 18.** The coordinator listed only 27 and 30. In ACTION_MEANINGS, `raise_limit` covers a request throttle such as a max on-demand throughput or an ECPU/s limit.
- **Replacing near-duplicate or trivial cases (06/29, 21/30, 10/11, 25, 34, 37).** That would change the case set; it is out of this pass's scope.
- **Making `cancel_query` the only answer for 07.** Terminating the runaway query's session also stops it, so `terminate_connections` is kept.
