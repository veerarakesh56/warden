# Operating WARDEN

## Secret and key rotation (register S4)

Every secret WARDEN loads is a Secrets Manager secret named `warden/<environment>/<name>` (settings.py; decision D5),
read when a process starts: after a rotation, restart the workers (or let the deployment roll them) and the new value
is in use. `tests/test_operations_rotation.py` fails if a secret WARDEN can load has no row here.

WARDEN's own cloud runtime has a slot only for the secrets one of its zones or Lambdas reads (settings.ZONE_SECRETS and
LAMBDA_SECRETS, terraform/modules/warden-runtime/secrets.tf; secrets audit, 2026-10-16). A rotation's `_PREVIOUS`
secret, the Alertmanager webhook's token, PagerDuty, Teams, another model's key and the terminate role's DSN have none
there: before using one, add it to the zone or Lambda that reads it, to secrets.tf and to iam.tf, and apply.

| Secret or key | What it unlocks | How to rotate | Overlap |
|---|---|---|---|
| `WARDEN_TEMPORAL_KEY` | decrypts every Temporal payload (codec.py) | create 32 random bytes; set it as the new `WARDEN_TEMPORAL_KEY` and move the old one into `WARDEN_TEMPORAL_KEY_PREVIOUS`; restart workers and clients | old key stays in `WARDEN_TEMPORAL_KEY_PREVIOUS` until no running workflow was started before the rotation (at most the approval TTL plus the verify window, about 7 hours); then remove it |
| `WARDEN_TEMPORAL_KEY_PREVIOUS` | decrypts payloads written before the last rotation | emptied when its keys are no longer needed (above) | - |
| `WARDEN_ALERTMANAGER_TOKEN` | the bearer secret Alertmanager sends to the webhook (register S5) | create a new random secret; move the current one into `WARDEN_ALERTMANAGER_TOKEN_PREVIOUS`, set the new one, then change Alertmanager's `http_config.authorization` to it | both are accepted until Alertmanager sends the new one; then empty `WARDEN_ALERTMANAGER_TOKEN_PREVIOUS` |
| `WARDEN_SLACK_CLIENT_SECRET` | the approval page's Sign in with Slack (slack_login.py): it exchanges Slack's sign-in code for who signed in | in the Slack app's Basic Information, regenerate the client secret; store the new value in the secret; nothing to restart - the approval Lambda reads it on each start | none: a sign-in in progress fails once and is started again |
| `WARDEN_PAGERDUTY_ROUTING_KEY` | pages the on-call through PagerDuty's Events API v2 (decision D13) | create a new integration key on the PagerDuty service, store it, restart the workers, then delete the old integration | none: an alert's deduplication key is the incident, not the routing key |
| `WARDEN_ALERTMANAGER_TOKEN_PREVIOUS` | the webhook secret before the last rotation, accepted meanwhile | emptied once Alertmanager uses the new one (above) | - |
| `WARDEN_TEMPORAL_API_KEY` | the worker's Temporal Cloud service account | create a second API key for the same service account in Temporal Cloud, store it, restart, then delete the old key; set an expiry on every key | both keys valid until the old one is deleted |
| `WARDEN_AUDIT_DSN` | the runtime's connection to the shared audit (Aurora PostgreSQL) | rotate the audit writer's password with Secrets Manager's managed rotation for the database, then restart the workers so they reconnect | none needed: the audit rows do not change |
| `WARDEN_AUDIT_KEY_PASSPHRASE` | the local audit signing key's encryption | re-encrypt the key file under a new passphrase, store the new passphrase | none needed: the key itself does not change |
| `WARDEN_SLACK_BOT_TOKEN` | posting into the incident channel | regenerate the bot token in the Slack app's settings, store it, restart | the old token stops at once: rotate in a quiet hour |
| `WARDEN_DATADOG_API_KEY`, `WARDEN_DATADOG_APP_KEY` | reading logs, spans and metrics from Datadog (datadog.py; the read zone's alone; the application key scoped to `logs_read_data`, `logs_read_index_data`, `apm_read`, `timeseries_query`, `events_read`, `monitors_read`) | run `scripts/observability_setup.py` again: it makes a new scoped key, stores it and deletes the older one; then restart the read workers (runtime.yml restart) | the old key stops when it is deleted: rotate between incidents |
| `WARDEN_DATADOG_WEBHOOK_TOKEN` | Datadog monitors' webhook into WARDEN (`POST /datadog`; the webhook Lambda's alone) | run `scripts/datadog_setup.py` again: it makes a new token, stores it and puts it in the webhook's header in one step | none: rotate between alerts |
| `WARDEN_SLACK_APP_TOKEN` | the discussion channel's Socket Mode connection (discuss.py; the notify zone's alone) | in the Slack app's Basic Information, App-Level Tokens: generate a new token with `connections:write`, store it, restart the notify workers, then revoke the old token | both work until the old one is revoked |
| `WARDEN_SLACK_WEBHOOK`, `WARDEN_TEAMS_WEBHOOK`, `WARDEN_WEBHOOK_URL` | posting through an incoming webhook | create a new webhook, store it, restart, delete the old one | both work until the old one is deleted |
| `WARDEN_GITHUB_TOKEN` | opening change-record issues in one repository | create a new fine-grained token limited to issues on that repository, with an expiry; store it, restart, revoke the old one | both work until the old one is revoked |
| `WARDEN_DB_DSN`, `WARDEN_DB_TERMINATE_DSN`, `WARDEN_STACK_DB_PRIMARY_RO_DSN`, `WARDEN_STACK_DB_REPLICA_RO_DSN` | the database readers and the narrow terminate role (renamed 2026-10-16 from `WARDEN_DB_ADMIN_DSN`, `WARDEN_STACK_DB_WRITER_DSN` and `WARDEN_STACK_DB_READER_DSN`, which are still read for one release with a warning; the Secrets Manager slots keep the old names `db-admin-dsn`, `stack-db-writer-dsn` and `stack-db-reader-dsn` until the runtime module renames them) | change the role's password (or let RDS rotate the managed secret), store the new DSN, restart | a database role has one password: rotate, then restart promptly |
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY` | a model provider, when it is not Bedrock | create a new key in the provider's console, store it, restart, delete the old key | both work until the old one is deleted |

Keys that are not environment secrets:

| Key | How to rotate |
|---|---|
| The audit signing key (KMS, register S12) | KMS has no automatic rotation for asymmetric keys: create a new key, point the signer at it, and keep every retired public key - `warden audit verify` checks each checkpoint with the key it was signed by (G6). |
| An approver's Ed25519 break-glass key | `warden audit keygen` a new pair, replace the public key in the approvers file through a reviewed change, destroy the old private key. |
| An approver's passkey | `warden enrol --approver <name> --key ~/.warden/<name>.pem` (key files are read only from the key folder, `WARDEN_KEY_DIR`, default `~/.warden`) opens a 15-minute link in the browser; the approval page creates the passkey and shows the approver list with it; save that list as the `approvers` parameter and restart the workers (`runtime.yml`, action `restart`). Remove the old credential from the list the same way; a lost device is removed at once. |
| The webhook's bearer secret (webhooks.py) | add the new secret beside the old one (both are accepted), change Alertmanager's `http_config.authorization`, then remove the old one. |
| The operator's IAM Roles Anywhere certificate (if you use one) | before it expires, run `python scripts/roles_anywhere_cert.py issue` and at once replace the trust anchor's certificate bundle with the new CA (sign-ins fail between the two steps); see [SETUP.md](SETUP.md), section 3d. |

## WARDEN's records (registers G10-46, G10-47)

Every incident WARDEN has handled is at `https://<the approval domain>/r` - no time limit (the record is
append-only), newest first, under its day, 50 a page by default (10, 25, 50 or 100; newest, newer, older and oldest
links; filters for environment, status, service, a day range and title text): its summary and status in the list, its details unfolding
beneath it, and a page of its own (the message's "Full record" button) with who approved or denied it and their note,
anything that tried to steer WARDEN, the complete findings section by section, the evidence the model was shown and
every step, in UTC and local time.
A reader whose approver entries are all limited to some environments sees only those environments' incidents.
Sign in with Slack; it opens for the approvers and for the Slack members in the plain setting
`/warden/<env>/env/WARDEN_RECORD_VIEWERS` (comma-separated member ids). Slack gets one message per incident; approved,
denied and fixed are on the record, not posted.

## Pause and resume to save money (owner update 5, 2026-10-17)

Between uses, pause instead of destroy: every data store is copied first, and resume brings it back from the newest
copy. On a first install there is no copy, and resume simply builds everything empty, as apply does.

**From the pipelines (one run each):**

| What | Run | Keeps | Stops paying for |
|---|---|---|---|
| The full stack (dev) | Actions → *Deploy · dev* → `part: infra`, `infra_action: pause` | Aurora as a cluster snapshot, each DynamoDB table as an on-demand backup, named `<name>-pause-<UTC time>` | everything else: the whole stack is destroyed after the copies are available |
| | `infra_action: resume` | restores the tables (and imports them into Terraform's state) before the apply, Aurora from its newest pause snapshot after it, then redeploys the Lambdas, ECS and the cluster's add-ons (Argo CD, the Datadog agent, the shop) in the same run, waiting until each is healthy | |
| WARDEN's runtime (ops) | Actions → *Runtime · ops* → `action: pause` | the audit database (a snapshot, then STOPPED, not deleted), its keys, the secrets, the witness | the workers, the NAT, the alarm intake; the self-alarms' actions are off, so a planned pause pages nobody |
| | `action: resume` | starts the audit database, then applies, migrates and checks every zone as `apply` does | |

What each step guarantees: nothing is deleted or stopped until every copy is **available** (the step fails
otherwise, and no later step runs). Resume takes the newest available `-pause-` copy by the time AWS made it, so the
copies made by hand on 2026-10-17 (`warden-dev-aurora-pause-20261017`, `warden-dev-carts-pause-20261017`,
`warden-ops-audit-pause-20261017`, a date only) are found too. An existing database or table is never overwritten.
If the audit database is gone while a pause snapshot of it exists, resume refuses rather than let Terraform create
an empty audit: restore it by hand (below). Nothing deletes a copy: the run's summary lists the newest
`PAUSE_KEEP_SNAPSHOTS` per data store (a repository variable, default 3) and the older ones for a person to delete.

**Cost while paused** (AWS Price List API for the region, read 2026-10-17; Billing is the ground truth):
Aurora snapshot storage USD 0.023 per GB-month, an RDS (Free plan audit) snapshot USD 0.095, a DynamoDB on-demand
backup USD 0.114; a stopped RDS instance still bills its storage (20 GB gp3 at USD 0.131 per GB-month, about USD
0.09 a day); each secret USD 0.40 a month and each customer-managed KMS key USD 1 a month stay. For this lab's sizes
that is cents a day; the pause run prints its own estimate.

**How long resume takes:** not measured yet; expect most of an hour - the EKS cluster and the Aurora restore are the
slow parts, then the apps redeploy. The first live resume will give the number.

⛔ **AWS starts a stopped RDS database again by itself after 7 days** (StopDBInstance / StopDBCluster), and it bills
from then. Pause the runtime again before the seventh day, or start it on purpose.

**By hand (console and CLI), e.g. when the pipelines cannot run.** `$T` is the UTC time, `T=$(date -u +%Y%m%dt%H%M%Sz)`.

- Aurora snapshot - console: RDS → Databases → `warden-dev-aurora` → Actions → Take snapshot, name
  `warden-dev-aurora-pause-$T`. CLI: `aws rds create-db-cluster-snapshot --db-cluster-identifier warden-dev-aurora
  --db-cluster-snapshot-identifier warden-dev-aurora-pause-$T --tags Key=Project,Value=warden Key=Environment,Value=dev`,
  then `aws rds wait db-cluster-snapshot-available --db-cluster-snapshot-identifier warden-dev-aurora-pause-$T`.
- DynamoDB backup - console: DynamoDB → Tables → `warden-dev-carts` → Backups → Create backup → Create on-demand
  backup, name `warden-dev-carts-pause-$T`. CLI: `aws dynamodb create-backup --table-name warden-dev-carts
  --backup-name warden-dev-carts-pause-$T` (wait until `aws dynamodb describe-backup --backup-arn <arn>` says
  `AVAILABLE`).
- Audit snapshot and stop - console: RDS → Databases → `warden-ops-audit` → Actions → Take snapshot
  (`warden-ops-audit-pause-$T`), then Actions → Stop temporarily. CLI: `aws rds create-db-snapshot
  --db-instance-identifier warden-ops-audit --db-snapshot-identifier warden-ops-audit-pause-$T`, `aws rds wait
  db-snapshot-available --db-snapshot-identifier warden-ops-audit-pause-$T`, `aws rds stop-db-instance
  --db-instance-identifier warden-ops-audit` (an Aurora audit: `create-db-cluster-snapshot` / `stop-db-cluster`).
- The runtime's switch - console: Systems Manager → Parameter Store → `/warden/ops/tf/paused` → Edit → `true` (or
  `false`). CLI: `aws ssm put-parameter --name /warden/ops/tf/paused --value true --overwrite`; then *Runtime · ops*
  `apply`.
- Start the audit again - console: Actions → Start. CLI: `aws rds start-db-instance --db-instance-identifier
  warden-ops-audit` and `aws rds wait db-instance-available --db-instance-identifier warden-ops-audit`.
- Restore a lost audit database (resume refuses to do it): console: RDS → Snapshots → the newest
  `warden-ops-audit-pause-...` → Actions → Restore snapshot, identifier `warden-ops-audit`, the audit's subnet group and
  security group. CLI: `aws rds restore-db-instance-from-db-snapshot --db-instance-identifier warden-ops-audit
  --db-snapshot-identifier <snapshot> --db-subnet-group-name <the audit's> --vpc-security-group-ids <the audit's>
  --no-publicly-accessible`. Then adopt it into Terraform's state:
  `terraform -chdir=terraform/runtime import 'module.runtime.aws_db_instance.audit[0]' warden-ops-audit` (an Aurora
  audit: `restore-db-cluster-from-snapshot` and `module.runtime.aws_rds_cluster.audit[0]`), and run `apply`.
- Delete an old copy (never automatic; the environment's own roles may not): with the operator's credentials,
  `aws rds delete-db-cluster-snapshot --db-cluster-snapshot-identifier <name>`, `aws rds delete-db-snapshot
  --db-snapshot-identifier <name>`, `aws dynamodb delete-backup --backup-arn <arn>`.

## Talking to WARDEN about an incident in Slack (register G10-45)

A second Slack channel where anyone asks WARDEN about an incident: mention `@WARDEN` with the incident's id (the one in
the footer of its messages) and a question; WARDEN answers in that thread from the incident's own evidence - read again
as the diagnosis read it, or around now when the question asks about now ("still", "again", "now") - and from what its
record says it decided. Follow-ups mention `@WARDEN` in the same thread. Anyone may ask; WARDEN changes nothing from
this channel, and says who may ask for a new plan (an enrolled approver; the plan still needs their passkey in the alerts
channel). Its answers are capped at 20 per incident a day and count toward the daily model cap every incident shares.

Setup, once, in the Slack app WARDEN signs people in with (api.slack.com/apps):

1. **Socket Mode**: on. WARDEN connects out to Slack; it needs no new public address.
2. **Basic Information, App-Level Tokens**: generate a token with the scope `connections:write`.
3. **OAuth & Permissions, Bot Token Scopes**: `app_mentions:read`, `chat:write`, `channels:history`; for a private
   channel also `groups:history`. Nothing else is needed.
4. **Event Subscriptions**: on; the bot event `app_mention` only - WARDEN reads a thread when it is mentioned in it,
   so it needs no other channel message pushed to it. Save, then reinstall the app and copy its Bot User OAuth Token.
5. In every channel WARDEN uses - each environment's alerts channel and its discussion channel:
   `/invite @<the app's name>`; copy the channel's ID (its name, then About).
6. Store the app-level token in the secret `warden/<runtime>/slack-app-token` and the bot token in
   `warden/<runtime>/slack-bot-token` (`<runtime>` is WARDEN's own environment, `ops`).
7. Put each environment's channels in two plain settings, `env=channel-id` pairs separated by commas:
   `/warden/<runtime>/env/WARDEN_SLACK_CHANNELS` (alerts, e.g. `dev=C...,prod=C...`) and
   `/warden/<runtime>/env/WARDEN_DISCUSS_CHANNELS` (discussion). Restart the notify workers.

Each environment's incidents go only to its own channels (owner, 2026-10-16). With `WARDEN_SLACK_CHANNELS` set, the
alerts go through the bot to the incident's environment's channel, and the Slack webhook is not used; an environment
the map does not name gets no Slack message at all - never another environment's channel - and its record has a
`chatops.withheld` row saying so. PagerDuty, Teams and the generic webhook are not routed by it. A discussion channel
answers only about its own environment's incidents, and the incidents "like this one" it shows are that environment's
only. A map that names an environment not in environments.yaml, gives a channel id of the wrong shape, names an
environment twice or gives two environments one channel stops the worker at start with the reason.

Without the maps, as before: the webhook (`warden/<runtime>/slack-webhook`) for the alerts, or the bot in the one
`WARDEN_SLACK_CHANNEL` when that is set, and the one discussion channel `WARDEN_DISCUSS_CHANNEL` for every environment.

The notify worker holds the connection; if it cannot connect it says so in its log and goes on sending alerts.

## Expected down: nights, weekends, holidays, not in use (register G10-39)

An alarm on something switched off on purpose is not an incident. Say what is expected down in the plain setting
`WARDEN_EXPECTED_DOWN` (Parameter Store, `/warden/<env>/env/WARDEN_EXPECTED_DOWN`, a YAML list; the intake reads it
on its next start, no deploy):

```yaml
- name: dev nights
  environments: [dev]
  zone: Asia/Kolkata
  hours: "20:00-08:00"
- name: dev weekends
  environments: [dev]
  zone: Asia/Kolkata
  days: [sat, sun]
- name: reports service parked
  services: [reports]
  zone: Asia/Kolkata
  until: "2026-11-01T09:00"
- name: old search cluster, not in use
  resources: [search-v1]
```

WHAT: `environments`, `services`, `resources` - every one given must match the alarm. WHEN: `hours`, `days`,
`dates`, `from`, `until`, in the declaration's `zone` - every one given must hold; none means until the declaration
is removed. A covered alarm starts no incident and is recorded (`intake.decision`, action `expected`). When the
cover ends WARDEN looks at the alarm again: still firing, it is an incident from that moment. A declaration that
cannot be read covers nothing and is said in the intake's log: a typing mistake brings alarms back, it never hides
one. A person who asks for a diagnosis (CLI, MCP) always gets one.

## Optional: Claude's security review on pull requests

`.github/workflows/security-review.yml` runs Anthropic's Claude Code security review
(`anthropics/claude-code-security-review`, MIT, pinned by its commit) on a pull request into `main` and comments its
findings on the pull request. It is **off by default**: it calls the Claude API on your key, so it costs money per pull
request. It is advisory - it is not a required check, and CodeRabbit, SonarCloud and CodeQL stay the gates.

To turn it on (once, in the repository's Settings):

1. Create an Anthropic API key for this alone, in its own workspace with a monthly spend limit (Claude Console,
   Workspaces and Limits) - not WARDEN's runtime key. Store it as the Actions secret
   `SECURITY_REVIEW_ANTHROPIC_API_KEY` (Settings, Secrets and variables, Actions, Secrets).
2. Set the Actions variable `WARDEN_SECURITY_REVIEW` to `on` (same page, Variables). Any other value, or none, turns
   it off. Optionally set `WARDEN_SECURITY_REVIEW_MODEL` to `claude-sonnet-5-5` for a cheaper review; the default is
   `claude-opus-5-5`.
3. Keep Settings, Actions, General, "Fork pull request workflows from outside collaborators" at **Require approval for
   all external contributors**. The action is not hardened against prompt injection (its README): it runs only on
   pull requests from this repository's own branches, never on a fork's code with the key.

What it costs: Claude API tokens only (Actions minutes are free on a public repository). It reviews a pull request
once; later pushes to the same pull request are skipped unless it is run again. Claude Code reads the change and the
code around it, then a second, smaller call filters false positives. At Claude Opus 5.5's list price ($4 per million
input tokens, $20 per million output, read 2026-10-17) an estimated $1 to $3 per pull request for a change of a few
hundred lines, about half that with Claude Sonnet 5.5 ($2 / $10) - an estimate, not measured here: read the real
figure in the Claude Console's usage page after the first runs, and let the workspace's spend limit cap it. To turn
it off, set `WARDEN_SECURITY_REVIEW` to anything but `on`, or delete it.

Known limit, not verified here: the action's false-positive filter checks its API access with a fixed older model
(`claude-3-5-haiku-20241022` in its code). If that model is retired, the filter step may fail and its findings may
arrive unfiltered; read the first run's log.
