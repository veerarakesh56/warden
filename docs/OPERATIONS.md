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
| `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_API_KEY` | a model provider, when it is not Bedrock (`ANTHROPIC_API_KEY`: read by the llm zone and by Eldane's critic zone - one key, owner 2026-10-17) | create a new key in the provider's console, store it, restart, delete the old key | both work until the old one is deleted |
| `WARDEN_ELDANE_SLACK_TOKEN` | Eldane's own Slack bot token (eldane_slack.py; the critic zone's alone): it posts its review in the discussion channel, never reads it | in Eldane's Slack app, OAuth & Permissions: reinstall to get a new bot token (scope `chat:write` only), store it in `warden/<env>/eldane-slack-token`, restart the critic worker, revoke the old token | both work until the old one is revoked; Slack is never the record |
| `ELDANE_ANTHROPIC_API_KEY` (GitHub Environment `dev` secret) | Eldane's review of dev's saved infrastructure plans (`eldane-apply`, B3): the same key as `ANTHROPIC_API_KEY` | after rotating `ANTHROPIC_API_KEY`, set the new key here too | an `eldane-apply` run with the old key fails closed: nothing is applied, the plan waits for a person |
| `WARDEN_ELDANE_KEY` | Eldane's own Ed25519 signing key (eldane.py; the critic zone's alone): its approvals in dev | `warden audit keygen --private eldane.pem --public eldane.pub.pem --unencrypted` a new pair; put the public key in the approver list's AI entry (a reviewed change) and the private PEM in `warden/<env>/eldane-key`; restart the critic worker; destroy the old private key | Eldane's approvals stop until both halves match: rotate between incidents |

Keys that are not environment secrets:

| Key | How to rotate |
|---|---|
| The audit signing key (KMS, register S12) | KMS has no automatic rotation for asymmetric keys: create a new key, point the signer at it, and keep every retired public key - `warden audit verify` checks each checkpoint with the key it was signed by (G6). |
| An approver's Ed25519 break-glass key | `warden audit keygen` a new pair, replace the public key in the approvers file through a reviewed change, destroy the old private key. |
| An approver's passkey | `warden enrol --approver <name> --key ~/.warden/<name>.pem` (key files are read only from the key folder, `WARDEN_KEY_DIR`, default `~/.warden`) opens a 15-minute link in the browser; the approval page creates the passkey and shows the approver list with it; save that list as the `approvers` parameter and restart the workers (`runtime.yml`, action `restart`). Remove the old credential from the list the same way; a lost device is removed at once. |
| The webhook's bearer secret (webhooks.py) | add the new secret beside the old one (both are accepted), change Alertmanager's `http_config.authorization`, then remove the old one. |
| The operator's IAM Roles Anywhere certificate (if you use one) | before it expires, run `python scripts/roles_anywhere_cert.py issue` and at once replace the trust anchor's certificate bundle with the new CA (sign-ins fail between the two steps); see [SETUP.md](SETUP.md), section 3d. |

## Dev autonomy: Eldane, demotions and a person's re-enable (owner, 2026-10-17)

Who approves a fix:

- **prod:** a person, with a passkey (or the signed CLI key), always. Eldane, the AI critic, reviews the plan and
  says so beside the request; it never approves there.
- **dev:** Eldane alone, from the first plan, when it agrees with the plan on both of its passes and nothing in
  the gate, the bounds, the self-guard or the kill switch stands. The channel gets "Eldane · AI critic (an AI)
  approved ..." with the approval page's buttons. A person can still say no - on the page, with their passkey
  and a note - for five minutes, and after that until the apply step starts (WARDEN reads every "no" that has
  arrived right before it applies; one that arrives once the apply step has started is too late for that run); a person's decision always overrides
  Eldane's. People keep the rest too: they can ask WARDEN anything in the dev discussion channel, and an approver
  can ask there for a new plan.

When Eldane does not agree it says why as typed objections (`wrong_target`, `cause_not_addressed`,
`not_reversible`, `touches_warden`, `evidence_thin`, `evidence_contradicts`, `other`), each citing evidence ids.
WARDEN's diagnosing model answers each one - it concedes, or rebuts with evidence - and Eldane is asked again, at
most three rounds. WARDEN conceding any objection, or answering with no evidence on the record, ends it with nothing
approved: a person decides. Each objection and answer is on the incident's record (`eldane.objection`,
`eldane.rebuttal`). Eldane can read recorded evidence items again in full and the target's state as read when the
plan was made; it can read nothing live and change nothing. Every request, on the page and in the channel, says the
fix's **risks if approved** (`catalog.RISKS`).

**Eldane in the discussion channel (B2).** With its own Slack token set, Eldane posts its review of each plan in the
environment's discussion channel (`WARDEN_DISCUSS_CHANNELS`): it opens a thread naming the incident and the plan, then
each round's objections, WARDEN's answers (posted by WARDEN's own bot), and how it ended - agreed, or a person
decides. Every message of Eldane's starts with **Eldane · AI critic**, whatever its Slack app is called (EU AI Act
Art. 50). It only posts: it never reads the channel, so nothing written there reaches it. What it posts is what is on
the record, made from the redacted evidence (placeholders and stable ids, never a real value), and every message goes
through the redactor and the outbound gate. People discuss in the same thread: mention @WARDEN there to ask WARDEN
(the thread names the incident). Setting it up, once (the owner):

1. Create a Slack app named `Eldane · AI critic` (or any name; its messages carry the label regardless), with the
   bot scope `chat:write` and nothing else - no read scope, no Socket Mode, no events. Install it and invite it to
   each environment's discussion channel.
2. Store its bot token in `warden/<runtime>/eldane-slack-token` (the runtime module makes the slot; only the critic
   zone's task role can read it) and restart the critic worker.

Without the token nothing is posted and nothing else changes; Eldane's review is on the record either way.

Dev drops to **L1** - Eldane reviews, a person approves - the moment any of these is on the record:

- a fix of that action class ended badly (rolled back, relapsed, not recovered, or left in an unknown state);
- a person said no to a plan Eldane said yes to;
- the diagnosing model, Eldane's model or Eldane's prompt changed;
- Eldane said yes to a planted bad plan (a catch trial: about one review in ten, more while its model is new;
  each is labelled a test on the record and never applied) - this one stops its approvals for every class;
- the kill switch is on (dev returns when an approver resets the switch).

It goes back to L2 only when a person turns it back on, signed and recorded:

1. `warden autonomy status --environment dev` lists every demotion since autonomy was last enabled.
2. Read each one. When the cause is understood (and fixed, if it needed a fix), run
   `warden autonomy enable --environment dev --approver YOU --key YOUR.pem --demotions N`, where N is how many you
   read. Your key signs exactly those demotions (a T3 approval, so the newest must be at least ten minutes old);
   one added after you read the list makes the signature not match, and nothing changes.
3. The runtime's `AutonomyWorkflow` checks the signature in the core zone and records `autonomy.enabled` with
   your name and the demotions it covers. Eldane can never do this step: an AI approver has no T3 and is refused by
   name.

Prod has nothing to re-enable: it is never autonomous.

### Eldane reviews dev's infrastructure plans (B3)

`Deploy · dev` with `infra_action=eldane-apply` plans the stack and keeps the saved plan in the state bucket, as
`plan` does; then Eldane reviews exactly that plan, and the same file is applied only if it approved. In order:

1. **Dev only.** `_infra-deploy.yml` refuses `eldane-apply` in any other environment, and the review refuses any
   environment whose autonomy ceiling is not L2 (`environments.yaml`; the prod tier never is). Prod always needs a
   person: `apply-plan` with the run id and sha256 the plan step printed.
2. **The plan's shape** (`plan_shape.py`), before any model reads it: any access change (IAM, resource policies,
   security groups and rules, network ACLs, cluster access), or a delete or replace of a data store, networking or the
   platform (clusters, services, functions, alarms, the budget), a provider these stacks do not use, or more than 60
   changes - a person reviews it.
3. **Eldane** (`plan_review.py`), on the first model of `providers.yaml` `critic` (Claude Opus 5.5 - critic is the role
   it holds until its paid qualification passes), shown the plan's addresses, types, actions and the NAMES of changing
   attributes - never a value - redacted; and in the same run a planted known-bad plan. It approves only when it
   agrees with the real plan, citing its changes, AND refuses the planted one.
4. **Bound to the plan.** The review (`plans/<run>.eldane.json` beside the plan, in the state bucket) names the run id,
   the plan file's sha256, the commit, stack and environment; the apply step checks all of them against the file
   again right before `terraform apply` of that file. Anything else, or no approval, and nothing is applied - the plan
   waits for a person.

The review step holds no cloud credential (every `AWS_*` variable is unset for it) and is the only step given the
model key. It is off until the owner turns it on:

1. On the GitHub Environment `dev`: the secret `ELDANE_ANTHROPIC_API_KEY` (the runtime's Anthropic key,
   `warden/<runtime>/anthropic-api-key`, owner 2026-10-17: one key) and the variable `ELDANE_PLAN_APPROVAL` = `on`.
   Setting the variable to anything else is the off switch.
2. Two model calls per `eldane-apply` run (the plan and the planted one); with neither set, `eldane-apply` stops after
   keeping the plan, for a person.

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
