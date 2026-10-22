# What leaves WARDEN's network, and how to check it

The owner's goal (2026-10-20): sensitive data never leaves the network; every egress is recorded, and security,
network and operations engineers can check that it is safe; AI agents never see or reach the masked values; people
with access can reveal them through an audited path.

How far `main` meets it, in short (details below):
- detected values are masked before anything is built for a model, a chat message, a ticket or a log. One opt-in
  exception: with `WARDEN_REPORT_SHOW_IDENTIFIERS=true`, chat messages show emails, tenant ids and IP addresses again
  (never secrets, never to a model);
- every model call and every urllib request to a destination outside the network is checked and recorded on the
  egress ledger (`egress.py`); other clients (boto3, the tracing exporter, Slack's async client) are held to the
  listed hosts by name and connection, not by content (limits below);
- the personal values behind the placeholders are sealed with a key no AI zone can use (`vault.py`), and only an
  approver can reveal one, on the records page, recorded on the signed audit first (`reveal.py`).

This page is for those engineers. It covers every destination, what goes there and what is masked; the guards and
the ledger; the sealed vault and the reveal; and what the model provider does with what it receives.

> **Status, checked against `main` at `4f01b40` (#115, `vault.py`, merged) with PR #119 (`reveal.py`) merged in, on
> 2026-10-22 (01:48 UTC / 07:18 IST).** This page merges after #119, so it describes `main` as #119 leaves it.
> Each statement is what that code does, or is marked **pending PR #n**: code under review, not merged, not
> running anywhere. The open PRs this page still relies on:
>
> | PR | Adds |
> |---|---|
> | [#147](https://github.com/veerarakesh56/warden/pull/147) | `warden records list` and `warden records show`, a read-only CLI over the audit |
> | [#83](https://github.com/veerarakesh56/warden/pull/83) | the AWS updates watch (AWS's news feeds) |
> | [#130](https://github.com/veerarakesh56/warden/pull/130) | end-to-end privacy tests over the bundled incidents |
> | [#91](https://github.com/veerarakesh56/warden/pull/91) | the audit, its anchors and backups kept at least 180 days |
>
> When one merges, its "pending" marks here are removed in the same or the next PR.

## What is never sent out

Everything the redactor's patterns find (`src/warden/redaction.py`) is replaced by a placeholder (`<EMAIL_1>`) before
any text is built for a model, a chat message, a ticket or a log line:

- personal data: email addresses, phone numbers, IPv4/IPv6/MAC addresses, tenant, organisation, customer, account and
  user ids (`tenant_id=...`), internal host names (names under `.corp`, `.lan`, `.intranet`, `.internal`, `.local`,
  `home.arpa`, keeping a Kubernetes `.cluster.local` name and AWS's `compute.internal`/`ec2.internal`), street
  addresses, and personal names where a pattern can see one (after a name field's key, a title or a greeting);
- national ids: US SSNs, Indian Aadhaar and PAN numbers;
- financial numbers: IBANs, payment card numbers;
- credentials: private keys, JWTs, API keys and tokens, cloud tokens (GCP, Azure SAS), webhook URLs, passwords in
  URLs and connection strings, `Bearer` and `Basic` credentials, cookies, credential flags and fields, and long
  high-entropy strings;
- cloud account ids, ARNs and UUIDs.

`tests/test_redaction_classes.py` holds a corpus for every class.

Honest limits:
- A value that **no pattern recognises** is not masked. Detection is pattern-based, never a model judging what is
  personal ([ARCHITECTURE.md, the safety layers](ARCHITECTURE.md#the-safety-layers)).
- A personal name in free prose with no marker (`priya nair restarted the pod`) is **not** found.
- **Chat can show identifiers on purpose.** With `WARDEN_REPORT_SHOW_IDENTIFIERS=true`, the chat message (Slack,
  Teams, a webhook) puts emails, tenant ids and IP addresses back in for the people reading it
  (`reporting.REVEALABLE`, `chatops.notify`); secrets are never put back. It is off by default and the cloud runtime
  does not set it. It never reaches a model: prompts are built before and apart from it.

## What comes in, and is masked first

Every source WARDEN reads is untrusted text, redacted as one text with the rest of the incident before anything is
built from it (`graph.node_redact`, run inside the read zone's `activities.prepare`):

- CloudWatch alarms and logs, CloudTrail, the AWS service APIs;
- Datadog (and Grafana for adopters);
- Kubernetes;
- the watched databases;
- Alertmanager and Datadog webhooks;
- AWS Health and service events;
- code review findings on a recent deploy's pull requests (GitHub, SonarCloud, CodeRabbit - `findings.py`);
- GuardDuty and Security Hub findings (`security_findings.py`).

A security finding's own words and its resource's details (addresses, keys, instance and account ids, ARNs) are
redacted in the alert's summary before it is recorded or told, and every finding is escalate-only: no plan is opened.
`tests/test_security_intake.py` checks it.

## Every destination

"Gated" below means the outbound gate (`src/warden/gate.py`) and a second redaction of the exact payload in
`chatops.notify`: links, images and markup removed (G3), write commands withheld (G4), and a message that still holds
a secret blocked (G5). "Checked" means the egress check below (`egress.check_request` or `egress.guard_model`): the
request is refused if anything the redactor finds is still in it, and it is recorded either way.

The table is the code's inventory: `egress.STATIC` plus `egress._CONFIGURED` (hosts named by a setting), and
`tests/test_egress.py` fails when a module in `src/warden` opens a network client that is not on it.

| Destination | Hosts | What goes there | Checked how | Outside the network? |
|---|---|---|---|---|
| Anthropic (the diagnosis model, Eldane, the discussion chat) | `api.anthropic.com` | a prompt built from redacted evidence: placeholders only | redaction before the prompt is built (`node_redact`; `discuss.py` redacts a thread and question); then every prompt re-scanned strictly before it is sent (`egress.guard_model`) and refused if any value is found | yes |
| The Claude CLI (laptop only, for replay qualification) | Anthropic, through the `claude` CLI | the same redacted prompts of recorded incidents | the same | yes |
| Other model APIs (adopters only; the cloud runtime creates no key slot for them) | OpenAI, Groq, OpenRouter, Gemini, Bedrock, `WARDEN_BASE_URL` | the same | the same | yes |
| Slack | `slack.com`, `*.slack.com`, `hooks.slack.com` | the incident report, thread replies; Sign in with Slack (OAuth code exchange) | gated and checked; the OAuth exchange's own client id, secret and code are the only fields the check leaves out (`slack_login.py`) | yes |
| Microsoft Teams, a generic webhook | `*.webhook.office.com`, `WARDEN_WEBHOOK_URL` | the report | gated and checked (a webhook's secret path is left out of the scan) | yes |
| PagerDuty | `events.pagerduty.com` | a page about the report | gated and checked (its routing key left out) | yes |
| GitHub | `api.github.com` | a change record (an issue, `changes.py`); reads of recent deploys and pull requests; the infra workflow's runs and its apply-plan dispatch | the record is gated; every request checked | yes |
| SonarCloud (opt-in) | `sonarcloud.io` | reads: the issues of a pull request (`WARDEN_SONAR_PROJECT`) | GET only; checked | yes |
| Datadog | `api.<site>` | reads: a service name, a time window, fixed metric queries, a monitor id | reads only; checked | yes |
| AWS's documentation | `knowledge-mcp.global.api.aws` | an AWS error code from the typed facts and a service word from WARDEN's own table (`aws_docs.py`; the cloud read zone sets `WARDEN_AWS_DOCS=on`) | closed vocabulary; checked | yes |
| Temporal Cloud | `*.tmprl.cloud` | workflow payloads, **encrypted** with AES-256-GCM (`codec.py`); workflow ids and activity names in clear | the codec; the client is Rust, outside the Python hooks (limits) | yes |
| Tracing (opt-in) | `OTEL_EXPORTER_OTLP_ENDPOINT` | spans: node names, timings, scrubbed error text (`observability.py`) | scrubbed where written; its host held by the name check | yes |
| WARDEN's own AWS account | the AWS API names WARDEN uses (`egress.AWS_ENDPOINTS`) | reads, the approved fix, the audit, secrets, KMS - the vault's sealing and the reveal's opening included (boto3) | IAM and key policies (below); boto3's content is not scanned | no |
| The private network | non-routable addresses, `*.svc`, `*.cluster.local`, `*.internal`, `localhost` | a cluster's services, instance and task metadata, WARDEN's database | - | no |
| Datadog, from the lab's own agent | Datadog's intake | the lab shop's container and OpenTelemetry logs and spans (not WARDEN's) | masked at the agent (`helm/datadog/values.yaml`) | yes |
| AWS's news feeds | `aws.amazon.com` | a GET of the What's New and blog feeds | on the inventory; the watch that reads them is **pending PR #83** | yes |

## The guards

1. **Redaction before every prompt.** The evidence, the alert, labels, deploys and tool errors are redacted as one
   text in the read zone; the llm zone gets the built prompt, never the placeholder map (`activities.prepare`).
   Untrusted text is also turned into typed facts first (`quarantine.py`). Eldane reads only the recorded evidence
   and diagnosis rows and the plan (`eldane.READS`).
2. **The strict model guard.** Every provider class in `providers._REGISTRY` (Eldane's included) has its `complete`
   wrapped: the system and user prompts are scanned with every pattern, and a prompt holding any value is refused
   before it is sent (`egress.guard_model`). It holds in every process.
3. **The urllib hook** (a PEP 578 audit hook on `urllib.Request`): an unlisted host is refused; the body, query, path,
   user name and fragment of a request outside the network (or to an AWS name) are scanned and the request refused
   if a value is found; a compressed body, which cannot be read, is refused.
4. **The name-lookup and connection hooks** (`socket.getaddrinfo`, `gethostbyname*`, `socket.connect`): an unlisted
   host is refused before it is resolved; a connection to an IP address must be the private network's or one a
   checked lookup returned.
5. **The outbound gate** on each of these paths: chat, terminal, MCP results, generic webhooks, the change record
   (`gate.py`; `tests/test_gate.py`).
6. **The log gate** in the CLI, the MCP server, the workers and every Lambda: every log record is redacted,
   normalised, redacted again and bounded (`observability.GatedFormatter`); the Lambda runtime's own handler writes
   through the gate too (`observability.gate_handlers`), and an uncaught error reaches the runtime as its type only.
   `tests/test_log_canaries.py` sends canaries through every path.

The hooks (3, 4) are installed by every Lambda and by every `warden` command run against a real environment
(`WARDEN_ENV` set). `tests/test_egress.py` holds all of it.

## The ledger

Every model call and every urllib request to a destination outside the network or to an AWS name writes one row that
**never holds a value**:

```json
{"destination":"slack","outside":true,"purpose":"POST /api/chat.postMessage","bytes":2817,
 "sha256":"…","placeholders":{"EMAIL":2,"IPV4":1},"verdict":"PASS","kinds":[]}
```

- **CloudWatch Logs:** a line `egress {...}` from logger `warden.egress` in `/warden/<env>/worker` and
  `/aws/lambda/warden-<env>-<function>`. A refusal is a WARNING with `"verdict":"BLOCK"` and the kinds found.
- **The signed audit:** the same row as `egress.sent` or `egress.blocked`, under the incident's workflow id, where the
  process has opened the audit. If the row cannot be written, the egress is not made.
- A client other than urllib (boto3, the tracing exporter, Slack's async client) is on the ledger by its first lookup
  of each host only, not per request.

Logs Insights, on those log groups. Everything that left, by destination:

```
fields @timestamp, @message
| filter @message like /egress \{/
| parse @message '"destination":"*"' as destination
| parse @message '"verdict":"*"' as verdict
| stats count(*) by destination, verdict
```

Every refusal:

```
fields @timestamp, @logStream, @message
| filter @message like /egress/ and @message like /"verdict":"BLOCK"/
| sort @timestamp desc
```

Live Tail: the same log groups with the filter pattern `"egress"`.

Retention: the worker and Lambda log groups keep **90 days** (`terraform/modules/warden-runtime/compute.tf`,
`frontdoor.tf`). Keeping the audit at least 180 days is **pending PR #91**
([DATA-RETENTION.md](DATA-RETENTION.md)). `warden audit verify` checks the audit's hash chain and signatures.

## The masked values: sealed for people

- **Sealed where found** (`vault.py`). In the read zone's `prepare`, the placeholder map's personal values are
  encrypted with AES-256-GCM under a fresh KMS data key (encryption context `purpose=vault`, the environment, the
  incident) and stored in a `vault` table; the signed audit gets only an index (placeholder, kind, stable id) and the
  sealed bytes' SHA-256. The map never enters a workflow's history or a log. A seal that fails - KMS refusing, or
  not answering within its bounded timeout - is recorded (`incident.vault_unavailable`, its type only) and the
  incident goes on: the values stay masked, only their reveal is lost.
- **Personal data only.** Sealed: emails, phone numbers, tenant and account ids, ARNs, UUIDs, IP and MAC addresses,
  internal host names, personal names and street addresses. Never kept, thrown away after masking as before: every
  credential and token, IBANs, card numbers and national ids (SSN, Aadhaar, PAN). Every redaction class is in exactly
  one of the two lists (`tests/test_vault.py`).
- **Stable ids.** Each sealed value gets an id (`email:3f9a0c7d21b4`), an HMAC-SHA256 computed by KMS with
  `alias/warden-<env>-pseudonym`, a key that never leaves KMS: the same value has the same id in every incident of
  the environment. No model is shown an id.
- **Who can open them** (`terraform/modules/warden-runtime/vault.tf`). The read zone may seal
  (`kms:GenerateDataKey`, `purpose=vault`) and compute ids (`kms:GenerateMac`) and holds no `kms:Decrypt`. Only the
  approval page's Lambda may `kms:Decrypt`, with `purpose=vault`. No other role - the llm zone, Eldane's critic, the
  core, notify and act zones - holds `kms:Decrypt` on any key in the module (`tests/test_vault.py`).
- **Retention.** A sealed map expires `WARDEN_VAULT_DAYS` after it is sealed (default and minimum 180, at most
  3650). Expired rows are deleted by the next seal through `warden_vault_purge()`, a database function that judges
  expiry by the database's own clock; no runtime role may delete a row itself, and a row past its expiry is never
  read. An erasure request is the database owner's: delete the incident's `vault` row; scheduling the vault key's
  deletion makes every sealed map unreadable. The audit's index and hash stay.
- **The reveal** (`reveal.py`, `/r/<incident>/masked` on the records site). Only an **approver** for the incident's
  environment may see the masked values and reveal one; a record viewer (`WARDEN_RECORD_VIEWERS`) reads the record
  and never reveals. GET shows each placeholder, its kind and its id; a reveal is a POST of the page's own form, so
  the reason and the chosen values travel in the body, never in an address. The reader picks the values and gives a
  reason (at least 10 characters, redacted before it is kept); the `incident.reveal` row is written to the signed
  audit **before** the vault is opened, and the values are shown once (no-store), never in an address or in Slack.
  The form's token is bound to the reader's sign-in cookie; a refused attempt (a forged or stale form, no value, no
  reason, more fields than the page offers, not an approver) is recorded as `incident.reveal_attempt_refused`; at
  most 20 reveals and refused attempts per reader per hour, counted inside each row's own write (parallel requests
  cannot pass it together). Whether each reveal also needs a passkey step-up is an open owner decision.
- **No AI path.** No Temporal activity, MCP tool or model-facing module imports the vault or the reveal
  (`tests/test_vault.py`, `tests/test_reveal.py`).
- **Pending PR #147 - the records CLI** masks every string again and never imports the vault or the reveal.

## The model provider: what Anthropic does with a prompt

Researched on **2026-10-21 (13:55-14:00 UTC / 19:25-19:30 IST)** from Anthropic's own pages, read that day. Each
claim links the page it comes from. These are Anthropic's statements, not something WARDEN can check.

**Which path WARDEN uses.** The cloud runtime calls the **Claude API** (`api.anthropic.com`) with an API key: the
default provider is `anthropic` (`providers.resolve`) and the runtime module creates a key slot for no other provider
([PRODUCTION-ARCHITECTURE.md, the model](PRODUCTION-ARCHITECTURE.md#the-model)). WARDEN does not use Amazon Bedrock
(owner decision); the code keeps a Bedrock provider for adopters. The laptop's replay qualification has also used the
Claude CLI on a Claude Max subscription, on recorded incidents only.

| Question | What Anthropic's page says | Source |
|---|---|---|
| Training, the API | "Anthropic may not train models on Customer Content from Services." Customer Content is Inputs and Outputs. (Commercial Terms, section B, effective Jun 17, 2025.) | [Commercial Terms of Service](https://www.anthropic.com/legal/commercial-terms) |
| Data processing terms | "Data submitted through the Services will be processed in accordance with the Anthropic Data Processing Addendum" (section C). | [Commercial Terms of Service](https://www.anthropic.com/legal/commercial-terms) |
| Retention, the API's standard policy | The API retention page points to a "commercial data retention policy" on Anthropic's Privacy Center for the standard period. **Not confirmed here:** that page (privacy.claude.com) could not be opened from this environment on 2026-10-21, so this page states no number for it. | [API and data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention) |
| Retention, what the API page itself says | "Retained data is never used for model training without your express permission." Under a zero data retention (ZDR) arrangement, "Anthropic does not store customer prompts or responses at rest after the API response is returned"; ZDR is enabled per organization on request. Covered Models (Claude Fable 5, 5.1, Claude Mythos 5, 5.1) require 30-day retention; WARDEN's runtime models are Claude Sonnet 5.5 (diagnosis) and Claude Opus 5.5 or Sonnet 5.5 (Eldane, `providers.yaml` `critic`), none of them on that list. | [API and data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention) |
| Region | Inference geo `"global"` is the default: "Inference may run in any available geography"; `"us"` keeps inference in the US. Workspace geo (where data is stored at rest) "is set when you create a workspace and can't be changed afterward. Currently, "us" is the only available workspace geo." | [Data residency](https://platform.claude.com/docs/en/manage-claude/data-residency) |
| Region, as WARDEN calls it | WARDEN's `AnthropicProvider` sends no `inference_geo`, so the workspace's default applies (`"global"` unless the workspace sets `default_inference_geo`). WARDEN cannot see the workspace's setting. | `src/warden/providers.py`; [Data residency](https://platform.claude.com/docs/en/manage-claude/data-residency) |
| Bedrock (not used) | "On Amazon Bedrock and Google Cloud's Agent Platform, the cloud provider is the data processor"; their own documentation applies. | [API and data retention](https://platform.claude.com/docs/en/manage-claude/api-and-data-retention) |
| The Claude CLI on a consumer plan | Free, Pro and Max: "We will train new models using data from Free, Pro, and Max accounts when this setting is on"; retention 5 years with that setting on, 30 days with it off. Commercial users (Team, Enterprise, API): "Standard: 30-day retention period" (for Claude Code). | [Claude Code: data usage](https://code.claude.com/docs/en/data-usage) |

What WARDEN adds on its side: only redacted prompts are sent, with a placeholder for each value a pattern recognises
(a value no pattern recognises can remain, above), and the model guard refuses any prompt that still holds a value it
finds. An install that needs US-only inference or no retention must set it in its Anthropic workspace
(`default_inference_geo`, `allowed_inference_geos`) or agree ZDR with Anthropic; WARDEN has no setting for either.

## Honest limits

- A value no pattern recognises is not masked (above).
- A client other than urllib (boto3, the tracing exporter, Slack's async client) is held by the name and connection
  checks only: its content is not scanned.
- Temporal's client is Rust and libpq is C: their connections raise no Python audit event. Temporal's payloads are
  encrypted by the codec; database hosts come only from configured DSNs; the runtime's network rules limit both.
- AWS names: an RDS, ElastiCache or EKS endpoint, and S3 addressed path-style by boto3, look the same in any account;
  IAM and the network rules decide whose they are.
- The pager Lambda (`terraform/modules/warden-runtime/pager`) is its own package: the hooks are not installed there.
  It posts the page's text to the Slack webhook its secret names.
- Behind a proxy (`HTTPS_PROXY`) a client other than urllib looks up the proxy's name, not its target's. The cloud
  runtime sets no proxy.
- A structured body's value that is only digits is not read as a phone number (an id, a count); every other kind in
  it still blocks.
- An administrator of the AWS account can change any key policy; CloudTrail records that change.

## Live steps (the owner's laptop, after #115 and #119 merge)

1. Apply the runtime module (creates `alias/warden-<env>-vault`, `alias/warden-<env>-pseudonym`, their policies and
   the routes `GET` and `POST /r/{incident}/masked`), then run the migrate Lambda (the `vault` table and
   `warden_vault_purge()`).
2. After the next incident check: Logs Insights shows `egress` rows and no unexpected `BLOCK`; the record shows
   "Masked values (n)" to an approver; a reveal writes `incident.reveal`; CloudTrail shows `GenerateDataKey` and
   `GenerateMac` only from `warden-<env>-read` and `Decrypt` on the vault key only from
   `warden-<env>-approval-lambda`.
3. Datadog (the lab): emit a test line with a made-up email and card number from a shop pod; Datadog Logs must show
   it masked.
4. Anthropic workspace: read its data residency and retention settings in the Claude Console and record them here.
