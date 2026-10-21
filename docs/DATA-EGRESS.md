# What leaves WARDEN's network, and how to check it

The owner's goal (2026-10-20): sensitive data never leaves the network; every egress is recorded, and security,
network and operations engineers can check that it is safe; AI agents never see or reach the masked values; people
with access can reveal them through an audited path.

How far `main` meets it today, in short (details below):
- detected values are masked before anything is built for a model, a chat message, a ticket or a log. One opt-in
  exception: with `WARDEN_REPORT_SHOW_IDENTIFIERS=true`, chat messages show emails, tenant ids and IP addresses again
  (never secrets, never to a model);
- recording **every** egress (the ledger) is **pending PR #104**;
- no masked value is stored on `main`, so there is nothing to reveal yet: the sealed vault and the audited reveal are
  **pending PRs #115 and #119**.

This page is for those engineers. It covers every destination, what goes there and what is masked; what the model
provider does with what it receives; and, as the open privacy PRs land, the egress ledger, the sealed vault and the
reveal.

> **Status, checked against `main` at `13a3324` on 2026-10-21 (14:00 UTC / 19:30 IST).** Each statement below is
> either what `main` does today, or is marked **pending PR #n**: code under review, not merged, not running anywhere.
> The open PRs this page relies on:
>
> | PR | Adds |
> |---|---|
> | [#104](https://github.com/veerarakesh56/warden/pull/104) | `egress.py`: the destination inventory, the strict model guard, the urllib and name-lookup hooks, the ledger; six more redaction classes |
> | [#110](https://github.com/veerarakesh56/warden/pull/110) | the log gate in every Lambda; the lab's Datadog agent masking; log canary tests |
> | [#115](https://github.com/veerarakesh56/warden/pull/115) | `vault.py`: masked values sealed with KMS, stable ids, retention |
> | [#119](https://github.com/veerarakesh56/warden/pull/119) | `reveal.py`: people reveal a masked value on the records page, audited first |
> | [#147](https://github.com/veerarakesh56/warden/pull/147) | `warden records list` and `warden records show`, a read-only CLI over the audit |
> | [#83](https://github.com/veerarakesh56/warden/pull/83) | the AWS updates watch (AWS's news feeds) |
> | [#130](https://github.com/veerarakesh56/warden/pull/130) | end-to-end privacy tests over the bundled incidents |
>
> When one merges, its "pending" marks here are removed in the same or the next PR.

## What is never sent out

On `main`, everything the redactor's patterns find (`src/warden/redaction.py`) is replaced by a placeholder
(`<EMAIL_1>`) before any text is built for a model, a chat message, a ticket or a log line:

- personal data: email addresses, phone numbers, IPv4/IPv6/MAC addresses, tenant, organisation, customer, account and
  user ids (`tenant_id=...`), IBANs, payment card numbers;
- credentials: private keys, JWTs, API keys and tokens, cloud tokens (GCP, Azure SAS), webhook URLs, passwords in
  URLs and connection strings, `Bearer` and `Basic` credentials, cookies, credential flags and fields, and long
  high-entropy strings;
- cloud account ids, ARNs and UUIDs.

**Pending PR #104** adds: internal host names (names under `.corp`, `.lan`, `.intranet`, `.internal`, `.local`,
`home.arpa`, keeping a Kubernetes `.cluster.local` name and AWS's `compute.internal`/`ec2.internal`), US SSNs, Indian
Aadhaar and PAN numbers, street addresses, and personal names where a pattern can see one (after a name field's key,
a title or a greeting). Its `tests/test_redaction_classes.py` holds a corpus for every class. Until it merges, none
of these six is masked by `main`.

Honest limits:
- A value that **no pattern recognises** is not masked. Detection is pattern-based, never a model judging what is
  personal ([ARCHITECTURE.md, the safety layers](ARCHITECTURE.md#the-safety-layers)).
- Even after #104, a personal name in free prose with no marker (`priya nair restarted the pod`) is **not** found.
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
- **GuardDuty and Security Hub findings** (`security_findings.py`, merged in #52).

A security finding's own words and its resource's details (addresses, keys, instance and account ids, ARNs) are
redacted in the alert's summary before it is recorded or told, and every finding is escalate-only: no plan is opened.
`tests/test_security_intake.py` checks it.

## Every destination

"Gated" below means `main`'s outbound gate (`src/warden/gate.py`) and a second redaction of the exact payload in
`chatops.notify`: links, images and markup removed (G3), write commands withheld (G4), and a message that still holds
a secret blocked (G5).

| Destination | Hosts | What goes there | Checked how on `main` | Outside the network? |
|---|---|---|---|---|
| Anthropic (the diagnosis model, Eldane, the discussion chat) | `api.anthropic.com` | a prompt built from redacted evidence: placeholders, never the values | redaction before the prompt is built (`node_redact`; `discuss.py` redacts a thread and question). **Pending PR #104:** every prompt re-scanned strictly before it is sent (`egress.guard_model`), refused if any value is found | yes |
| The Claude CLI (laptop only, for replay qualification) | Anthropic, through the `claude` CLI | the same redacted prompts of recorded incidents | the same | yes |
| Other model APIs (adopters only; the cloud runtime creates no key slot for them) | OpenAI, Groq, OpenRouter, Gemini, Bedrock, `WARDEN_BASE_URL` | the same | the same | yes |
| Slack | `slack.com`, `*.slack.com`, `hooks.slack.com` | the incident report, thread replies; Sign in with Slack (OAuth code exchange) | the report and replies are gated; the OAuth exchange sends Slack's code and the app's own client id and secret (`slack_login.py`) | yes |
| Microsoft Teams, a generic webhook | `WARDEN_TEAMS_WEBHOOK`, `WARDEN_WEBHOOK_URL` | the report | gated | yes |
| PagerDuty | `events.pagerduty.com` | a page about the report | gated | yes |
| GitHub | `api.github.com` | a change record (an issue, `changes.py`); reads of recent deploys and pull requests | the record is gated (`changes.py`); reads send a repository, a commit and a pull request number | yes |
| SonarCloud (opt-in) | `sonarcloud.io` | reads: the issues of a pull request (`WARDEN_SONAR_PROJECT`) | GET only; sends a project key and a pull request number | yes |
| Datadog | `api.<site>` | reads: a service name, a time window, fixed metric queries, a monitor id | reads only | yes |
| AWS's documentation | `knowledge-mcp.global.api.aws` | an AWS error code from the typed facts and a service word from WARDEN's own table (`aws_docs.py`; the cloud read zone sets `WARDEN_AWS_DOCS=on`) | closed vocabulary: no log text, name or account | yes |
| Temporal Cloud | `*.tmprl.cloud` | workflow payloads, **encrypted** with AES-256-GCM (`codec.py`); workflow ids and activity names in clear | the codec | yes |
| Tracing (opt-in) | `OTEL_EXPORTER_OTLP_ENDPOINT` | spans: node names, timings, scrubbed error text (`observability.py`) | scrubbed where written | yes |
| WARDEN's own AWS account | `*.amazonaws.com` | reads, the approved fix, the audit, secrets, KMS (boto3) | IAM (below) | no |
| The private network | non-routable addresses, `*.svc`, `localhost` | a cluster's services, instance and task metadata | - | no |
| *Pending PR #110:* Datadog, from the lab's own agent | Datadog's intake | the lab shop's container and OpenTelemetry logs and spans (not WARDEN's) | masked at the agent (`helm/datadog/values.yaml`) | yes |
| *Pending PR #83:* AWS's news feeds | `aws.amazon.com` | a GET of the What's New and blog feeds | nothing of WARDEN's is sent | yes |

**Pending PR #104** turns this table into code: `egress.STATIC` plus `egress._CONFIGURED`, and a test that fails when
a module opens a network client that is not on it. Found while checking this page on 2026-10-21: #104's inventory
does not list `sonarcloud.io`, which `main`'s findings reader calls. Once #104 merges, its hook would refuse that
read unless the host is added (reported to the PR's lane).

## The guards

On `main` today:

1. **Redaction before every prompt.** The evidence, the alert, labels, deploys and tool errors are redacted as one
   text in the read zone; the llm zone gets the built prompt, never the placeholder map (`activities.prepare`).
   Untrusted text is also turned into typed facts first (`quarantine.py`). Eldane reads only the recorded evidence
   and diagnosis rows and the plan (`eldane.READS`).
2. **The outbound gate** on every way out: chat, terminal, MCP results, generic webhooks, the change record
   (`gate.py`; `tests/test_gate.py`, `tests/test_egress.py`).
3. **The log gate** in the CLI, the MCP server and the workers: every log record is redacted, normalised, redacted
   again and bounded (`observability.GatedFormatter`); warnings and uncaught errors go through it too.

Pending:

4. **Pending PR #104 - the strict model guard.** Every provider class in `providers._REGISTRY` has its `complete`
   wrapped: system and user prompts are scanned with every pattern, and a prompt holding any value is refused.
5. **Pending PR #104 - the urllib hook** (PEP 578 audit hook on `urllib.Request`): an unlisted host is refused; a
   body or query to a destination outside the network is scanned; a body that cannot be read without consuming it
   is refused.
6. **Pending PR #104 - the name-lookup hook** (`socket.getaddrinfo`): an unlisted host is refused before it is
   resolved.
7. **Pending PR #110 - the Lambda log gate.** The Lambda runtime's own handler is wrapped, and an uncaught error
   reaches the runtime as its type only. `tests/test_log_canaries.py` sends canaries through every path.

## The ledger (pending PR #104)

None of this section runs on `main`. With #104, every model call and every request to a destination outside the
network writes one row that **never holds a value**:

```json
{"destination":"slack","outside":true,"purpose":"POST /api/chat.postMessage","bytes":2817,
 "sha256":"…","placeholders":{"EMAIL":2,"IPV4":1},"verdict":"PASS","kinds":[]}
```

- **CloudWatch Logs:** a line `egress {...}` from logger `warden.egress` in `/warden/<env>/worker` and
  `/aws/lambda/warden-<env>-<function>`. A refusal is a WARNING with `"verdict":"BLOCK"` and the kinds found.
- **The signed audit:** the same row as `egress.sent` or `egress.blocked`, under the incident's workflow id. If the
  row cannot be written, the egress is not made.

Logs Insights, on those log groups, once #104 is deployed. Everything that left, by destination:

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

Retention on `main` today: the worker and Lambda log groups keep **90 days**
(`terraform/modules/warden-runtime/compute.tf`, `frontdoor.tf`). Keeping the audit at least 180 days is **planned**,
not built ([DATA-RETENTION.md](DATA-RETENTION.md)). `warden audit verify` checks the audit's hash chain and
signatures today.

## The masked values: sealed for people (pending PRs #115, #119)

On `main` the placeholder map lives only in memory inside the read zone and is dropped once the prompt is built; it
is not stored, so no one can look a masked value up afterwards. The two PRs below change that, and none of it runs
yet.

- **Pending PR #115 - sealed where found.** In `prepare`, the map is encrypted with AES-256-GCM under a fresh KMS data
  key (encryption context `purpose=vault`, environment, incident) and stored in a `vault` table; the signed audit gets
  only an index and the sealed bytes' SHA-256. Each value also gets a **stable id** (`email:3f9a0c7d21b4`), an
  HMAC-SHA256 computed by KMS with `alias/warden-<env>-pseudonym`. No model is shown an id.
- **Who can open them (#115's `vault.tf`).** The read zone may seal (`kms:GenerateDataKey`) and compute ids
  (`kms:GenerateMac`) and holds no `kms:Decrypt`; only the approval page's Lambda may `kms:Decrypt` with
  `purpose=vault`. No AI zone (llm, Eldane's critic) is named in the key policy.
- **Retention (#115).** A sealed map expires after `WARDEN_VAULT_DAYS` (default and minimum 180). An erasure request
  deletes the incident's vault row; scheduling the vault key's deletion makes every sealed map unreadable.
- **Pending PR #119 - the reveal** (`/r/<incident>/masked`): an approver or listed viewer for that environment picks
  values and gives a reason; the `incident.reveal` row is written to the signed audit **before** anything is opened;
  the values are shown once (no-store), never in an address or in Slack. The form's token is bound to the reader's
  sign-in cookie; at most 20 reveals per reader per hour.
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

What WARDEN adds on its side: only redacted prompts are sent, placeholders instead of values (above);
**pending PR #104** refuses any prompt that still holds a value. An install that needs US-only inference or no retention must set
it in its Anthropic workspace (`default_inference_geo`, `allowed_inference_geos`) or agree ZDR with Anthropic; WARDEN
has no setting for either.

## Honest limits

- A value no pattern recognises is not masked (above).
- Until #104 merges, nothing checks a prompt or an HTTP body against a destination list at the moment it is sent; the
  checks are the redaction before the prompt is built and the outbound gate on messages.
- Until #110 merges, a Lambda's log lines and uncaught errors reach CloudWatch through the Lambda runtime's own
  handler, not the log gate.
- Temporal's client is Rust and opens its own connections; its payloads are encrypted by the codec.
- The database client (libpq) resolves names in C; database hosts come only from configured DSNs.
- With #104: behind a proxy (`HTTPS_PROXY`) a client other than urllib looks up the proxy's name, not its target's;
  a raw socket to an IP address with no name lookup would bypass the name check. The cloud runtime sets no proxy.
- An administrator of the AWS account can change any key policy; CloudTrail records that change.

## Live steps (the owner's laptop, after #104, #110, #115 and #119 merge)

1. Apply the runtime module (creates `alias/warden-<env>-vault`, `alias/warden-<env>-pseudonym`, their policies and
   the route `GET /r/{incident}/masked`), then run the migrate Lambda (the `vault` table).
2. After the next incident check: Logs Insights shows `egress` rows and no unexpected `BLOCK`; the record shows
   "Masked values (n)"; a reveal writes `incident.reveal`; CloudTrail shows `GenerateDataKey` and `GenerateMac` only
   from `warden-<env>-read` and `Decrypt` on the vault key only from `warden-<env>-approval-lambda`.
3. Datadog (the lab, after #110): emit a test line with a made-up email and card number from a shop pod; Datadog Logs
   must show it masked.
4. Anthropic workspace: read its data residency and retention settings in the Claude Console and record them here.
