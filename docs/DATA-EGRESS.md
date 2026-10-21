# What leaves WARDEN's network, and how to check it

Owner, 2026-10-20: sensitive data never leaves the network. Every egress is recorded, and security, network and
operations engineers can check that it is safe. AI agents never see or reach the masked values. People with access
can reveal them through an audited path.

This page is for those engineers. It covers every destination, what goes there and what is masked; where the ledger
is and how to read it (CloudWatch Logs Insights, Live Tail, the signed audit); and how the masked values are sealed,
revealed, kept and deleted.

> **Status, 2026-10-20.** This page describes the privacy lane's four code changes:
> - #104: egress inventory, strict checks, ledger
> - #110: Lambda log gate and canaries
> - #115: the sealed vault and stable ids
> - #119: the reveal
>
> Until a change has merged and been deployed, its part below describes code under review, not the running system.
> "Live steps" at the end lists what the owner's laptop must do once.

## What is never sent out

Everything the redactor's patterns find (`src/warden/redaction.py`), of **every** kind:

- personal data: email addresses, phone numbers, personal names (where a pattern can see one, below), street
  addresses, IPv4/IPv6/MAC addresses, tenant, organisation, customer, account and user ids, IBANs, card numbers,
  national ids (US SSN, Indian Aadhaar and PAN);
- internal host names: names under a company's private suffixes (`.corp`, `.lan`, `.intranet`, `.internal`, `.local`,
  `home.arpa`). A Kubernetes service's `.cluster.local` name and AWS's own `compute.internal`/`ec2.internal` are kept:
  WARDEN reads and acts on them (the address inside an EC2 name is masked);
- credentials: keys, tokens, passwords, cookies, JWTs, private keys, connection-string passwords, webhook URLs, and
  long high-entropy strings;
- cloud account ids and ARNs.

Each value is replaced by a placeholder (`<EMAIL_1>`) before any text is built for a model, a chat or a ticket.

Honest limits:
- A value that **no pattern recognises** is not masked. That is the patterns' limit, not a guard's.
- **Personal names are caught only in the forms a pattern can see**: after a name field's key (`full_name=`,
  `"customer_name":`, `username=`), after a title (`Dr.`, `Mrs`, `Shri`...) or a greeting (`Dear ...`). A name in
  free prose with no such marker (`priya nair restarted the pod`) is **not** found - no pattern can tell it from a
  word. A test pins this, so the day it changes, this page changes with it.
- Detection is pattern-based, never a model judging what is personal.

`tests/test_redaction_classes.py` holds a corpus for every class above (`tests/privacy_corpus.py`), the evidence that
must stay as it is, and the egress check refusing each.

## What comes in, and is masked first

Every source WARDEN reads is evidence of kind A or B: untrusted text, redacted as one text with the rest of the
incident before anything is built from it (`graph.node_redact`, `activities.prepare`). The sources are:

- CloudWatch alarms and logs, CloudTrail, the AWS service APIs;
- Datadog (and Grafana for adopters);
- Kubernetes;
- the watched databases;
- Alertmanager and Datadog webhooks;
- AWS Health and service events;
- since #52, **GuardDuty and Security Hub findings**.

A finding's own words, the attacker's address, the instance's addresses and keys are masked in the alert's summary
before it is recorded or told. A finding is always escalate-only: no model is asked about it. `tests/test_egress.py`
plants an email, an address and an account id in a finding's description and checks none of them reaches the alert,
the evidence or a Slack body.

## Every destination

| Destination | Hosts | What goes there | Checked how | Outside the network? |
|---|---|---|---|---|
| Anthropic (the diagnosis model, Eldane, the discussion chat) | `api.anthropic.com`; the Claude CLI | a prompt: redacted evidence, placeholders only | every prompt, strictly, before it is sent (`egress.guard_model`); a prompt holding any value is refused | yes |
| Other model APIs (adopters only) | OpenAI, Groq, OpenRouter, Gemini, `WARDEN_BASE_URL` | the same | the same | yes |
| Slack | `slack.com`, `*.slack.com`, `hooks.slack.com` | the gated incident report, thread replies; sign-in with Slack (OAuth code exchange) | every request body and query (urllib hook); Slack's own OAuth fields (`client_id`, `client_secret`, `code`) and WARDEN's approval/record links are the only exemptions | yes |
| Microsoft Teams, a generic webhook | `*.webhook.office.com`, `WARDEN_WEBHOOK_URL` | the gated report | the same; the webhook's path is never written to the ledger | yes |
| GitHub | `api.github.com` | the gated change record (an issue); reads of recent deploys | the same | yes |
| Datadog | `api.<site>` | reads only: a service name, a time window, fixed metric queries | the same (all-digit query values are times, not phone numbers) | yes |
| Datadog, from the lab's agent (the shop's own logs and spans, not WARDEN's) | Datadog's intake, by its agent on the lab cluster | the apps' container and OpenTelemetry logs, spans, metrics | **masked at the agent**: global `mask_sequences` for every class above (`helm/datadog/values.yaml`, RE2), span tags by `DD_APM_REPLACE_TAGS`; the collector before it hashes user/client attributes and drops URL queries; `tests/test_datadog_agent_masking.py`. Not at the agent: `.local`/`.internal` names | yes |
| PagerDuty | `events.pagerduty.com` | the gated report's first line | the same; `routing_key` is PagerDuty's own credential | yes |
| AWS's documentation (opt-in) | `knowledge-mcp.global.api.aws` | an AWS error code and a service word | the same | yes |
| AWS's news feeds (the AWS updates watch, opt-in) | `aws.amazon.com` | a GET of the What's New and blog RSS feeds - nothing of WARDEN's; the text read is untrusted | the urllib hook (no body to check) | yes |
| Temporal Cloud | `*.tmprl.cloud` | workflow payloads, **encrypted** (`codec.py`); workflow ids and activity names in clear | the codec; Temporal's client is Rust and is not seen by the hook (limit below) | yes |
| *Inbound:* GuardDuty and Security Hub findings (#52) | EventBridge → the alarm Lambda (no outbound call) | nothing goes out; the finding's own words are masked in the alert's summary before it is recorded or told, and it is escalate-only (no model is asked) | `redact` in `security_findings.py`; the report it becomes passes the Slack check above; `tests/test_egress.py` plants canaries in a finding | - (comes in) |
| WARDEN's own AWS account | `*.amazonaws.com` | reads, the approved fix, the audit, secrets, KMS (boto3); a database endpoint's name looked up for a reachability analysis | name lookups listed; a urllib body to any AWS name is checked like one outside | no |
| The private network | non-routable addresses, `*.svc`, `*.internal`, `localhost` | a cluster's services, instance and task metadata | name lookups listed | no |
| A proxy (`HTTPS_PROXY`) | its host | the tunnel to the destinations above | requests through it are checked by their real address | no |
| Tracing (opt-in) | `OTEL_EXPORTER_OTLP_ENDPOINT` | spans: node names, timings, scrubbed error text | name lookup listed (its client is `requests` since 1.45.1, not urllib: the lookup is its guard, tested); the span text is scrubbed where it is written (`observability.span`) | yes |

The table is `egress.STATIC` plus `egress._CONFIGURED` (`src/warden/egress.py`). `tests/test_egress.py` fails when a
module starts opening a network client that is not on its inventory.

## The guards

1. **The model guard.** Every model provider class in `providers._REGISTRY` has its `complete` wrapped, so every path
   that builds a provider is covered, Eldane's included. The system and user prompts are scanned with every pattern,
   strictly. The bench's 132 recorded prompts were scanned the same way: no hits.
2. **The urllib hook.** An interpreter audit hook (PEP 578, `urllib.Request`) sees every HTTP request urllib makes,
   through any opener, before a connection:
   - an unlisted host is refused;
   - a destination outside the network has its body and query scanned;
   - a body that cannot be read without consuming it (a file, a stream) is refused.
3. **The name-lookup hook** (`socket.getaddrinfo`, used by the model SDKs, boto3, Slack's socket client and OTLP): an
   unlisted host is refused before it is resolved.
4. **The log gate.** Every log record is redacted, normalised, redacted again and bounded: the CLI, the MCP server,
   the workers, and every Lambda (the Lambda runtime's own handler is wrapped). A Lambda's uncaught error reaches the
   runtime as its type only. `tests/test_log_canaries.py` sends canaries through every path: arguments, messages,
   chained exceptions, tracebacks, warnings, a thread's error and a Lambda's error.

The hooks are installed by every Lambda, and by `warden ...` whenever `WARDEN_ENV` names an environment (the
runtime's workers and the laptop's commands against it).

## The ledger: every egress, recorded

Every model call and every request to a destination outside the network writes one ledger row. A row **never
holds a value**:

```json
{"destination":"slack","outside":true,"purpose":"POST /api/chat.postMessage","bytes":2817,
 "sha256":"…","placeholders":{"EMAIL":2,"IPV4":1},"verdict":"PASS","kinds":[]}
```

- **CloudWatch Logs.** Each row is a line `egress {...}` from logger `warden.egress`, in `/warden/<env>/worker` and in
  `/aws/lambda/warden-<env>-<function>`. The first lookup of each host per process is also a line
  (`"connect": "<host>"`). A refusal is a WARNING with `"verdict":"BLOCK"` and the kinds found.
- **The signed audit.** The same row is written as `egress.sent` or `egress.blocked`, under the incident's workflow
  id. It appears on the incident's records page under "Every step on the record". If the row cannot be written, the
  egress is **not made** (fail closed).

### Checking it: CloudWatch Logs Insights

Select the log groups `/warden/<env>/worker` and `/aws/lambda/warden-<env>-*`.

Everything that left, by destination:

```
fields @timestamp, @message
| filter @message like /egress \{/
| parse @message '"destination":"*"' as destination
| parse @message '"verdict":"*"' as verdict
| stats count(*) by destination, verdict
```

Every refusal (something tried to leave unmasked, or to an unlisted host):

```
fields @timestamp, @logStream, @message
| filter @message like /egress/ and @message like /"verdict":"BLOCK"/
| sort @timestamp desc
```

Every host each process looked up:

```
filter @message like /"connect":/ | parse @message '"destination":"*"' as d | parse @message '"connect":"*"' as host
| stats count(*) by d, host
```

A raw value in any log (an independent check of the log gate). Use a value you know, such as a test address, and
search for it:

```
filter @message like /canary\.person/
```

### Live Tail

In CloudWatch, open Live Tail on the same log groups with the filter pattern `"egress"`. Or use
`aws logs start-live-tail --log-group-identifiers <arns> --log-event-filter-pattern '"verdict\":\"BLOCK"'`.

### The audit

Rows of kind `egress.sent` / `egress.blocked` are in the signed audit beside the incident's other steps, and
`warden audit verify` checks the chain they are in. The audit is retained for at least 180 days (register B19).
The CloudWatch log groups keep 90 days until lane N's retention change lands.

## The masked values: sealed for people, out of every AI's reach

- **Sealed where they are found.** In the read zone's `prepare`, the run's placeholder → value map is sealed. Each
  seal gets a fresh AWS KMS data key (encryption context `purpose=vault`, the environment and the incident) and the
  map is encrypted with AES-256-GCM. The sealed row goes to the `vault` table beside the audit. The signed audit gets
  only the index: placeholder, kind, stable id, the sealed bytes' SHA-256 and the expiry. The map is never returned
  by `prepare`, so it never enters Temporal's history. No log line holds it. No Slack message holds it.
- **Stable ids.** For example `email:3f9a0c7d21b4`: an HMAC-SHA256 of kind and value, computed **by KMS** with
  the environment's HMAC key (`alias/warden-<env>-pseudonym`), which never leaves KMS; only the read zone may use it
  (`kms:GenerateMac`). The same value gets the same id in every incident, so people can recognise and correlate
  their own users, organisations, tenants and hosts. The id reveals nothing about the value. **No model is shown an
  id**; models see `<EMAIL_1>`.
- **Who can open them.** The vault key's policy (`terraform/modules/warden-runtime/vault.tf`) names every principal:
  - the read zone may seal (`GenerateDataKey`) and holds **no** `kms:Decrypt`;
  - only the approval page's Lambda may open (`kms:Decrypt`, `purpose=vault`) - it is the only principal with
    Decrypt on the key, in the key policy and in IAM;
  - the account may administer the keys (exact actions, no `CreateGrant`) but never use them.

  No AI zone is named: not the llm zone (the diagnosis model and the discussion chat), not Eldane's critic zone, and
  not any zone added later. An IAM grant elsewhere cannot add one, because the key policy does not delegate use to
  IAM. CloudTrail records every `GenerateDataKey` and `Decrypt`.
- **The reveal** (`/r/<incident>/masked`, linked from the record page as "Masked values (n)"):
  1. It is open to a reader Slack names who is an approver or on the viewer list, for that environment.
  2. The reader first sees the values by placeholder, kind and id.
  3. To reveal, they choose values and give a reason. The `incident.reveal` row (who, which values, why, the sealed
     row's hash) is written to the signed audit **before** anything is opened.
  4. Only the chosen values are shown, once (no-store), never in an address, never in Slack.

  The form's token is bound to the reader's HttpOnly sign-in cookie, so another site cannot trigger a reveal. A
  reader may make at most 20 reveals an hour. API Gateway's access log records the route, not the query.

  To see who revealed what, look for the `incident.reveal` rows on the record, and the `kms:Decrypt` events by
  `warden-<env>-approval-lambda` in CloudTrail.
- **The records CLI** (`warden records list|show`, lane Z's #147, when it lands): read-only over the audit, for an
  operator's terminal. It masks every reader-facing string again before printing, never imports the vault or the
  reveal, and never puts a masked value back. The reveal stays on the records page only.
- **Retention and deletion.** A sealed map expires after `WARDEN_VAULT_DAYS` (default and minimum 180) and is deleted
  by the next seal (through `warden_vault_purge()`). The audit's index and hash remain, so what existed stays provable.
  - **Erasure request:** the database owner deletes the incident's row with
    `DELETE FROM vault WHERE incident = '<id>'`. The signed audit holds no value to erase; its ids are keyed hashes.
  - **Everything at once:** schedule the vault key's deletion. Every sealed map then becomes unreadable for good.

## Honest limits

- A value no pattern recognises is not masked (see above).
- Temporal's client (Rust) opens its own connections, which no Python hook sees. Its payloads are encrypted by the
  codec, and the runtime's network rules are the outer layer (register B23).
- The database client (libpq) resolves names in C, so database hosts are not checked by the hook. They come only
  from configured DSNs.
- A raw socket to an IP address with no name lookup would bypass the name check. Nothing in `src/warden` opens one,
  and the static inventory test catches a new network client.
- An administrator of the AWS account can change the vault key's policy. CloudTrail records that change, and every
  `Decrypt`.
- Every runtime zone connects to the audit database as one writer, so any zone can read a sealed row. It holds
  ciphertext only, which no zone but the approval page can open. No zone can delete one: retention runs through
  `warden_vault_purge()`, which removes only expired rows by the database's own clock.

## Live steps (the owner's laptop, once)

1. Apply the runtime module. This creates the vault key `alias/warden-<env>-vault` and the HMAC key
   `alias/warden-<env>-pseudonym` (about US$1 a month each, plus US$0.03 per 10,000 requests), their role policies,
   and the route `GET /r/{incident}/masked`.
2. Run the migrate Lambda, which creates the `vault` table and its grants (`runtime.yml` already runs it after
   apply).
3. After the next incident, check four things:
   - Logs Insights shows `egress` rows and no unexpected `BLOCK`;
   - the record shows "Masked values (n)";
   - a reveal writes `incident.reveal`;
   - CloudTrail shows `GenerateDataKey` and `GenerateMac` only from `warden-<env>-read` and `Decrypt` on the vault
     key only from `warden-<env>-approval-lambda`.
4. Datadog (the lab): after the next deploy, emit a test line with a made-up email and card number from a shop pod
   and search Datadog Logs for it - it must read `[masked:email]` and `[masked:card]`, for a container line and for an
   OpenTelemetry one.
