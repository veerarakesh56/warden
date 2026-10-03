# Build or adopt: redaction, the audit log, the signature catalogue (requirement R9)

Read live 2026-10-03. For each component WARDEN built itself, the best ready-made, production-used, free or
AWS-managed alternatives as of today, and whether WARDEN should adopt one.

## 1. Redacting secrets and PII before a model sees text

WARDEN needs: deterministic, reversible indexed placeholders (`<TYPE_n>`), credentials as well as PII, local,
fast on about 20,000 lines, and no over-masking that would make diagnosis impossible.

| Tool | Licence / status | Latest release | Reversible indexed map | Credentials? | Sends text out? |
|---|---|---|---|---|---|
| Presidio | MIT; moved in 2026 from Microsoft to the independent `data-privacy-stack` org | 2.2.364, 2026-07-22 | A docs sample builds `<PERSON_0>` with an entity map and reverses it | Mostly PII; credentials need custom recognisers; NLP model by default, so probabilistic and slower | No |
| detect-secrets (Yelp) | Apache-2.0 | v1.5.0, 2024-05-06 (stale) | No, detects only | AWS keys, JWT, private keys, entropy | No |
| gitleaks | MIT | v8.30.1, 2026-03-21 | No, detects only | Large regex rule set | No |
| Betterleaks (gitleaks' original author, launched 2026-03-15) | - | v1.9.0, 2026-09-29 | No | Yes | No |
| Kingfisher (MongoDB) | Apache-2.0, Rust with a Python module | v2.9.1, 2026-10-02 | No: detects, validates, revokes | Hundreds of rules, live validation | Only with live validation on |
| LLM Guard (Protect AI) | MIT; **archived 2026-07-09** | 0.3.16, 2025-05-19 | Had a vault | - | - |
| AWS Comprehend PII | Managed | - | No (offsets or `*****`) | AWS keys, PASSWORD; no JWT or connection strings | **Yes**; English and Spanish, 100 KB per call |
| Bedrock Guardrails sensitive-information filter | Managed | - | No (`{NAME}`, no index); its docs call it probabilistic | AWS keys, PASSWORD, custom regex | **Yes**, and its trace returns the original values |

**Verdict: keep WARDEN's own.** Nothing does all of: deterministic, reversible indexed placeholders, credentials
and PII, local, fast. The managed services are probabilistic, send the text out, and cannot map back; Presidio's
mapping is a sample, and its NLP layer would over-mask names in logs. Worth taking, if an eval ever shows a missed
secret: diff WARDEN's credential patterns against the gitleaks, Betterleaks or Kingfisher rule sets, or call
Kingfisher as a second detector inside WARDEN's own placeholder mapper. Bedrock note: the guardrail trace and the
invocation log's input are not masked, so any Bedrock path still needs WARDEN's own redaction first.

## 2. A tamper-evident audit log

| Option | Status / licence | Fit |
|---|---|---|
| Amazon QLDB | **End of support 2025-07-31**; AWS points to Aurora PostgreSQL | Retired |
| CloudTrail Lake | **Closed to new customers since 2026-05-31**; critical fixes only | Closed to a new adopter |
| immudb | v1.11.2, 2026-09-03; BSL 1.1 (Apache-2.0 after four years) | A whole database server for one append-only table; licence not plain open source |
| Trillian | Apache-2.0; README: maintenance mode, better supported by Tessera | Do not start on it |
| Tessera | Apache-2.0, Go library; v1.0.4, 2026-07-16; POSIX, AWS (S3 and Aurora), GCP | The standard for tile-based transparency logs, but Go, and on AWS it needs Aurora |
| Sigstore Rekor v2 (on Tessera) | GA October 2025 | The public instance is for software signing; self-hosting means running Tessera |
| Azure confidential ledger | Active | Azure only, paid, no local test mode |

**Verdict: keep WARDEN's own** - a SQLite hash chain with Ed25519 checkpoints, a KMS signer and S3 Object Lock
anchors (register S12): offline verification at near-zero running cost, locally and on AWS, in CloudTrail's digest
pattern. Optional later: write checkpoints in the C2SP signed-note / tlog-checkpoint format (Tessera's and Rekor
v2's), so standard verifiers or witnesses could check them.

## 3. The incident-signature catalogue

| Option | Status | Deterministic library? | AWS (ECS, Lambda, DynamoDB, Aurora) |
|---|---|---|---|
| k8sgpt | Apache-2.0, v0.4.39, 2026-09-14 | Analyzers run without AI, in Go, against a live cluster | None |
| HolmesGPT | Apache-2.0, CNCF Sandbox, 0.42.0, 2026-09-16 | No: runbooks feed an agentic loop | RDS only, via MCP |
| Robusta | MIT, 0.50.0, 2026-09-16 | Playbooks run in-cluster | Kubernetes only |
| kube-prometheus mixins | v0.19.0, 2026-09-24 | PromQL alerts, need Prometheus | Kubernetes only |
| OpenTelemetry semantic conventions | v1.44.0, 2026-08-04 | Names only, no detectors | n/a |
| AWS DevOps Agent | GA 2026-03-31 | A managed agent, not a library | AWS-wide |

**Verdict: keep WARDEN's own catalogue.** Nothing found is a deterministic detector library callable without an
agent loop or a live cluster that covers Kubernetes and ECS, Lambda, DynamoDB and Aurora. Worth taking: k8sgpt's
analyzer list and the kube-prometheus rules as checklists for the Kubernetes signatures, and OpenTelemetry names in
`detect` clauses where they apply - as references, not dependencies.

## Sources (all read 2026-10-03)

- https://api.github.com/repos/microsoft/presidio (and /releases); https://presidio.dataprivacystack.org/anonymizer/;
  https://presidio.dataprivacystack.org/samples/python/pseudonymization/
- https://api.github.com/repos/Yelp/detect-secrets/releases; https://api.github.com/repos/gitleaks/gitleaks/releases
- https://www.bleepingcomputer.com/news/security/betterleaks-a-new-open-source-secrets-scanner-to-replace-gitleaks/;
  https://api.github.com/repos/betterleaks/betterleaks/releases
- https://github.com/mongodb/kingfisher (and /releases)
- https://github.com/protectai/llm-guard; https://pypi.org/pypi/llm-guard/json
- https://docs.aws.amazon.com/comprehend/latest/dg/how-pii.html
- https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-sensitive-filters.html
- https://www.infoq.com/news/2024/07/aws-kill-qldb
- https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake-service-availability-change.html
- https://api.github.com/repos/codenotary/immudb/releases; https://raw.githubusercontent.com/codenotary/immudb/master/LICENSE
- https://github.com/google/trillian; https://github.com/transparency-dev/tessera (and /releases)
- https://blog.sigstore.dev/rekor-v2-ga/
- https://learn.microsoft.com/en-us/azure/confidential-ledger/overview
- https://github.com/k8sgpt-ai/k8sgpt; https://github.com/HolmesGPT/holmesgpt; https://github.com/robusta-dev/robusta
  (each with /releases)
- https://api.github.com/repos/prometheus-operator/kube-prometheus/releases
- https://api.github.com/repos/open-telemetry/semantic-conventions/releases
- https://aws.amazon.com/about-aws/whats-new/2026/03/aws-devops-agent-generally-available
