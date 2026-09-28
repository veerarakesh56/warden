# Orchestration and platform chosen on quality (research, 2026-09-28)

**Recommendation:** keep Temporal, on **Temporal Cloud**, with a high-availability namespace. If you
operate WARDEN yourself, run its workers on ECS; if customers install it, ship a Helm chart plus a
Terraform module on EKS. WARDEN's own database is Aurora PostgreSQL; blobs go to S3. Facts come from
vendor pages fetched 2026-09-28; **[unverified]** marks anything not confirmed on a primary page.

## 1. Temporal Cloud vs self-hosted

**Temporal Cloud plans** ([pricing](https://temporal.io/pricing), [pricing docs](https://docs.temporal.io/cloud/pricing))

| Plan | Price | Includes | Support |
|---|---|---|---|
| Developer | pay-as-you-go; the greater of $0 or 10% of usage | — | developer support |
| Business | the greater of $500/mo or 10% of usage | 2.5M actions, 2.5 GB active, 100 GB retained | P0 2 h, business hours |
| Enterprise | contact sales | 10M actions, 10 GB active, 400 GB retained | P0 30 min, 24/7 |
| Mission Critical | contact sales | as Enterprise | P0 15 min, named architect |

- Actions: $50 per million for the first 5M, stepping down to $25 per million in the 100–200M band.
- Storage: active $0.042 per GB-hour; retained $0.00105 per GB-hour.
- High-availability namespaces charge a 2x multiplier.
- "Essentials" is no longer listed [unverified whether retired or renamed].
- **Plan-feature conflict:** the pricing page says "no features locked behind plan upgrades", yet
  lists audit logging and PrivateLink under Business. Confirm with sales.

**Availability** ([SLA](https://docs.temporal.io/cloud/sla), [regions](https://docs.temporal.io/cloud/regions), [HA](https://docs.temporal.io/cloud/high-availability))
- SLA: 99.9% for standard namespaces, 99.99% for HA namespaces.
- **ap-south-1 (Mumbai) and ap-south-2 (Hyderabad) are both available**, with multi-region replication within APAC.
- HA replication is asynchronous, active to passive: RPO under 1 minute, RTO about 20 minutes, automatic failover.

**Security** ([security](https://docs.temporal.io/cloud/security), [connectivity](https://docs.temporal.io/cloud/connectivity))
- Authentication: mTLS per namespace, or API keys held by service accounts.
- SAML SSO, plus SCIM provisioning on Enterprise.
- Network: AWS PrivateLink / GCP Private Service Connect; connectivity rules can force private-only access.
- Encryption: TLS 1.3 in transit, AES-256-GCM at rest.
- Compliance: SOC 2 Type 2, GDPR, HIPAA.
- No customer-managed keys. Encrypt payloads client-side with a data converter (can use KMS), and run
  a codec server so the UI can decrypt.

**Audit logs** ([audit logging](https://docs.temporal.io/cloud/audit-logging))
- Cover account and admin actions only (user email or API key ID), streamed to Kinesis or Pub/Sub,
  kept 30 days.
- They do **not** record workflow events such as starts, signals or terminations. WARDEN must keep
  its own record of who approved and who triggered.

**Other**
- Nexus exists in both Cloud and self-hosted.
- Cloud handles upgrades.
- Terraform provider: `temporalio/temporalcloud` ([docs](https://docs.temporal.io/cloud/terraform-provider)).

**Self-hosted**
- Components: the frontend, history, matching and worker services; a persistence store (PostgreSQL,
  MySQL or Cassandra); and a visibility store.
- For visibility, PostgreSQL 12+ works, but Elasticsearch/OpenSearch is recommended "for any setup
  that spawns more than a few Workflow Executions" ([visibility](https://docs.temporal.io/self-hosted-guide/visibility)).
- **The default authorizer allows every API call** ("not secure for production"). You need a JWT
  ClaimMapper, an authorizer and mTLS ([security](https://docs.temporal.io/self-hosted-guide/security)).
- The history shard count is fixed at install time, and minor versions cannot be skipped on upgrade
  ([checklist](https://docs.temporal.io/self-hosted-guide/production-checklist)).
- Latest release v1.32.0 ([releases](https://github.com/temporalio/temporal/releases)). Recent CVEs:
  CVE-2026-5199 (low) and CVE-2026-5724 (medium, missing authorization on a replication endpoint).
- The official Helm chart is production-grade only for the Temporal services themselves.

**Latency.** Temporal's May 2024 benchmark had Cloud about 2x faster; signal p50/p90 was 7.6/9.8 ms on
Cloud against 17.5/23.5 ms self-hosted ([benchmark](https://temporal.io/blog/benchmarking-latency-temporal-cloud-vs-self-hosted-temporal)).

**Adoption.** Temporal raised $550M at a $12.55B valuation in Sep 2026, with 4,300+ paying Cloud
customers ([news](https://temporal.io/news/temporal-raises-550m-at-a-12-55b-valuation)).

**Cost estimate**
- Cloud Business with HA: about $500–1,000/month at WARDEN's volume.
- Self-hosted: about $1.5–3k/month for infrastructure plus 0.5–1 SRE FTE [estimate].

## 2. Is Temporal still the right engine? Yes, keep Temporal.

| Engine | Assessment |
|---|---|
| AWS Step Functions ([quotas](https://docs.aws.amazon.com/step-functions/latest/dg/service-quotas.html), [pricing](https://aws.amazon.com/step-functions/pricing/)) | Native IAM, task-token callbacks, runs up to 1 year, $0.025 per 1k transitions. But limited to 25k history events, 256 KiB payloads and 90-day history, and it uses a JSON DSL. |
| Restate 1.6 (Feb 2026), DBOS | Credible, but younger ([Restate](https://www.restate.dev/blog/announcing-restate-1-6), [DBOS](https://www.dbos.dev/dbos-pricing)). |
| Hatchet, Inngest | Weaker on versioning and replay [assessment]. |
| Kestra | A YAML pipeline tool, not a durable code engine. |
| Azure Durable | Tied to Azure. |

**Worth adopting:** receive approvals as Temporal **Updates with a validator**, so a bad approval is
rejected before it is written to history [from knowledge; not re-fetched].

## 3. Where the workers run

Temporal ([2 Apr 2026 post](https://temporal.io/blog/deploying-temporal-workers-to-amazon-ecs)) says
start with ECS and Fargate for 1–10 workers; move to EKS when you already run Kubernetes, pass 50+
tasks, or need Worker Versioning. The Worker Controller for Worker Versioning is Kubernetes-only
([docs](https://docs.temporal.io/production-deployment/worker-deployments/kubernetes-controller)).

- **Tool companies install themselves:** the standard is a Helm chart plus a Terraform module, on EKS
  (about $300–450/month).
- **Service you run yourself:** ECS (about $100–200/month for 2–4 tasks).

## 4. Database

| Option | Failover | Source |
|---|---|---|
| RDS Multi-AZ instance | 60–120 s | [AWS](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.Failover.html) |
| RDS Multi-AZ DB cluster | under 35 s | same |
| Aurora | often under 30 s, 6 copies across 3 AZs; Global Database for DR | same |

**Recommendation**
- **Aurora PostgreSQL, provisioned**: a writer and a reader in different AZs.
- Storage: Standard at first; switch to I/O-Optimized once I/O passes about 25% of the bill [unverified rule of thumb].
- Blobs: S3 with versioning, plus Object Lock in compliance mode for audit evidence, replicated to ap-south-2.
- Cost: about $400–600/month for Aurora, under $50/month for S3 [estimates].

**Total with Temporal Cloud Business HA:** about $1.0–1.8k/month.
