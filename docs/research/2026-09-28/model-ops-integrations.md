# Model, observability, paging, evidence, intake (research, 2026-09-28)

## 1. Model for RCA on Bedrock

| Model | Bedrock ID | $/1M in / out / cache read | Retirement |
|---|---|---|---|
| Fable 5.1 | anthropic.claude-fable-5-1 | 10 / 50 / 0.25 | not before 2027-09-01 |
| **Opus 5.5** (Anthropic's recommended default) | anthropic.claude-opus-5-5 | 4 / 20 / 0.20 | not before 2027-09-22 |
| Sonnet 5 | anthropic.claude-sonnet-5 | 2 / 10 / 0.20 | not before 2027-06-30 |
| Haiku 4.5 | anthropic.claude-haiku-4-5 | 1 / 5 / 0.10 | not before **2026-10-15**, so avoid it |

- **India:** ap-south-1 and ap-south-2 reach these models only through the **Global** endpoint;
  there is no India regional endpoint and no APAC geo profile.
  - Inference may run in any commercial region; logs stay in the calling region.
  - Regional endpoints cost 10% more.
- **Endpoint limits:** the bedrock-mantle endpoint has no structured outputs (use forced tool use
  plus validation) and no server-side fallback. The tokenizer from Opus 4.7 onward produces about 30%
  more tokens.
- **Other models on Bedrock** (from a third-party catalogue, unverified): Nova 2 Lite/Pro/Lite/Micro,
  Llama 4 Maverick/Scout, Mistral Large 3, DeepSeek V3.2, Qwen3, Kimi K3, GLM 5, gpt-oss, GPT-6.
  In-region in ap-south-1: Nova Pro/Lite, Mistral Large 3, DeepSeek V3.2.
- **Benchmarks:**
  - ORCA-bench (Jul 2026): Opus 4.7 best at 48.8%, but only 10% on Hard; Sonnet 4.6 better on Easy
    and Medium; implausible-root-cause rates from 7% to 40%; removing source-code access hurt every
    model.
  - ITBench-AA: GPT-5.6 Sol 56.2% and Gemini 3.8 Flash 52.5% on the live board; no Claude 5-generation
    results yet.
  - "Pooled leaderboards hide system-specific winners" (Jun 2026): the pooled-best method lost by up
    to 24.8 points on held-out systems.
- **Recommendation:**
  - **Opus 5.5 as the production default**, selected on WARDEN's own bench, with Fable 5.1 and
    Sonnet 5 as comparison arms.
  - Pin the model ID. Never use Haiku 4.5 as a fallback.
  - Estimated cost per incident: about $0.04 (Sonnet 5), $0.09 (Opus 5.5), $0.22 (Fable 5.1).

**Sources:** [Claude in Bedrock](https://platform.claude.com/docs/en/build-with-claude/claude-in-amazon-bedrock) · [models](https://platform.claude.com/docs/en/about-claude/models/overview) · [pricing](https://platform.claude.com/docs/en/about-claude/pricing) · [India global CRIS](https://aws.amazon.com/blogs/machine-learning/access-anthropic-claude-models-in-india-on-amazon-bedrock-with-global-cross-region-inference) · [catalogue (third-party)](https://hidekazu-konishi.com/entry/amazon_bedrock_model_catalog_2026.html) · [ORCA-bench](https://arxiv.org/html/2607.28545) · [ITBench-AA](https://artificialanalysis.ai/evaluations/itbench-aa) · [launch](https://huggingface.co/blog/ibm-research/itbench-aa) · [pooled audit](https://arxiv.org/abs/2606.29159) · [RCAEval](https://github.com/phamquiluan/RCAEval)

## 2. LLM observability

**Langfuse**
- Acquired by ClickHouse on 2026-01-16; the core stays MIT.
- Self-hosting needs Postgres, ClickHouse (≥25.12; 26.4 recommended), Redis and S3. Kubernetes/Helm is
  the production path.
- Enterprise-only extras include SCIM and audit logs.
- Cloud plans: Hobby free, Core $29, Pro $199, Enterprise $2,499. Regions: US, EU and JP only.
- PII masking happens client-side only.

**Other options**
- **Datadog LLM Observability:** includes Sensitive Data Scanner (pricing unverified).
- **Arize:** AX Free and Pro (unverified); Phoenix is OSS.
- **Honeycomb:** GenAI-convention aware; pricing unverified.
- **AWS:** CloudWatch gen-AI observability has been GA since Oct 2025. **CloudWatch Omni** went GA on
  2026-09-22, with trace timelines and 17 evaluators; its regions and PII handling are unverified.
- **OTel GenAI conventions:** still in Development status. They moved to a separate repo in v1.42.0
  (2026-06-12).

**Recommendation:** keep OTel GenAI spans flowing through an ADOT/OTel collector. **Langfuse
self-hosted in the customer's own account** for prompt debugging. Datadog when a company already uses
it. CloudWatch for operational metrics.

**Sources:** [Langfuse→ClickHouse](https://langfuse.com/blog/joining-clickhouse) · [self-hosting](https://langfuse.com/self-hosting) · [ClickHouse req](https://langfuse.com/self-hosting/deployment/infrastructure/clickhouse) · [pricing](https://langfuse.com/pricing) · [masking](https://langfuse.com/docs/observability/features/masking) · [Datadog](https://www.datadoghq.com/product/ai/llm-observability/3/) · [Arize](https://arize.com/pricing/) · [Phoenix](https://github.com/arize-ai/phoenix) · [CloudWatch Omni](https://aws.amazon.com/blogs/aws/introducing-amazon-cloudwatch-omni-ai-powered-observability-for-generative-ai-and-agentic-workloads/) · [CW gen-AI GA](https://aws.amazon.com/about-aws/whats-new/2025/10/generative-ai-observability-amazon-cloudwatch)

## 3. Paging and incident management

| Tool | Status |
|---|---|
| PagerDuty | Free tier: 5 users; Professional $21/user; Business $41. Events API v2 supports `dedup_key`. |
| Opsgenie | End of sale 2025-06-04; **shutdown 2027-04-05** (third-party source). |
| incident.io | Basic tier has no API; Team $15–19 + $10 for on-call. |
| Grafana OnCall OSS | Maintenance mode from 2025-03-11; **archived 2026-03-24**. |
| FireHydrant | Acquired by Freshworks. |
| Rootly | No public list price. |
| AWS Incident Manager | **Closed to new customers since 2025-11-07**. |

**Recommendation:** make PagerDuty Events API v2 the first-class integration
(`dedup_key=inc-<id>`, resolve when the fix is verified). Reach the others through the generic
webhook.

**Sources:** [PagerDuty pricing](https://www.pagerduty.com/pricing/incident-management/) · [Events v2](https://developer.pagerduty.com/docs/events-api-v2/overview/) · [Opsgenie EOL](https://hyperping.com/blog/opsgenie-end-of-life) · [Atlassian migration](https://www.atlassian.com/software/opsgenie/migration) · [incident.io](https://incident.io/pricing) · [Grafana OnCall](https://grafana.com/docs/oncall/latest/set-up/open-source/) · [FireHydrant](https://firehydrant.com/blog/firehydrant-to-be-acquired-by-freshworks/) · [Incident Manager change](https://docs.aws.amazon.com/incident-manager/latest/userguide/incident-manager-availability-change.html)

## 4. Evidence breadth

- **HolmesGPT** (CNCF Sandbox): `config.create_tool_executor(...)` gives a tool executor without an
  LLM. Its output is raw text, so it has to go through quarantine.
- **AWS DevOps Agent:**
  - GA 2026-03-31, available in ap-south-1 (one of 11 regions).
  - APIs: `CreateBacklogTask` / `GetBacklogTask`, EventBridge events, HMAC webhooks (2026-06-24).
  - Vendor-claimed 94% accuracy.
- **CloudWatch investigations:** 1 group, 2 concurrent, 150 enhanced per month. By default, content
  may be used to improve AWS services unless you opt out.

**Recommendation:** keep WARDEN independent. DevOps Agent investigations and Holmes toolsets may be
added only as quarantined, untrusted evidence.

**Sources:** [HolmesGPT SDK](https://holmesgpt.dev/0.31.1/reference/python-sdk/) · [DevOps Agent GA](https://aws.amazon.com/blogs/mt/announcing-general-availability-of-aws-devops-agent/) · [regions](https://docs.aws.amazon.com/devopsagent/latest/userguide/about-aws-devops-agent-supported-regions.html) · [GetBacklogTask](https://docs.aws.amazon.com/devopsagent/latest/APIReference/API_GetBacklogTask.html) · [webhook](https://docs.aws.amazon.com/devopsagent/latest/userguide/configuring-capabilities-for-aws-devops-agent-invoking-devops-agent-through-webhook.html) · [investigations](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Investigations.html) · [data use](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/data-usage-considerations.html)

## 5. Intake

- **EventBridge:** "CloudWatch guarantees the delivery of alarm state change events to EventBridge",
  for every alarm type.
- **SNS:** only for fan-out.
- **Lambda alarm action:** available since Dec 2023.
- **Alertmanager v4 payload:** carries `groupKey` and a fingerprint. Defaults: group_wait 30s,
  group_interval 5m, repeat_interval 4h.

**Recommendation:** one EventBridge rule on "CloudWatch Alarm State Change" with retry and a DLQ.
Alertmanager grouping, with `groupKey` as the alert id. Idempotent intake, with workflow ids as the
dedup.

**Sources:** [alarm events](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch-and-eventbridge.html) · [Lambda action](https://aws.amazon.com/about-aws/whats-new/2023/12/amazon-cloudwatch-alarms-lambda-change-action/) · [Alertmanager](https://prometheus.io/docs/alerting/latest/configuration/)
