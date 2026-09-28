# What mature companies run around production LLM agents (research, 2026-09-28)

About half of the claims were verified against primary sources; the rest are marked [unverified].

## A. What named companies run

| Company | What they run | Source |
|---|---|---|
| **Uber** | **GenAI Gateway:** Go, OpenAI-compatible, auth, cache, observability, PII redaction before vendors. **MCP Gateway:** 1,000+ servers; 60k agent tasks a week; 1,500+ agents. **Agent identity:** registry, SPIFFE/SPIRE, a token service that rebuilds the token per hop with the actor chain, p99 under 40 ms. **Cost:** live counters, tiered pools, Slack nudges at 50/80/100%, a dashboard of 16 anti-patterns | uber.com/blog/genai-gateway, /solving-the-agent-identity-crisis, /efficient-software-factory |
| **Stripe** | Bedrock (one security review); an LLM proxy with fallback; prompt caching; an agent service; human checkpoints; the full log of every run; "Minions" (deterministic blueprints, output a PR) | AWS ML blog (2026-06-26); InfoQ (Mar 2026) |
| **Shopify** | Ground-truth sets from production, labelled by 3+ experts; LLM judges calibrated against humans (Kappa 0.02 → 0.61, vs humans 0.69); a merchant simulator; instructions injected just in time; reward-hacking checks | shopify.engineering (2025-08-26) |
| **LinkedIn** | Messaging as the orchestrator; a gRPC skill registry; separate memory; LangSmith before production and OTel in production; HITL; traces turned into eval sets | LinkedIn Eng (2025-09-10) |
| **DoorDash** | A real-time guardrail, an LLM judge for quality monitoring, a simulation/evaluation flywheel | careersatdoordash.com |
| **Replit** (negative) | An agent deleted prod during a code freeze. Afterwards: dev/prod split, a plan-only mode, one-click restore | 2025 post-mortems |

The shared pattern: one model gateway, one tool gateway, identity that records who delegated to
whom, cost counters, evals built from production, OTel, and a human gate.

## B. Layers, and where WARDEN stands

| Layer | Tools | WARDEN |
|---|---|---|
| AI gateway / proxy | Agent Router (formerly Envoy AI Gateway, AAIF) [license unverified]; LiteLLM (compromised PyPI 1.82.7/1.82.8, 2026-03-24, via a Trivy step in their CI); Portkey; Kong | Not needed: one model call per incident |
| Model routing / fallback | Gateways; Bedrock CRIS | Partial |
| Prompt management / versioning | Langfuse (Radar: Trial); Bedrock Prompt Management; LaunchDarkly AgentControl | **Missing** |
| Caching | Bedrock / Anthropic caching | Skip |
| Cost governance / denial of wallet | Agent Router quotas; Bedrock application inference profiles + tags; AWS Budgets | Partial |
| Eval in CI | Inspect AI, promptfoo, DeepEval | Strong |
| Online eval / production feedback | Langfuse, Phoenix, Braintrust | **Missing** |
| Tracing | OTel GenAI (dev status), Langfuse, Phoenix, SigNoz | Done |
| Guardrails | NeMo, Prompt Guard 2, Bedrock Guardrails (incl. Automated Reasoning checks: detect-only, English, `ApplyGuardrail` standalone) | Strong |
| Red-team program | PyRIT, garak, promptfoo, AgentDojo; MITRE ATLAS; OWASP Agentic Top 10 2026 (2025-12-09) | Partial |
| Sandboxed execution | gVisor, Firecracker, E2B, Daytona, Modal | N/A (no code execution) |
| Secrets | SSM, Secrets Manager, Vault/OpenBao | Done/planned |
| Agent identity / delegation | SPIFFE/SPIRE; RFC 8693; **Entra Agent ID (GA 2026-05-01)**; AgentCore Identity; CoSAI ODIS | Partial: approver not carried into the actor session |
| Policy engine | Cedar (CNCF); **AgentCore Policy (GA 2026-03-03)**; OPA | Done in-house |
| Data governance / PII | Presidio; Bedrock Guardrails PII | Strong |
| HITL | Temporal, LangGraph interrupts, LaunchDarkly, Slack | Strong |
| AI incident management | **CoSAI AI Incident Response Framework v1.0 (2025-10-27)**: extends NIST SP 800-61r3; preserve prompts, model checksums, traces, tool logs | Partial |
| Model / prompt supply chain | OpenSSF model signing v1.0; CycloneDX ML-BOM (1.7); SPDX 3 AI | Partial |
| Feature flags / progressive rollout | OpenFeature/flagd, Unleash, LaunchDarkly AgentControl | Partial |
| Kill switch | flags, gateway deny, IAM deny | Done |
| Durable execution | Temporal, Restate, DBOS (Radar: Caution on "ignoring durability") | Done |
| Tool gateway / MCP registry | Agent Router MCPRoute, AgentCore Gateway (Radar: Caution on "MCP by default") | N/A |
| Compliance | NIST AI RMF + AI 600-1; ISO/IEC 42001 (Anthropic certified 2025-01-13); **EU AI Act Digital Omnibus**, in force 2026-07-27 (Annex III high-risk from **2027-12-02**; Annex I from 2028-08-02; Art. 50 watermarking 2026-12-02) | **Missing** |

## C. Layers WARDEN is missing, with a recommendation each

1. **Prompt, model and policy provenance in the signed audit** (model id, returned version, sha256
   of the prompt template, `environments.yaml` and signatures).
2. **Production feedback:** approver decisions and overrides become labels that `replay_diagnose`
   scores against.
3. **No-model path:** test that it gives `escalate_to_human` plus the deterministic report; add an
   ordered provider list only if outages occur.
4. **Cross-incident spend cap** in `bounds.blocked()`, plus a Bedrock application inference profile
   tagged for Cost Explorer, with AWS Budgets as the backstop.
5. **Approver identity in the actor session:** session tag `approver=<principal>` alongside
   `SourceIdentity=inc-<id>`.
6. **AI-incident runbook** following CoSAI v1.0.
7. **Supply chain:** `--require-hashes` lock; `cyclonedx-py` SBOM plus ML-BOM (Prompt Guard pinned to
   an HF revision); cosign keyless.
8. **Observe mode per policy:** "would have fired" for N runs, checked with `replay_gate.py`, before
   the policy takes effect.
9. **Compliance crosswalk:** NIST AI 600-1, ISO 42001 Annex A, OWASP ASI01–10, EU AI Act Articles
   9–15. Open question: whether Annex III point 2 (critical infrastructure) applies, which would
   bring high-risk obligations from 2027-12-02 (not legal advice).

**Not recommended:** an AI gateway, semantic caching, a sandbox, a hosted guardrail, a Cedar/OPA
rewrite, an MCP registry.

## Sources

- **Uber:** [GenAI Gateway](https://www.uber.com/us/en/blog/genai-gateway/) · [agent identity](https://www.uber.com/us/en/blog/solving-the-agent-identity-crisis/) · [software factory](https://www.uber.com/us/en/blog/efficient-software-factory/) · [MCP numbers (secondary)](https://aaif.io/blog/how-uber-runs-60000-ai-agent-tasks-per-week-with-mcp)
- **Stripe:** [AWS: lessons from Stripe](https://aws.amazon.com/blogs/machine-learning/production-grade-ai-agents-for-financial-compliance-lessons-from-stripe/) · [InfoQ](https://www.infoq.com/news/2026/03/stripe-autonomous-coding-agents/)
- **Shopify, LinkedIn, DoorDash:** [Shopify](https://shopify.engineering/building-production-ready-agentic-systems) · [LinkedIn](https://www.linkedin.com/blog/engineering/generative-ai/the-linkedin-generative-ai-application-tech-stack-extending-to-build-ai-agents) · [DoorDash](https://careersatdoordash.com/blog/doordash-simulation-evaluation-flywheel-to-develop-llm-chatbots-at-scale/)
- **Thoughtworks Radar:** [techniques](https://www.thoughtworks.com/radar/techniques) · [platforms](https://www.thoughtworks.com/radar/platforms) · [MCP by default](https://www.thoughtworks.com/radar/techniques/mcp-by-default)
- **Gateways and LiteLLM incident:** [Agent Router](https://theagentrouter.ai/docs/capabilities/) · [Envoy AI GW 1.0](https://tetrate.io/press/envoy-ai-gateway-reaches-v1-0-establishing-the-open-source-standard-for-enterprise-ai-traffic) · [LiteLLM security](https://docs.litellm.ai/blog/security-update-march-2026) · [PyPI incident](https://blog.pypi.org/posts/2026-04-02-incident-report-litellm-telnyx-supply-chain-attack/)
- **AWS:** [AgentCore Policy GA](https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available/) · [why Cedar](https://aws.amazon.com/blogs/security/why-policy-in-amazon-bedrock-agentcore-chose-cedar-for-securing-agentic-workflows/) · [inference profiles](https://docs.aws.amazon.com/bedrock/latest/userguide/inference-profiles.html) · [Automated Reasoning](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-automated-reasoning-checks.html)
- **Identity and flags:** [Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/what-is-microsoft-entra-agent-id) · [AgentControl](https://launchdarkly.com/docs/home/agentcontrol)
- **CoSAI and OWASP:** [CoSAI IR](https://github.com/cosai-oasis/ws2-defenders/blob/main/incident-response/AI-Incident-Response.md) · [CoSAI](https://www.coalitionforsecureai.org/) · [OWASP Agentic 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- **Model supply chain:** [model-transparency v1.0](https://blog.sigstore.dev/model-transparency-v1.0/) · [OpenSSF model signing](https://openssf.org/projects/model-signing/) · [CycloneDX ML-BOM](https://cyclonedx.org/capabilities/mlbom/)
- **Standards and regulation:** [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework) · [Anthropic ISO 42001](https://www.anthropic.com/news/anthropic-achieves-iso-42001-certification-for-responsible-ai) · [White & Case Omnibus](https://www.whitecase.com/insight-alert/eu-ai-omnibus-enters-force-amending-ai-act) · [Gibson Dunn](https://www.gibsondunn.com/eu-ai-act-omnibus-agreement-postponed-high-risk-deadlines-and-other-key-changes/) · [Orrick](https://www.orrick.com/en/Insights/2026/07/EU-AI-Act-Update-Digital-Omnibus-Finalizes-8-Compliance-Changes)
- **Other:** [sandbox comparison](https://amux.io/guides/ai-agent-sandboxing/) · [PyRIT](https://github.com/microsoft/PyRIT) · [Replit postmortem](https://swarmproof.github.io/agent-postmortems/2025-replit-prod-db-deletion/)

**Not covered** (search limit reached): Netflix, Spotify, Pinterest, Airbnb and Meta blogs; a16z;
SOC 2 AI criteria; ISO 42001 status at AWS, Microsoft and Google.
