# Open-source AI SRE agents, production remediation patterns, and WARDEN's gaps (as of 2026-09-28)

NOTE: plan mode was active for this research agent, so these notes are written to the plan file instead of
`...\scratchpad\research_notes\Production AI ops tooling 2026\sre_agents.md`. Copy them there verbatim.
No file in C:\work\warden was modified. The WARDEN baseline was read from README.md,
docs/PRODUCTION-ARCHITECTURE.md and docs/SYSTEM-COMPONENTS.md.

## Q1. Open-source AI SRE agents: HolmesGPT, k8sgpt, Keep, Robusta, others

### Takeaway
HolmesGPT is the leading OSS AI SRE agent. It is a CNCF Sandbox project under Apache-2.0, its latest release is 0.42.0 (2026-09-16), and it has 50+ integrations. It is a ReAct-style agent: read-only by default, with an opt-in Kubernetes write MCP that lets the model issue a broad allow-listed kubectl verb set behind one approval prompt. k8sgpt is a deterministic analyzer with LLM explanation (v0.4.39, 2026-09-14) and nothing write-side. Keep (acquired by Elastic) is the reference OSS alert-intake/AIOps layer. None of them has WARDEN's deterministic policy gate, closed action enum, digest-bound approval, verified redaction or signed audit. All of them have far more breadth, meaning integrations, runbooks, memory and topology, than WARDEN.

### Cited Findings
**HolmesGPT**
- Apache-2.0, "CNCF Sandbox Project", about 3.5k stars, 505 forks, 1,588 commits on master; 50+ integrations covering Prometheus, Datadog, Grafana, New Relic, Loki, AWS, Azure, GCP, AKS, ArgoCD, Crossplane, Helm, Kafka, RabbitMQ, PostgreSQL, MySQL, MongoDB, MariaDB, PagerDuty, OpsGenie, Jira, Slack and Teams — [GitHub HolmesGPT/holmesgpt](https://github.com/HolmesGPT/holmesgpt)
- The agentic loop queries live observability data. Large payloads are handled with server-side filtering and JSON tree traversal — [GitHub](https://github.com/HolmesGPT/holmesgpt)
- Runbooks: private runbooks and docs can be pulled from Confluence, Slab and public web sources — [GitHub](https://github.com/HolmesGPT/holmesgpt)
- Operator mode runs 24/7 and adds "deployment verification" and "scheduled health checks". Alerts can be read from and written back to AlertManager, PagerDuty, OpsGenie and Jira — [GitHub](https://github.com/HolmesGPT/holmesgpt)
- The project states: "By design, HolmesGPT has read-only access and respects RBAC permissions" — [GitHub](https://github.com/HolmesGPT/holmesgpt)
- Latest releases: 0.42.0 on 2026-09-16 (also 0.42.0-alpha the same day) and 0.41.0 on 2026-09-08. 0.42.0 adds GPU node diagnostics for Kubernetes remediation and "stricter RBAC security defaults for namespace-scoped installations" — [GitHub releases API](https://api.github.com/repos/HolmesGPT/holmesgpt/releases?per_page=3)
- **Kubernetes Remediation MCP (write path):**
  - Write operations: restart/delete pods, scale, patch/update, drain/cordon, labels/annotations/taints, and creating jobs.
  - Verb allow-list: `KUBECTL_ALLOWED_COMMANDS: 'edit,patch,delete,scale,rollout,cordon,uncordon,drain,taint,label,annotate,run,exec'`.
  - Approval: only `run_kubectl_command` requires human approval (`approval_required_tools`).
  - RBAC: a scoped ClusterRole with delete on workloads, `pods/exec`, patch on nodes and full CRUD on batch jobs, no secrets.
  - Guards: `--kubeconfig/--context/--token/--as` are blocked, shell metacharacters are rejected, and commands time out after 60 s.
  - `allowArbitraryKubectlCommands: false` disables mutations.
  - The doc describes no audit log, rollback or post-execution verification — [HolmesGPT docs](https://holmesgpt.dev/latest/data-sources/builtin-toolsets/kubernetes-remediation-mcp/)
- The default Helm values set `approvalRequiredTools: - "*"`, so every tool needs confirmation (search snippet, file not fetched) — [values.yaml](https://github.com/HolmesGPT/holmesgpt/blob/master/helm/holmes/values.yaml)
- Maintained by Robusta and Microsoft. CNCF Sandbox since October 2025. In Operator mode it can open GitHub PRs with suggested fixes. This source is written by the Aurora vendor, so it has a vendor bias — [dev.to (Arvo AI)](https://dev.to/siddharth_singh_409bd5267/open-source-ai-sre-aurora-vs-holmesgpt-vs-k8sgpt-2026-5g26)
- The CNCF blog, 2026-04-21: "Auto-diagnosing Kubernetes alerts with HolmesGPT and CNCF tools" (title only; not fetched) — [CNCF](https://www.cncf.io/blog/2026/04/21/auto-diagnosing-kubernetes-alerts-with-holmesgpt-and-cncf-tools/)

**k8sgpt**
- Apache-2.0. 14 default analyzers (Pod, PVC, ReplicaSet, Service, Event, Ingress, StatefulSet, Deployment, Job, CronJob, Node, webhooks, ConfigMap) plus 24 optional ones (HPA, NetworkPolicy, storage and others). A separate k8sgpt-operator does continuous monitoring. The MCP server exposes 12 tools, 3 resources and 3 prompts. It supports 15+ AI backends (OpenAI, Azure, Bedrock, Gemini, Ollama, LiteLLM and more) — [GitHub k8sgpt](https://github.com/k8sgpt-ai/k8sgpt)
- Anonymisation covers 9 analyzers only. "events and pod logs remain unmasked" — [GitHub k8sgpt](https://github.com/k8sgpt-ai/k8sgpt)
- v0.4.39 was released on 2026-09-14 and added `--resource` (analyze one resource) and a ValidatingAdmissionPolicy analyzer. v0.4.38 came 2026-09-01 and v0.4.37 on 2026-08-27 — [releases API](https://api.github.com/repos/k8sgpt-ai/k8sgpt/releases?per_page=3)
- "Strictly read-only", deterministic analysis runs before the LLM, Kubernetes-only (vendor-biased source) — [dev.to (Arvo AI)](https://dev.to/siddharth_singh_409bd5267/open-source-ai-sre-aurora-vs-holmesgpt-vs-k8sgpt-2026-5g26)

**Keep**
- "The open-source AIOps and alert management platform". About 12.4k stars, not archived, last push 2026-09-28. The GitHub API reports the licence as `NOASSERTION` — [GitHub API](https://api.github.com/repos/keephq/keep)
- Features: deduplication, correlation, enrichment, workflows ("GitHub Actions for your monitoring tools") and AI correlation/summarisation. It connects to 7 AI backends, 44+ observability tools, 15 incident-management tools and 12 ticketing tools — [GitHub keep](https://github.com/keephq/keep)
- Elastic acquired Keep, and Keep "will ... remain open source". Its workflow engine "automates the remediation of incidents with workflow-as-code" — [Elastic blog](https://www.elastic.co/blog/elastic-and-keep-join-forces); [APMdigest](https://www.apmdigest.com/elastic-completes-acquisition-keep)

**Robusta**
- Robusta OSS is "and always will be free. It is MIT licensed." The Robusta Platform (SaaS or self-hosted) is the paid control plane for triage and investigation timelines. The OSS engine ("Robusta Classic") runs rule-based playbooks that enrich alerts and route them to sinks — [Robusta docs OSS vs SaaS](https://docs.robusta.dev/master/how-it-works/oss-vs-saas.html) (via search snippet)

**Other 2025–2026 OSS agents**
- Aurora (Arvo AI): Apache-2.0, 201 stars, v1.1.1 (March 2026). LangGraph supervisor, multi-cloud, Memgraph dependency graph, remediation PRs, and approval gates for destructive actions (the author works for the vendor) — [dev.to](https://dev.to/siddharth_singh_409bd5267/open-source-ai-sre-aurora-vs-holmesgpt-vs-k8sgpt-2026-5g26)
- OpenSRE (swapnildahiphale/OpenSRE): automated investigation with episodic memory and a Neo4j knowledge graph that "remembers what it learned for next time" — [GitHub discussion](https://github.com/swapnildahiphale/OpenSRE/discussions/5) (search snippet; licence and maturity not verified)
- AURA (Mezmo): Apache-2.0, 125 stars, "breaking changes in April 2026"; an agentic harness. Mezmo's four autonomy tiers are read-only, advised, approved, and autonomous-with-rollback-and-audit. "Irreversibility is the formal trigger for mandatory human-in-the-loop" — [Mezmo](https://www.mezmo.com/learn/open-source-ai-sre-tools) (vendor page)

### Inferences
- **HolmesGPT vs WARDEN.**
  - HolmesGPT has more breadth: about 12x WARDEN's evidence sources, runbook retrieval, an always-on operator, PagerDuty/Jira round-trip and PR-based fixes.
  - WARDEN has a stronger safety model:
    - Holmes's write path lets the model choose from about 13 kubectl verbs, including `delete`, `drain` and `exec`, with one human prompt and no documented policy engine, digest binding, own success check, rollback or signed audit.
    - WARDEN's closed 14-action enum, its 12–15 deterministic policies, the approval bound to a plan hash, and its apply-once, verify and rollback steps have no equivalent in any OSS project reviewed.
- **Reuse recommendation.** Do not adopt Holmes as the brain; that would reintroduce "the model chooses what to look at". Two reuse options are worth evaluating:
  1. Call HolmesGPT toolsets or MCP servers as fixed, deterministic read steps chosen by WARDEN, not by the model, to widen evidence cheaply (Prometheus, Loki, Datadog, RDS). This needs verification that toolsets can be invoked outside the agent loop.
  2. Run k8sgpt analyzers (`analyze` without `--explain`) as extra deterministic detectors feeding WARDEN evidence ids. They are Apache-2.0 and free, and they overlap WARDEN's 34 signatures.
- **Redaction.** k8sgpt masks only 9 analyzers and leaves events and logs unmasked. WARDEN's verified redaction with a re-scan is a real differentiator.
- **Alert intake.** Keep or Alertmanager, not WARDEN code, should handle intake dedup and correlation (see Q4).

### Gaps
- Keep's exact licence split: the API says NOASSERTION. Historically MIT with a separately licensed `ee/` directory, but not verified here. The Elastic acquisition date was not confirmed on the source; likely May 2025 (unverified).
- k8sgpt's CNCF status: not stated on the README fetched. I believe it is CNCF Sandbox (2023), but this is unverified. Whether k8sgpt-operator's experimental auto-remediation still exists was not verified.
- HolmesGPT's date of CNCF Sandbox acceptance comes only from a vendor-biased secondary source.
- OpenSRE's licence, release and activity were not verified.

## Q2. Commercial AI SRE products (all PAID): architecture, gating, metrics

### Takeaway
Every major commercial agent checked investigates autonomously and gates writes behind human approval. Azure SRE Agent allows autonomy only inside a pre-defined incident response plan. The advertised metrics are MTTR and investigation time plus a claimed "root cause accuracy". None of these is independently verified.

### Cited Findings
- **AWS DevOps Agent (PAID, billed per second of agent time).**
  - Went GA on 2026-03-31. It builds a topology from metrics, logs and code, and uses "learned skills" and "custom skills".
  - It proposes mitigation plans and code-level fixes.
  - Claims up to "75% lower MTTR, 80% faster investigations, and 94% root cause accuracy". Customer examples: WGU 2 h to 28 min (77%); Zenchef 75% less investigation time.
  - Integrations: Datadog, Dynatrace, New Relic, Splunk, GitHub, GitLab, ServiceNow, Slack, PagerDuty and Grafana — [AWS blog](https://aws.amazon.com/blogs/mt/announcing-general-availability-of-aws-devops-agent/)
  - A third-party analysis says it "still can't deploy the fix". Per that analysis, a safe fix needs per-agent identity, action-scoped credentials, approval gates per action class, an append-only audit and reversible, verifiable primitives — [bex.co](https://bex.co/blog/2026/08/06/aws-devops-agent-diagnose-not-act-line) (snippet only); [InfoQ](https://www.infoq.com/news/2026/04/aws-devops-agent-ga/)
- **Azure SRE Agent (PAID, Preview).**
  - Review mode is the default: the agent writes an execution plan and waits for consent before write actions.
  - Autonomous mode "can only [be enabled] in the context of an incident management plan".
  - Guidance: start in Review and switch once confident in its tool selection — [Microsoft Learn run modes](https://learn.microsoft.com/en-us/azure/sre-agent/agent-run-modes); [incident response plans](https://learn.microsoft.com/en-us/azure/sre-agent/incident-response-plans)
- **Traversal, Cleric, Resolve.ai (PAID)**, from a comparison site, not primary sources:
  - Traversal: causal ML "Production World Model"; claims 90%+ RCA accuracy in 2–4 min; approval-gated remediation; on-prem option.
  - Cleric: hypothesis trees with semantic, episodic and procedural memory; read-only; does not execute.
  - Resolve.ai: targets "80% autonomous resolution"; valued at $1B (Dec 2025) — [wetheflywheel comparison](https://wetheflywheel.com/en/comparisons/cleric-vs-resolve-ai-vs-traversal/) (search snippet)
- Cleric publishes a "State of AI SRE" report (not fetched) — [Cleric](https://cleric.ai/resources/reports/the-state-of-ai-sre)

### Inferences
- WARDEN's per-environment auto-remediate flag matches Azure's two modes, Review by default and Autonomous only inside a plan. WARDEN is stricter: prod never auto-applies.
- What WARDEN lacks here:
  - A named, per-alert-type response plan that scopes autonomy (Azure's incident response plans).
  - Learned or custom "skills" (AWS).
  - Topology discovery (AWS, Traversal).
  - Memory of past incidents (Cleric).
- The bex.co checklist of per-agent identity, action-scoped credentials, per-action-class approval, append-only audit and reversible verifiable primitives maps almost one-to-one onto WARDEN's Phase 2/4 design: the actor role with a session policy of exact ARNs, the signed hash-chained audit, and the closed catalogue with its own success check and rollback. That is independent support for WARDEN's design.

### Gaps
- PagerDuty, incident.io and Datadog Bits AI agent architectures and approval patterns were not researched (budget).
- The accuracy and MTTR figures are vendor claims with no public methodology.

## Q3. Published reference architectures and engineering results from companies

### Takeaway
Meta is the best-documented case. It runs deterministic, code-reviewed, backtested "analyzers as code" (DrP) triggered by alerts at 50k analyses a day. Its LLM RCA deliberately trades reach for precision using confidence thresholds. Its automated actions are mostly tasks or PRs, not direct mutation. Academic work shows that LLM AIOps agents can be steered by crafted telemetry, which is what WARDEN's quarantine and gate defend against.

### Cited Findings
- **Meta DrP:**
  - Engineers write "analyzers as code" with an SDK and helper ML (anomaly detection, event isolation, time-series correlation, dimension analysis).
  - Analyzers are triggered automatically by alerts and get "automated backtesting integrated into code review tools".
  - Post-processing "can create tasks or pull requests to mitigate issues".
  - Scale: 300+ teams, 50,000 analyses a day, 2,000 analyzers, 20–80% MTTR reduction, in production for 5+ years. No failures were reported — [Engineering at Meta, 2025-12-19](https://engineering.fb.com/2025/12/19/data-infrastructure/drp-metas-root-cause-analysis-platform-at-scale/)
- **Meta's LLM-assisted RCA:**
  - Heuristic retrieval, then LLM ranking with a fine-tuned Llama 2 7B.
  - "42% accuracy" at investigation-creation time for web-monorepo investigations.
  - Meta uses confidence measurement "to detect low confidence answers and avoid recommending them ... sacrificing reach in favor of precision". Results must be reproducible by responders — [Engineering at Meta, 2024-06-24](https://engineering.fb.com/2024/06/24/data-infrastructure/leveraging-ai-for-efficient-incident-response/) (via search snippet)
- **AIOpsLab (Microsoft Research):** a framework and benchmark that puts agents in live DeathStarBench microservices. The search snippet cites 114 problems — [arXiv 2501.06706](https://arxiv.org/pdf/2501.06706)
- **AIOpsDoom attack:**
  - Crafted telemetry that plants a "plausible but incorrect root cause with suggested fixes" reached "an average success rate of 90%" against ReAct and Flash agents on GPT-4o/4.1.
  - Plain prompt injection got 0%.
  - The AIOpsShield defence templatises untrusted telemetry fields into abstract identifiers; with it, "none of the attacks result in success" — [arXiv 2508.06394](https://arxiv.org/html/2508.06394v2)
- SOCpilot, "Verifying Policy Compliance for LLM-Assisted Incident Response", is a similar verifier-over-LLM pattern (title only; not read) — [arXiv 2605.05501](https://arxiv.org/pdf/2605.05501)
- A 2026 multi-dataset benchmark for LLM agents in microservice failure diagnosis exists (not read) — [arXiv 2606.29193](https://arxiv.org/html/2606.29193v1)

### Inferences
- Meta's pattern is deterministic analyzers, backtested in review, triggered by alerts, with actions emitted as tasks or PRs and LLM output shown only above a confidence threshold. WARDEN matches this closely: deterministic detectors, the replay tool, P4 plus the planned Phase 3 calibration, and approval before any change.
- WARDEN is missing three things from Meta's pattern:
  1. **Remediation as a PR/GitOps change.** WARDEN patches Deployments directly. On an ArgoCD or Flux-managed cluster the patch would be reverted or cause drift. Meta, HolmesGPT and Aurora all emit PRs.
  2. **Backtesting new signatures and policies in CI** against the recorded corpus, as a merge gate, not an ad-hoc script.
  3. **Measured reach.** WARDEN should publish what fraction of incidents it answers versus escalates, alongside precision.
- AIOpsDoom's attack is exactly the "confident plausible fix" failure named in WARDEN's README. WARDEN's typed-fact quarantine plus the gate is structurally the AIOpsShield defence. WARDEN should add the AIOpsDoom payload style ("reward-hacking" fake root cause plus fix) to its 14-family injection corpus, because the Prompt Guard tripwire would likely miss it (it missed forged config lines).

### Gaps
- No primary 2024–2026 posts were found on automated remediation with blast-radius controls from Google, LinkedIn, Uber or Netflix; the search returned only blog indexes.
- Microsoft RCACopilot (EuroSys 2024) numbers were not re-verified in this session.
- No company published a false-action rate for automated remediation in the sources read.

## Q4. Alert intake best practice: dedup, correlation, storms, flapping

### Takeaway
The standard OSS approach is to deduplicate and group upstream of any agent: Alertmanager grouping, inhibition and silences, or Keep fingerprint dedup and correlation. Flapping is handled at the rule level (`for` / `keep_firing_for`), not in the responder. WARDEN has only workflow-id dedup (`inc-<alert_id>`) in its intake design.

### Cited Findings
- Alertmanager "takes care of deduplicating, grouping, and routing". "Grouping categorizes alerts of similar nature into a single notification". Inhibition can "mute all other alerts concerning this cluster if that particular alert is firing". Silences use equality or regex matchers — [Prometheus Alertmanager docs](https://prometheus.io/docs/alerting/latest/alertmanager/)
- Keep dedup:
  - Partial (default): a fingerprint over chosen fields, with per-provider pre-built rules.
  - Full: identical except "ignore fields", such as the timestamp.
  - Order: ingest, then enrich, then dedup — [Keep docs](https://docs.keephq.dev/overview/deduplication)
- Azure SRE Agent advertises "intelligent merging" of Azure Monitor alerts (title only) — [Microsoft Tech Community](https://techcommunity.microsoft.com/blog/appsonazureblog/azure-monitor-in-azure-sre-agent-autonomous-alert-investigation-and-intelligent-/4509069)
- The AWS DevOps Agent triage agent "automatically detects duplicates and links tickets" — [AWS blog](https://aws.amazon.com/blogs/mt/announcing-general-availability-of-aws-devops-agent/)

### Inferences
- **What WARDEN lacks at intake:**
  - Fingerprint dedup across sources: a CloudWatch alarm and a Prometheus alert for the same service are separate IDs today.
  - A grouping window, so an alarm storm is one incident.
  - Inhibition: suppress child alerts when the cluster or database alert fires.
  - Silences and maintenance windows, so no diagnosis or remediation runs during a planned change.
  - Flap hysteresis: do not remediate a flapping alert, and do not re-run a closed workflow on re-fire within N minutes.
  - A cool-down or rate limit on repeated remediation of the same target.
- **Cheapest fix (free):** put Alertmanager in front for EKS, and rely on CloudWatch alarm M-of-N evaluation (`DatapointsToAlarm`) plus composite alarms for ECS/RDS. WARDEN then needs only:
  1. a stable fingerprint as the workflow id;
  2. Temporal signal-with-start to join duplicates;
  3. a per-target remediation cool-down enforced by the gate as a new policy.
- Keep is optional if multi-source correlation is needed later.

### Gaps
- The Alertmanager page did not render `group_wait`, `group_interval`, `repeat_interval`, HA gossip dedup or `keep_firing_for`; those details come from memory, not re-verified.
- Grafana alerting's grouping and flap behaviour was not fetched.
- Keep's correlation-rule and storm docs were not fetched.

## Consolidated list: what WARDEN lacks (with evidence pointer)
1. **Alert intake hygiene.** Missing: fingerprint dedup, grouping window, inhibition, silences and maintenance windows, flap hysteresis, and per-target remediation cool-down (Q4).
2. **Evidence breadth.** WARDEN has 4 backend families. HolmesGPT has 50+ (Prometheus queries, Loki, traces, Datadog, RDS Performance Insights and DB logs). Candidate: fixed-plan reuse of Holmes toolsets or MCP (Q1).
3. **Adaptive investigation.** WARDEN is single-shot by design. When the fixed evidence misses the cause (its RDS wave: "wrong where it could only count it"), there is no second read. Option: a bounded second round chosen from a closed read catalogue by deterministic rules, not by the model (inference).
4. **Runbook and knowledge retrieval, and incident memory.** HolmesGPT pulls Confluence runbooks. OpenSRE, Cleric and AWS use episodic memory or learned skills. WARDEN has only 34 static YAML signatures (Q1, Q2).
5. **Service topology / dependency graph.** AWS DevOps Agent, Aurora, OpenSRE and Traversal have one. WARDEN's P6 blast radius comes from its action table, not topology (Q1, Q2).
6. **Change correlation.** WARDEN's change timeline is still planned. AWS DevOps Agent and Meta treat recent deploys and changes as first-class evidence (Q2, Q3).
7. **GitOps/PR remediation path.** WARDEN patches directly, which conflicts with ArgoCD/Flux. Meta DrP, HolmesGPT and Aurora emit PRs (Q3).
8. **Pre-scoped response plans.** Azure-style incident response plans that grant autonomy per alert type. WARDEN scopes autonomy per environment only (Q2).
9. **Shadow mode and measured reach/precision/MTTR on real incidents.** The shadow mode is planned for Phase 3. Meta measures precision versus reach; vendors publish MTTR. WARDEN's benchmark uses injected faults only (Q2, Q3).
10. **Responder feedback loop.** Meta and DrP close the loop on responder feedback. WARDEN has no thumbs up/down or post-incident label feeding calibration (Q3).
11. **Ticketing and paging round-trip.** HolmesGPT and Keep support PagerDuty, Opsgenie and Jira. WARDEN has only Slack or a webhook (Q1).
12. **Continuous or scheduled health checks.** The Holmes operator and k8sgpt-operator provide these. WARDEN is alert-triggered only (Q1).
13. **Injection corpus coverage of AIOpsDoom-style "reward-hacking" telemetry** (Q3).

## What WARDEN has that the reviewed OSS agents lack
- A deterministic, explainable policy gate with policy ids.
- A closed action enum. HolmesGPT allows about 13 kubectl verbs, including delete, drain and exec.
- Approval bound to a plan digest.
- Apply-once, own success check and rollback.
- Verified two-pass redaction. k8sgpt leaves events and logs unmasked.
- Typed-fact quarantine, the AIOpsShield-style defence.
- A token/USD budget.
- An Ed25519 hash-chained audit.
- A test asserting IAM policy equals code.
- A public benchmark that includes its own failures.

Sources: see the inline links in each section.
