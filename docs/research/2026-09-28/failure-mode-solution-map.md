# Failure mode → every solution (research, 2026-09-28)

**Tags:** [V] = verified this session; [U] = prior knowledge, unverified.
**WARDEN status:** USE = in use; PLAN/OPT = planned or optional in SYSTEM-COMPONENTS; H/M/L = new and
of high, medium or low relevance; n/a = not applicable.

## Source lists

- **OWASP Agentic Top 10 (2025-12-09)** [V]:
  - ASI01 Goal Hijack · ASI02 Tool Misuse · ASI03 Identity & Privilege Abuse · ASI04 Supply Chain · ASI05 Unexpected Code Execution
  - ASI06 Memory & Context Poisoning · ASI07 Insecure Inter-Agent Comms · ASI08 Cascading Failures · ASI09 Human-Agent Trust Exploitation · ASI10 Rogue Agents
  - Sources: [OWASP](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/), [Modulos mapping](https://docs.modulos.ai/frameworks/owasp-top-10-agentic)
- **OWASP LLM Top 10 2026 (2026-08-03)** [V]:
  - LLM01 Prompt Injection · 02 Sensitive Info Disclosure · 03 Excessive Agency · 04 Supply Chain · 05 Data/Model Poisoning
  - 06 Unbounded Consumption · 07 Misinformation · 08 Hidden Context Exposure · 09 Vector/Embedding · 10 Improper Output Handling
  - Sources: [OWASP](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/), [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-owasp-genai-top10-2026-agent-control-stand/)
- **OWASP Agentic Threats & Mitigations v1.0** (2025-02-17): only the landing page was read ([link](https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)).
- **MITRE ATLAS:**
  - v5.1 has 16 tactics and about 170 techniques.
  - Zenity added 14 agent techniques in Oct 2025 (context poisoning, memory manipulation, tool credential harvesting, clickbait).
  - v5.4 (Feb 2026) added "Publish Poisoned AI Agent Tool" and "Escape to Host".
  - Sources: [Zenity](https://zenity.io/blog/current-events/mitre-atlas-ai-security), [CSA gap](https://labs.cloudsecurityalliance.org/agentic/csa-research-note-atlas-agentic-gap-analysis-20260327/)
- **MAST, NeurIPS 2025** ([arXiv 2503.13657](https://arxiv.org/abs/2503.13657), [repo](https://github.com/multi-agent-systems-failure-taxonomy/MAST)):
  - FM-1 system design: 1.1–1.5
  - FM-2 inter-agent: 2.1–2.6
  - FM-3 verification: 3.1–3.3
  - Includes the MAD dataset and an LLM-judge notebook.

## Cross-cutting finding

**"The Attacker Moves Second"** ([arXiv 2510.09023](https://arxiv.org/abs/2510.09023)): adaptive attacks
broke 12 defences at 71–100% success, and human red-teamers reached 100%.

**Meta's Agents Rule of Two** ([summary](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)):
an agent should have at most two of [A] untrusted input, [B] sensitive data, [C] the ability to change
state or communicate externally. With all three, a human must approve.

WARDEN has A and B, and reaches C only through signed approval. That fits the rule. Detectors act as
tripwires only.

## Solutions per failure mode (condensed)

1. **Goal hijack / prompt injection**
   - Architecture (USE): dual-LLM / plan-then-execute ([2506.08837](https://arxiv.org/abs/2506.08837)).
   - Research defences:
     - CaMeL ([repo](https://github.com/google-research/camel-prompt-injection)): M, reference.
     - FIDES ([2505.23643](https://arxiv.org/abs/2505.23643), [MS blog](https://devblogs.microsoft.com/agent-framework/fides/)): L.
     - Progent, AgentArmor, MELON, PFI, RTBAS, AirGapAgent: L.
   - Spotlighting ([2403.14720](https://arxiv.org/abs/2403.14720)): M.
   - Meta SecAlign-8B/70B ([HF](https://huggingface.co/facebook/Meta-SecAlign-8B), [repo](https://github.com/facebookresearch/Meta_SecAlign)): M, local model option.
   - Detectors:
     - Prompt Guard 2: OPT.
     - PIGuard + NotInject ([repo](https://github.com/leolee99/PIGuard)): OPT.
     - ProtectAI deberta: L.
     - LlamaFirewall ([2505.03574](https://arxiv.org/abs/2505.03574)): M.
     - NeMo ([repo](https://github.com/NVIDIA/NeMo-Guardrails)): L.
   - Guard models (Qwen3Guard, Granite Guardian 4.1, Nemotron, GLiGuard, ToolSafe, WildGuard, ShieldGemma): L.
   - Benchmarks: AgentDojo, InjecAgent, WASP, ASB.
   - Red-team tools: garak, PyRIT, promptfoo, DeepTeam (has an `OWASP_ASI_2026` mapping).
   - **Unsolved:** adaptive attackers; only architecture holds.
2. **Tool misuse / excessive agency**
   - Closed action set plus deterministic gate: USE.
   - **Kubernetes ValidatingAdmissionPolicy / Kyverno / Gatekeeper enforcing clamps on the server side: H**.
   - Microsoft Agent Governance Toolkit ([repo](https://github.com/microsoft/agent-governance-toolkit), MIT, preview): M, reference.
   - Cedar / OPA: M.
   - agentgateway: L.
   - Invariant ([repo](https://github.com/invariantlabs-ai/invariant)): L.
   - **Tenuo warrants** ([repo](https://github.com/tenuo-ai/tenuo), Apache-2.0, Temporal integration): **H**.
   - **Unsolved:** semantic misuse of an allowed action (e.g. scale_up on OOM).
3. **Identity**
   - STS, OIDC, boundaries: USE.
   - SPIFFE: M.
   - Tenuo: H.
4. **Supply chain**
   - pip-audit, Dependabot, pinned SHAs: USE.
   - Hash locks: PLAN.
   - **OpenSSF model-signing** ([repo](https://github.com/sigstore/model-transparency)): M.
   - **ModelAudit** ([repo](https://github.com/promptfoo/modelaudit)): M.
   - fickling, modelscan, safetensors-only loading: M.
   - **Syft, Grype, OSV-Scanner, cosign, SLSA: H**.
   - CycloneDX ML-BOM; OWASP ACS AgBOM ([repo](https://github.com/GenAI-Security-Project/agent-control-standard); v0.1 fails open): L–M.
   - Snyk Agent Scan (sends data out): L.
   - **Cisco mcp-scanner offline** ([repo](https://github.com/cisco-ai-defense/mcp-scanner)): M.
   - Slopsquatting: 5.2% / 21.7% hallucinated packages ([2406.10279](https://arxiv.org/abs/2406.10279)).
5. **Code execution / output handling**
   - Pydantic, closed enum, sink encoding: USE.
   - **Anthropic sandbox-runtime** ([repo](https://github.com/anthropic-experimental/sandbox-runtime)) around the `claude_cli` subprocess: **H**.
6. **Memory poisoning**
   - OWASP Agent Memory Guard ([repo](https://github.com/OWASP/www-project-agent-memory-guard)): L.
   - A-MemGuard (NC licence): n/a.
   - Knowledge base is human-edited: USE.
7. **Inter-agent communication**
   - A2A cards, agentgateway A2A: n/a for WARDEN.
   - Temporal mTLS (S15): PLAN.
8. **Cascading failures**
   - Breaker, kill switch, bounds: USE.
   - **MAST annotator**: M.
   - Who&When ([repo](https://github.com/mingyin1/Agents_Failure_Attribution)): L.
   - **Chaos testing WARDEN itself (FIS / Chaos Mesh / Litmus): H**.
9. **Human trust / approval fatigue**
   - Structural safety (Anthropic's sandbox cut permission prompts by 84%; [link](https://www.anthropic.com/engineering/claude-code-sandboxing)): USE.
   - Typed target and latency metric: PLAN.
   - **Catch trials (seeded bad proposals): H**.
   - Showing counter-evidence: M.
10. **Rogue agents**
    - Kill switch, OTel: USE.
    - **ControlArena** ([repo](https://github.com/UKGovernmentBEIS/control-arena), MIT): **H**.
    - **Petri v3** ([repo](https://github.com/safety-research/petri), MIT): **H**.
    - CoT monitoring ([2503.11926](https://arxiv.org/abs/2503.11926)): M.
    - Persona vectors: n/a.
11. **Exfiltration and secret leaks**
    - Redaction and gate: USE.
    - Presidio: OPT.
    - **Kingfisher** ([repo](https://github.com/mongodb/kingfisher)): M–H.
    - gitleaks: OPT.
    - Egress allowlist via sandbox-runtime: H.
    - Payload codec: PLAN.
    - AgentLeak: L.
12. **Hidden context exposure:** L; the prompts are already public.
13. **Hallucination**
    - Evidence IDs, P13–P15: USE.
    - HHEM-2.1-Open ([HF](https://huggingface.co/vectara/hallucination_evaluation_model)): OPT.
    - **MiniCheck** ([repo](https://github.com/Liyan06/MiniCheck)): M–H.
    - **LettuceDetect** ([repo](https://github.com/KRLabsOrg/LettuceDetect), MIT, span-level): M–H.
    - Granite Guardian 4.1 ([repo](https://github.com/ibm-granite/granite-guardian)): M.
    - **Unsolved:** numeric/unit claims, claims of absence, log-shaped evidence.
14. **False completion**
    - Positive success signals: PLAN.
    - Independent verifier: USE.
    - Healthy controls, i.e. ImpossibleBench ([2510.20270](https://arxiv.org/abs/2510.20270)): USE.
15. **Reward hacking**
    - METR ([Jun 2025](https://metr.org/blog/2025-06-05-recent-reward-hacking/)): o3 30.4%; "please don't cheat" had no effect.
    - Anthropic ([Nov 2025](https://www.anthropic.com/research/emergent-misalignment-reward-hacking)): reward hacking generalises.
    - Controls: the gate decides; the grader stays hidden.
16. **Sycophancy**
    - SycEval ([2502.08177](https://arxiv.org/abs/2502.08177)): 58%.
    - **Blind diagnosis (keep the human hypothesis out of the prompt): H**.
    - Petri: M.
17. **Model drift**
    - Chen et al. ([2307.09009](https://arxiv.org/abs/2307.09009)).
    - Pinned ids and a replay gate: PLAN.
    - Inspect AI ([inspect_evals](https://github.com/UKGovernmentBEIS/inspect_evals)): PLAN.
18. **Cost runaway**
    - Own USD/call caps: USE.
    - LiteLLM budgets need Postgres, and per-model budgets are Enterprise only: L.
    - Daily cap in own code.
19. **Non-determinism**
    - pass^k (τ-bench, [2406.12045](https://arxiv.org/abs/2406.12045)): PLAN.
    - Batch-invariant kernels ([blog](https://thinkingmachines.ai/blog/defeating-nondeterminism-in-llm-inference/)): L, self-hosted models only.
20. **Calibration**
    - **UQLM** ([repo](https://github.com/cvs-health/uqlm), Apache-2.0): **H**.
    - LM-Polygraph ([repo](https://github.com/IINemo/lm-polygraph)): M.
    - **Conformal factuality** ([2402.10978](https://arxiv.org/abs/2402.10978)): M–H.
    - "Why LMs hallucinate" ([2509.04664](https://arxiv.org/abs/2509.04664)): USE in spirit.
21. **Over-refusal**
    - OR-Bench ([repo](https://github.com/justincui03/or-bench)): M.
    - **NotInject**: M–H, to measure tripwire false positives.

## Top 20 WARDEN is not using yet

1. k8s ValidatingAdmissionPolicy / Kyverno clamps
2. Anthropic sandbox-runtime around `claude_cli`
3. UQLM consistency
4. Blind diagnosis
5. Catch trials
6. Tenuo warrants
7. ControlArena
8. Petri v3
9. MiniCheck / LettuceDetect
10. Conformal abstention
11. Chaos testing of WARDEN
12. Syft, Grype/OSV, cosign/attestations
13. OpenSSF model-signing + ModelAudit
14. Kingfisher
15. NotInject + benign-but-scary set
16. Cisco mcp-scanner (offline)
17. Granite Guardian 4.1 (or #9)
18. Meta SecAlign-8B
19. MAST annotator
20. OWASP ACS AgBOM + OCSF (wait for v0.2)

**Skip:** LiteLLM/agentgateway budgets, NeMo, Guardrails AI, CaMeL/FIDES (WARDEN is already
stricter), memory guards, batch-invariant kernels.

**Reference only:** Microsoft Agent Governance Toolkit.
