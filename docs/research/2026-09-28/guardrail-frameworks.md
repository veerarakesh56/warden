# Open-source agent security and guardrail frameworks (state as of 2026-09-28) - for WARDEN

Note: plan mode was active, so these notes are saved here, not at the requested scratchpad path
(`...\scratchpad\research_notes\Production AI ops tooling 2026\guardrails.md`). Copy them there when
plan mode ends. Nothing in C:\work\warden was modified.

WARDEN context read: README.md (injection tripwire section), docs/ai-boundary.md, docs/SYSTEM-COMPONENTS.md §3-4.
WARDEN today: one model call per incident, model cannot choose tools or evidence, closed action enum,
deterministic gate P1-P16, quarantine (untrusted log/event/SQL text -> typed facts, never raw text),
citations checked (P13/P15), target must exist in evidence (P14), outbound gate G2/G3/G5, Prompt Guard 2
86M tripwire (P16), signed digest approval before any change, dry-run default.

## Meta LlamaFirewall: version, components, licence, AlignmentCheck, results, cost, integration

### Takeaway
LlamaFirewall is PromptGuard 2 + AlignmentCheck (an LLM auditing the agent's trace) + CodeShield (static
analysis of generated code) + regex scanners; the PyPI package has not been released since 1.0.3 (29 May
2025). WARDEN already runs its only CPU-cheap part (PromptGuard 2) directly. AlignmentCheck needs a
frontier-size model (Llama 4 Maverick / Llama 3.3 70B) behind an API, and it guards multi-step tool-using
agents, which WARDEN is not. Recommendation: **skip the package, keep PG2 direct, skip AlignmentCheck and CodeShield.**

### Cited Findings
- Latest PyPI release is 1.0.3 (May 29, 2025); history runs 0.0.0 (Apr 23, 2025) to 1.0.3; requires Python >=3.10; licence not shown on PyPI — [PyPI llamafirewall](https://pypi.org/project/llamafirewall/)
- PurpleLlama GitHub has no GitHub Releases at all (versions only on PyPI) — [PurpleLlama releases](https://github.com/meta-llama/PurpleLlama/releases)
- Components: PromptGuard 2 ("fast, lightweight BERT-style classifier that detects direct prompt injection attempts"), AlignmentCheck ("audits agent reasoning ... chain-of-thought analysis to identify goal hijacking"), CodeShield (static analysis of LLM-generated code, 8 languages, Semgrep + regex), Regex & custom scanners. API: scanners bound to roles (USER, ASSISTANT); `scan()` per message returns ScanResult (decision, reason, score); `scan_replay()` for a whole trace — [PyPI llamafirewall](https://pypi.org/project/llamafirewall/)
- AlignmentCheck setup requires a Together API key (`TOGETHER_API_KEY`) plus access to Meta Llama models on Hugging Face — [PyPI llamafirewall](https://pypi.org/project/llamafirewall/); [LlamaFirewall README](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall)
- AlignmentCheck mechanism (from source): extracts the user's original goal from the trace, formats the agent trace, asks an LLM for structured {observation, thought, conclusion}; conclusion True (misaligned) -> score 1.0 and decision `HUMAN_IN_THE_LOOP_REQUIRED`, else ALLOW. Docstring references configurable `model_name`, `api_base_url`, `api_key_env_var` via parent `CustomCheckScanner` — so an OpenAI-compatible local endpoint may be possible (**unverified**, defaults not in that file) — [alignmentcheck_scanner.py](https://raw.githubusercontent.com/meta-llama/PurpleLlama/main/LlamaFirewall/src/llamafirewall/scanners/experimental/alignmentcheck_scanner.py)
- AgentDojo results in the paper: no defence ASR 17.63% / utility 47.73%; PromptGuard 2 86M ASR 7.53% / utility 47.01%; AlignmentCheck (Llama 4 Maverick) ASR 2.89% / utility 43.09%; combined ASR 1.75% / utility 42.68% — [LlamaFirewall paper, arXiv 2505.03574](https://arxiv.org/html/2505.03574)
- AlignmentCheck backing LLM: Llama 4 Maverick (primary), also Llama 3.3 70B; stated limitations: high compute cost, latency, vulnerable to "guardrail injection", overblocking with smaller models — [arXiv 2505.03574](https://arxiv.org/html/2505.03574)
- CodeShield: precision 96%, recall 79%; ~60 ms tier 1, ~300 ms tier 2, ~70 ms average — [arXiv 2505.03574](https://arxiv.org/html/2505.03574)
- Integrations: LangChain agent demo, OpenAI guardrail integration — [LlamaFirewall README](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall)

### Inferences
- AlignmentCheck answers "did the agent's actions drift from the user goal?" over a multi-step trace. WARDEN's model takes no actions and picks no tools; its single output is a typed proposal that P11 (action contradicts evidence), P13/P15 (citations), P14 (target exists) and the closed enum already check deterministically. An LLM auditor would be a weaker, probabilistic duplicate that itself reads attacker-influenced text.
- AlignmentCheck is not CPU-feasible at the tested quality (Maverick / 70B); running it via Together is a paid third-party API that would receive incident traces, conflicting with WARDEN's local/free stance.
- CodeShield has nothing to scan: WARDEN never executes model-generated code or commands (the runbook is fixed code with computed values; see README §7). Revisit only if a future phase lets the model emit shell/SQL/Terraform.
- The 1.75% vs 17.63% AgentDojo numbers are static-attack numbers; see the benchmarks section for how detectors fare against adaptive attackers.

### Gaps
- LlamaFirewall's licence file contents could not be read (PyPI blank, README fetch did not show LICENSE). Paper is CC BY 4.0; **code licence unverified**.
- Whether there is newer LlamaFirewall code on GitHub main after 1.0.3 (commit dates not visible).
- Whether AlignmentCheck works out of the box against Ollama/vLLM (parameters exist per docstring; not tested).

## Other frameworks: NeMo Guardrails, Llama Guard 4, Guardrails AI, Granite Guardian, LLM Guard, ShieldGemma, Invariant/MCP-scan, new 2026 items

### Takeaway
None of these adds a boundary WARDEN lacks. Most are content-safety or chat I/O rails (toxicity, harm
categories) aimed at conversational apps. The only ones worth keeping on the "optional" list are
Granite Guardian 4.1 (Apache-2.0, has groundedness + function-calling-hallucination criteria; an
offline second opinion next to P13/P15/HHEM) and Snyk Agent Scan (a one-off scan of warden-mcp's tool
descriptions). Skip the rest.

### Cited Findings
**NVIDIA NeMo Guardrails**
- Latest 0.24.1 (Sep 16, 2026); 0.24.0 Aug 26, 2026; 0.23.0 Jul 1, 2026; 0.22.0 May 22, 2026; 0.21.0 Mar 12, 2026; Apache-2.0; Python 3.10-3.13 — [PyPI nemoguardrails](https://pypi.org/project/nemoguardrails/)
- Recent features: 0.24 "RailOutcome" engine-neutral outcomes, rail manifests, `/v1/checks` output checking; 0.23 local Hugging Face classifier rails (Transformers/vLLM), streaming and non-streaming tool-call validation, "context bloat" detection, OTel content capture; 0.22 LangChain optional, IORails streaming; 0.21 IORails parallel engine, `check_async`, LangChain GuardrailsMiddleware — [NeMo-Guardrails releases](https://github.com/NVIDIA/NeMo-Guardrails/releases) (the fetch summariser printed year 2024 on these; PyPI confirms 2026)
- Configured through Colang, runs as a proxy microservice — [Turing Post / lyzr roundup, secondary](https://www.lyzr.ai/blog/best-tools-for-prompt-injection-defense)

**Llama Guard 4**
- 12B, natively multimodal, pruned from Llama 4 Scout, content-safety classification of prompts/responses; released April 2025; no Llama Guard 5 found as of Sep 2026 — [HF model card](https://huggingface.co/meta-llama/Llama-Guard-4-12B); [HF blog](https://huggingface.co/blog/llama-guard-4)

**IBM Granite Guardian**
- Granite Guardian 4.1 8B, April 2026, Apache-2.0, fine-tuned from granite-4.1-8b; criteria: harm, social bias, jailbreaking, violence, profanity, unethical behaviour; RAG context relevance, groundedness, answer relevance; agentic function-calling hallucination; bring-your-own criteria; think / no-think modes; quantised variants incl. GGUF; reported function-calling balanced accuracy 0.79, RAG hallucination balanced accuracy 0.76, OOD safety F1 0.79 — [HF model card](https://huggingface.co/ibm-granite/granite-guardian-4.1-8b)

**Protect AI LLM Guard**
- Latest 0.3.16 (May 19, 2025), MIT; 15 input scanners (incl. PromptInjection, Secrets, InvisibleText, Anonymize, BanCode) and 20 output scanners (incl. MaliciousURLs, URLReachability, Sensitive, Deanonymize, FactualConsistency) — [PyPI llm-guard](https://pypi.org/project/llm-guard/)

**ShieldGemma**
- ShieldGemma 2 (4B, Gemma 3 based) filters violent, dangerous and sexually explicit **images**; ShieldGemma (2B etc.) text; under Gemma Terms of Use, which carry use restrictions that must be passed on when redistributing — [Gemma Terms](https://ai.google.dev/gemma/terms); [ShieldGemma 2](https://deepmind.google/models/gemma/shieldgemma-2/)

**Guardrails AI**
- Validators moving to plain PyPI packages; hosted remote inferencing discontinued with cutoff Aug 25, 2026; repo active (updates Sep 18, 2026) — [guardrails-ai/guardrails](https://github.com/guardrails-ai/guardrails) (via search summary; **exact version unverified**)

**Invariant Labs / MCP-scan**
- Snyk acquired Invariant Labs June 2025; MCP-Scan renamed Snyk Agent Scan (v0.4.13, April 2026); scans MCP configs/servers and agent skills for tool poisoning, prompt injection in tool descriptions, rug pulls, cross-origin escalation; scan mode runs locally but uses the Invariant Guardrails API for analysis — [snyk/agent-scan](https://github.com/snyk/agent-scan); [Snyk acquisition](https://snyk.io/news/snyk-acquires-invariant-labs-to-accelerate-agentic-ai-security-innovation/); [appsecsanta review, secondary](https://appsecsanta.com/mcp-scan)

**New in 2026 (thin evidence)**
- Credo AI "Agent Governor" research preview, July 2026, runtime governance for agent actions (commercial) — [futureagi blog, secondary](https://futureagi.com/blog/agent-runtime-guardrails/)
- Research systems (not products): Progent, FIDES, RTBAS, FORGE, AIRGuard (runtime authority control), StepGuard (step-level guardrails) — [arXiv 2606.26479](https://arxiv.org/html/2606.26479v1); [AIRGuard arXiv 2605.28914](https://arxiv.org/pdf/2605.28914); [StepGuard arXiv 2608.24777](https://arxiv.org/pdf/2608.24777)

### Inferences
- **NeMo Guardrails: skip.** It rails a chat loop (Colang flows, I/O rails). WARDEN has no conversation, and its input rail (quarantine) and output rail (outbound gate) are deterministic and already tighter. Its 0.23 tool-call validation duplicates the closed enum + gate.
- **Llama Guard 4 / ShieldGemma: skip.** Harm taxonomies (violence, hate, sexual content) do not apply to incident logs; 12B GPU cost; Gemma/Llama licences carry use restrictions.
- **LLM Guard: skip as a dependency** (no release for ~16 months as fetched; MIT). Its Secrets/Anonymize overlap WARDEN's verified redaction; its PromptInjection scanner is another DeBERTa-class detector in the same family PG2 is in.
- **Guardrails AI: skip.** WARDEN already enforces a typed pydantic proposal; Guardrails AI's value is structured-output validation.
- **Granite Guardian 4.1: optional, offline.** It is the only one with criteria matching WARDEN's residual risk (groundedness of a diagnosis in cited evidence; function-call hallucination). Apache-2.0, no gated licence. Use as an **eval-time judge** in the replay tool, not in the incident path (8B on CPU is too slow for per-incident use - latency **unmeasured**). Would be an alternative/complement to HHEM-2.1-open, not to P13/P15.
- **Snyk Agent Scan: optional one-off.** Run it once against the warden-mcp server config to confirm tool descriptions are clean. Note it sends tool descriptions to Snyk's API; WARDEN's tool descriptions are its own public code, so no secrecy issue, but it is not local-only.

### Gaps
- CPU latency for Granite Guardian 4.1 8B and Llama Guard 4 not found.
- Guardrails AI exact current version and date not verified on PyPI.
- LLM Guard GitHub activity after May 2025 not checked (PyPI history list printed by the fetch was inconsistent).
- No reliable independent comparison of these frameworks against each other on an agent benchmark was found; vendor roundups (Galileo, Lyzr, Maxim) are marketing.

## Design patterns with evidence: CaMeL, dual LLM, spotlighting, action-selector, plan-then-execute; 2025-2026 benchmarks

### Takeaway
The 2025-2026 evidence splits defences into two classes. **In-band detectors and prompting tricks**
(PromptGuard, spotlighting, SecAlign, Model Armor) look near-perfect on static benchmarks and fall to
>90% attack success under adaptive attack, with human red-teamers at 100%. **Out-of-band system design**
(CaMeL, Progent, FIDES, dual-LLM, reference monitors) held up in the one independent adaptive test. WARDEN
is already built in the second class; its detector (P16) is correctly positioned as a tripwire only.

### Cited Findings
- "The Attacker Moves Second" (Oct 2025, USENIX Security 2026): 12 published defences; adaptive attacks (gradient, RL, random search, human-guided) pushed most above 90% ASR despite near-zero originally reported; 500-person human red team reached 100% — [arXiv 2510.09023](https://arxiv.org/abs/2510.09023); [USENIX](https://www.usenix.org/conference/usenixsecurity26/presentation/nasr); [Simon Willison summary](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)
- Per the 2026 survey, PromptGuard and Model Armor exceeded 90% attack success in that work, MetaSecAlign 96%, human red-teaming 100%; StruQ, SecAlign, PromptGuard, Spotlighting, Attention Tracker classed as in-band defences that fail catastrophically under adaptive attack — [arXiv 2606.26479](https://arxiv.org/html/2606.26479v1)
- Out-of-band defences surveyed: CaMeL (capabilities + control-flow integrity), FIDES (taint labels), Progent (symbolic privilege rules), RTBAS (IFC + screeners), FORGE (Datalog reference monitor), plus Dual-LLM and Conseca — [arXiv 2606.26479](https://arxiv.org/html/2606.26479v1)
- Only independent adaptive test: Progent on Qwen2.5-7B, AgentDojo: mean ASR undefended 25.8%, Progent standard 4.2%, Progent adaptive 2.6% (adaptive attack did not raise it) — [arXiv 2606.26479](https://arxiv.org/html/2606.26479v1)
- Stated gaps of out-of-band defences: attacks that stay inside authorised dataflows; exfiltration/implicit flows (CaMeL admits two side channels); "in-the-loop" tasks where untrusted data must drive an authorised action force human endorsement and approval fatigue; text-to-text harms (poisoned summaries) undefended; white-box attacks untested — [arXiv 2606.26479](https://arxiv.org/html/2606.26479v1)
- CaMeL: solves 77% of AgentDojo tasks with provable security vs 84% undefended — [CaMeL paper arXiv 2503.18813](https://arxiv.org/pdf/2503.18813); [Simon Willison](https://simonwillison.net/2025/Apr/11/camel/)
- Meta "Agents Rule of Two": an agent should have at most two of [A] processes untrusted input, [B] accesses sensitive systems/data, [C] changes state or communicates externally; with all three, require human-in-the-loop — [Simon Willison summary](https://simonwillison.net/2025/Nov/2/new-prompt-injection-papers/)
- Spotlighting (Microsoft, 2024): datamarking cut ASR from ~50% to <3% on GPT-3.5-Turbo; base64 encoding to ~0% (static attacks) — [arXiv 2403.14720](https://arxiv.org/abs/2403.14720)
- Prompt Guard 2 model card itself warns of "vulnerability to adaptive attacks"; detects text that "explicitly attempt[s] to override prior instructions"; 512-token window, split longer inputs — [HF model card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)

### Inferences
- WARDEN's shape maps onto the patterns: quarantine = dual-LLM / typed-data extraction (done deterministically, no quarantined LLM needed); one call, no model-chosen tools = action-selector; evidence-first fixed gather = plan-then-execute with a fixed plan; closed enum + P1-P16 + separate write credentials = reference monitor / least privilege (CaMeL-like, without an interpreter). Nonce blocks around F items = spotlighting (in-band, bonus only).
- Rule of Two: WARDEN has A (logs), B (reads prod) and C (restart/scale/terminate). The rule says C must go through a human - which is what the signed digest approval does; dev/staging auto-apply after approval still needs that approval. Keep it that way; do not add unattended C in prod.
- WARDEN's residual risk is exactly the out-of-band gap: an attacker who plants closed-vocabulary phrases ("OOMKilled", "deploy") steering the model to a **permitted** action on a **real** target (e.g. rollback when a real deploy exists). No detector fixes this; it is bounded by P5/P11/P14, the metrics being WARDEN's own readings (not attacker text), and the human digest approval.
- Consequence for measurement: the 6/14 corpus catch rate for PG2 matters little; the useful test is **"even when the injection succeeds at steering the model, does the gate/approval stop harm?"** — i.e. adversarial tests at the gate, with the model assumed compromised (mock returns attacker's chosen proposal).

### Gaps
- No independent adaptive evaluation of CaMeL, FIDES or FORGE exists yet (per 2606.26479).
- AgentDojo's task suites (banking, Slack, workspace, travel) do not model an ops/incident agent; its numbers do not transfer directly to WARDEN. No ops-specific injection benchmark was found.

## Real added protection on top of WARDEN, CPU latency/cost; paid options

### Takeaway
Adopt nothing new in the incident path. Concrete: keep PG2 86M as P16 (consider the 22M variant only if
CPU time matters: 75% cheaper, recall 88.7% vs 97.5%); make sure the tripwire also scans the raw alert
name/summary (the one untrusted channel still reaching the model verbatim); add gate-level "model is
compromised" tests; optionally Granite Guardian 4.1 as an offline replay judge and a one-off Snyk Agent
Scan of warden-mcp. Replace none of WARDEN's own parts. Paid Lakera is unnecessary.

### Cited Findings
- PG2 86M: mDeBERTa-base, AUC .998, recall 97.5% @1% FPR, 92.4 ms/classification (A100, 512 tokens); 22M: DeBERTa-xsmall, "75%" lower latency and compute, AUC .995, recall 88.7% @1% FPR, 19.3 ms; licence "llama4" (Llama 4 Community License, gated) — [HF model card](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M)
- CPU latency for PG2: a search summary cited ~9 ms and ~45 ms on CPU from secondary sources — **unverified, not from a primary source** — [ARMO blog](https://www.armosec.io/blog/prompt-injection-detection-models/)
- WARDEN's own measurement: PG2 86M 0 false alarms on 4,637 real lines, 6/14 corpus payloads caught; alert name and summary still reach the model as-is — `C:\work\warden\README.md` (Injection detector section); `C:\work\warden\docs\ai-boundary.md` ("Honest limits")
- Lakera (paid SaaS): acquired by Check Point Sept 2025, now "Check Point AI Guardrails"; Community tier $0 with up to 10,000 requests/month and 8,000-token prompt cap (another source says 1K/month — conflicting) — [appsecsanta](https://appsecsanta.com/lakera); [eesel](https://www.eesel.ai/blog/lakera-pricing); [markaicode](https://markaicode.com/pricing/lakera-pricing/) (all secondary)
- Free local alternatives to Lakera: PG2 (Llama 4 licence), PIGuard (MIT, already in WARDEN's optional list), LLM Guard PromptInjection scanner (MIT) — [PyPI llm-guard](https://pypi.org/project/llm-guard/); `C:\work\warden\docs\SYSTEM-COMPONENTS.md` §3

### Inferences (the decision table)

| Framework | Verdict for WARDEN | Why | CPU cost |
|---|---|---|---|
| PG2 86M (have it) | **KEEP** as P16 tripwire | 0 FP measured; in-band, breaks under adaptive attack, so never a gate | ~tens of ms/line on CPU (unverified); 86M download, gated licence |
| PG2 22M | optional swap | only if P16 CPU time becomes a bottleneck; lower recall | ~4x cheaper per model card |
| Extend P16 to alert name/summary | **DO** (check first whether it already does) | only untrusted text that still reaches the model verbatim | a few extra classifications per incident |
| Gate-level "compromised model" tests | **DO** | the out-of-band property is what the literature says holds; test it directly: mock returns attacker-chosen proposals, assert gate/approval blocks | CI only |
| LlamaFirewall package | SKIP | wrapper around PG2 you already call; stale since May 2025 | — |
| AlignmentCheck | SKIP (revisit if WARDEN becomes a multi-step tool-choosing agent) | audits action traces WARDEN does not have; needs Maverick/70B via paid API; itself injectable | GPU / paid API |
| CodeShield | SKIP (revisit if model ever emits code/commands) | nothing generated is executed | ~70 ms |
| NeMo Guardrails 0.24.1 | SKIP | chat I/O rails; duplicates quarantine + outbound gate | proxy service + models |
| Llama Guard 4 12B / ShieldGemma | SKIP | content-harm taxonomies, irrelevant; restricted licences | GPU |
| LLM Guard 0.3.16 | SKIP | overlaps redaction/outbound gate; stale | per-scanner models |
| Guardrails AI | SKIP | typed pydantic proposal already enforced | — |
| Granite Guardian 4.1 8B | OPTIONAL, offline eval judge only | groundedness + function-call hallucination criteria; Apache-2.0 | 8B: too slow per-incident on CPU (unmeasured) |
| Snyk Agent Scan | OPTIONAL one-off on warden-mcp | tool-description poisoning check; uses Snyk API | trivial |
| Lakera Guard | SKIP (paid beyond free tier; sends logs off-box) | free tier 10k req/mo (conflicting 1k) | SaaS |
| CaMeL / Progent style | already the architecture | closed enum + gate + separate creds + human digest = reference monitor | — |

- None of these replaces any WARDEN component. The strongest thing WARDEN has (deterministic gate after a model that cannot pick tools) is the class of defence the adaptive-attack literature says survives; adding more in-band detectors buys little.

### Gaps
- No primary-source CPU latency for PG2 86M/22M; WARDEN should measure its own (it already runs PG2 on CPU).
- Whether WARDEN's current P16 already covers alert name/summary was not checked in code (only docs read).
- Lakera free-tier quota conflicting between secondary sources; Lakera/Check Point's own pricing page not fetched.
