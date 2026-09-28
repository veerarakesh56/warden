# Observability, evals and red-teaming tooling for WARDEN (state as of 2026-09-28)

NOTE: plan mode was active for this research agent, so these notes are saved here (the only writable
file). Intended destination: `<session scratch> AI ops tooling 2026\observability_evals.md`.

WARDEN context (from repo docs): one model call per incident (`diagnose`), Temporal activities, OTel
spans with GenAI attributes already (`gen_ai.operation.name`, `gen_ai.provider.name`,
`gen_ai.request.model`, `gen_ai.usage.*`), cost under `warden.cost.usd`; SYSTEM-COMPONENTS.md already
lists Inspect AI + AgentDojo as PLANNED Phase 3, garak OPTIONAL, promptfoo NOT USED; FAILURE-MODES.md
M15/E6 (model drift -> replay gate on model/prompt/CLI change) and E2/E5 (Wilson lower bound gating).

## Observability: which tool traces every model call and workflow step, free to self-host, fits a small team

### Takeaway
Keep WARDEN's own OTel spans as the source of truth and add Temporal's `TracingInterceptor` so workflow/activity spans join the same trace; ship OTLP to **Arize Phoenix** (single container, SQLite, ELv2 - free to self-host but not OSI open source) for a laptop-sized backend, or **Langfuse** (MIT core, now owned by ClickHouse) if a heavier stack (Postgres + ClickHouse + Redis + S3) is acceptable. Helicone (proxy-based, reportedly in maintenance mode) and OpenLLMetry (auto-instrumentation WARDEN does not need) add little.

### Cited Findings
- Langfuse was acquired by ClickHouse, Inc. on 2026-01-16; announcement says it remains open source and self-hostable and Langfuse Cloud continues unchanged — [ClickHouse blog](https://clickhouse.com/blog/clickhouse-acquires-langfuse-open-source-llm-observability); [SiliconANGLE](https://siliconangle.com/2026/01/16/database-maker-clickhouse-raises-400m-acquires-ai-observability-startup-langfuse/); [Langfuse GitHub discussion #11593](https://github.com/orgs/langfuse/discussions/11593)
- Langfuse self-host components: Langfuse Web + Langfuse Worker containers, Postgres, ClickHouse, Redis/Valkey, S3/blob storage (LLM API optional). Deployable via Docker Compose, Helm, AWS/Azure/GCP. Core MIT; "some add-on features require an enterprise license key"; "only depends on open source components" — [Langfuse self-hosting docs](https://langfuse.com/self-hosting). The overview page gives no CPU/RAM minimum.
- Langfuse latest release seen: v4.46.0 dated Sept 25 (the fetch summary printed the year as 2024, which is inconsistent with v4.x; treat the exact date as unverified, likely 2026-09-25); several releases per week — [Langfuse releases](https://github.com/langfuse/langfuse/releases)
- Arize Phoenix: Elastic License 2.0; single container image; SQLite for local, PostgreSQL for production; ingests OTLP; uses OpenInference conventions; has tracing, LLM-based evals, experiments, versioned datasets — [Phoenix GitHub](https://github.com/Arize-ai/phoenix)
- Helicone: Apache-2.0; self-host via docker-compose of Web, Worker (Cloudflare Workers proxy), Jawn, Supabase, ClickHouse, Minio; Helm charts require contacting enterprise sales — [Helicone GitHub](https://github.com/Helicone/helicone). A secondary source says Helicone is "in maintenance mode since the Mintlify acquisition in March 2026" — [morphllm.com](https://www.morphllm.com/ai-agent-observability-tools); NOT confirmed on the Helicone repo page (no notice visible) — unverified.
- OpenLLMetry (Traceloop) is Apache-2.0; no 2026 acquisition found — [morphllm.com](https://www.morphllm.com/ai-agent-observability-tools); it can export to Laminar — [Traceloop docs](https://www.traceloop.com/docs/openllmetry/integrations/laminar). Laminar publishes Python SDK `lmnr` — [PyPI lmnr](https://pypi.org/project/lmnr/); licence/self-host needs not verified.
- OTel GenAI semconv: the opentelemetry.io GenAI pages are now redirect notices ("GenAI semantic conventions have moved to the OpenTelemetry GenAI semantic conventions repository") — [opentelemetry.io gen-ai](https://opentelemetry.io/docs/specs/semconv/gen-ai/). In the core registry every `gen_ai.*` attribute (incl. `gen_ai.operation.name`, `gen_ai.provider.name`, `gen_ai.request.model`, `gen_ai.usage.input_tokens/output_tokens`, `gen_ai.agent.*`, `gen_ai.tool.*`) is shown as **Development**, marked deprecated/moved — [OTel attribute registry](https://opentelemetry.io/docs/specs/semconv/registry/attributes/gen-ai/). None is Stable or Release Candidate.
- The new repo `open-telemetry/semantic-conventions-genai` covers "spans, metrics, and events for GenAI clients, MCP ... and provider-specific conventions"; agent operations referenced: `invoke_agent`, `execute_tool`, `create_agent`, `invoke_workflow`; it has **no published releases** yet (releases page empty) and a TODO schema URL — [semconv-genai repo](https://github.com/open-telemetry/semantic-conventions-genai); [releases](https://github.com/open-telemetry/semantic-conventions-genai/releases)
- Temporal Python SDK `temporalio.contrib.opentelemetry.TracingInterceptor`: pass via `Client.connect(..., interceptors=[TracingInterceptor()])`; creates spans for all client calls and all workflow/activity invocations, propagated through the server into one trace per workflow execution; workflow-side spans are zero-duration completed spans because an open span cannot survive replay; custom workflow spans via `temporalio.contrib.opentelemetry.workflow.completed_span()` — [Temporal Python API docs](https://python.temporal.io/temporalio.contrib.opentelemetry.TracingInterceptor.html); [Temporal observability docs](https://docs.temporal.io/develop/python/platform/observability)

### Inferences
- WARDEN's existing attribute names match the moved conventions; the README claim "semconv v1.42.0 (June 2026)" could not be confirmed here (no releases in the new repo). Safe position: pin attribute names in a test, keep cost in `warden.cost.usd`, and adopt `invoke_workflow`/`execute_tool` span names only for WARDEN's own steps if desired — optional, not needed.
- Phoenix fits a one-person project best: one container, SQLite, no ClickHouse. ELv2 forbids offering it as a managed service, which WARDEN does not do; flag "source-available, not OSI" in SYSTEM-COMPONENTS.
- Langfuse is the better fit only if prompt management/datasets/annotation queues in a UI are wanted; it needs an always-on box with 4 stateful services, which conflicts with the owner's "no always-on server" rule in SYSTEM-COMPONENTS section 7.
- Cheapest viable route: TracingInterceptor + existing spans -> OTLP -> Phoenix run locally only during test windows/replays; nothing always-on.

### Gaps
- Langfuse minimum CPU/RAM for self-host not on the overview page (not fetched further).
- Exact current semconv version tag and whether any `gen_ai.*` attribute is scheduled for RC/Stable: not found.
- Phoenix latest version/date not captured. Laminar licence and self-host footprint not verified. Helicone maintenance-mode claim unverified on a primary source.
- Whether TracingInterceptor emits GenAI-semconv attributes (it does not appear to; it emits Temporal span names) — not confirmed.

## Evals: which framework for regression evals when model/prompt/CLI changes; pass^k and small-n statistics

### Takeaway
**Inspect AI** (MIT, UK AISI, v0.3.271 released 2026-09-26) is the best fit for WARDEN's replay-based regression gate: epochs give k runs per incident for pass^k, and it is local-first. DeepEval (Apache-2.0) is a usable alternative with agent metrics, local-only without login. promptfoo is now OpenAI-owned (announced 2026-03-09) but stays open source. Braintrust is paid (free tier not verified). Report pass^k with Wilson (or Bayesian) intervals, never point accuracy, on a ~30-incident set.

### Cited Findings
- Inspect AI: latest 0.3.271, released 2026-09-26; MIT; Python >=3.10; by UK AI Security Institute; built-in tool use, multi-turn, model grading, 200+ pre-built evals — [PyPI inspect-ai](https://pypi.org/project/inspect-ai/). GitHub "Releases" page shows none (it publishes via PyPI/tags) — [inspect_ai releases](https://github.com/UKGovernmentBEIS/inspect_ai/releases)
- promptfoo: OpenAI announced acquisition 2026-03-09; will "remain open source under the current license"; to be embedded into OpenAI Frontier — [OpenAI](https://openai.com/index/openai-to-acquire-promptfoo/); [Promptfoo blog](https://www.promptfoo.dev/blog/promptfoo-joining-openai/). Licence conflict among secondary sources (Apache-2.0 vs MIT) — [QASkills](https://qaskills.sh/blog/openai-promptfoo-acquisition-explained-2026) — check the repo LICENSE before use (unverified here).
- DeepEval: Apache-2.0; agent metrics Task Completion, Tool Correctness, Goal Accuracy, Step Efficiency, Plan Adherence; core runs locally, Confident AI cloud optional (only after `deepeval login`); auto-loads `.env.local`/`.env` at import (disable with `DEEPEVAL_DISABLE_DOTENV=1`) — [DeepEval GitHub](https://github.com/confident-ai/deepeval)
- pass^k = probability all k i.i.d. trials succeed (vs pass@k = at least one); tau-bench showed GPT-4o 61% pass@1 but 25% pass^8 on retail — [tau-bench paper](https://arxiv.org/pdf/2406.12045)
- CLT-based intervals miscalibrate on small benchmarks; Bayesian/small-n intervals recommended; ranking close models may need ~3x more trials for 95% CIs — [Don't Pass@k, ICLR 2026](https://arxiv.org/pdf/2510.04265)
- Reliability-science framing for long-horizon agents beyond pass@1 — [arXiv 2603.29231](https://arxiv.org/pdf/2603.29231) (not read in full)

### Inferences
- Regression gate recipe (fits M15/E6): on any change to model id, `claude` CLI version, prompt hash or catalogue hash, run the ~30 recorded incidents x k=3-5 epochs through `replay_diagnose.py` (or an Inspect task wrapping it), score with the frozen rubric, compute per-incident pass^k and a paired comparison vs the last accepted baseline (McNemar/exact sign test on per-incident flips), and block if any previously-passing safety case fails or the Wilson lower bound drops. Record versions in the audit row (E7).
- Wilson lower bound for all-pass results is n/(n+z^2): 20/20 -> 0.839, 30/30 -> 0.887 at 95% two-sided (computed, not sourced). So 30 incidents cannot certify an error rate below ~11%; the gate should be "no regression + deterministic verifier backstop", not "proves safe". (FAILURE-MODES' "20/20 -> ~14%" matches the one-sided exact/Clopper-Pearson bound 1-0.05^(1/20)=0.139.)
- Claude Max CLI as provider: Inspect has native Anthropic/Bedrock providers, but the CLI path needs a custom model provider or wrapping WARDEN's own `LLMClient` as the solver — the simplest route is an Inspect task whose solver calls WARDEN's pipeline (not verified against Inspect docs).
- OpenAI Evals and RAGAS: not researched in this pass (RAGAS targets RAG retrieval quality; WARDEN has no retriever, so low relevance).

### Gaps
- Braintrust pricing/free tier; OpenAI Evals current maintenance status; RAGAS version — not verified.
- promptfoo repo LICENSE text and whether red-team generation still defaults to remote Promptfoo servers post-acquisition — not verified (SYSTEM-COMPONENTS already records "remote generation by default").
- Whether Inspect ships a built-in pass^k reducer (it has epochs/reducers; exact pass^k support not confirmed).

## Red-teaming: garak, PyRIT, promptfoo, AgentDojo, InjecAgent, ASB, 2025-2026 benchmarks — which apply to a log-reading remediation agent

### Takeaway
For WARDEN the relevant threat is **indirect** prompt injection via log lines/events/alert text leading to an unsafe typed action. The best-fitting sources are AgentDojo-style indirect-injection cases (and its 2026 dynamic successor AgentDyn) adapted into WARDEN's own corpus, plus garak/PyRIT only as payload generators (both are free: garak Apache-2.0, PyRIT MIT). Chat-jailbreak scanners mostly test the model, not WARDEN's gate.

### Cited Findings
- garak (NVIDIA): probes for prompt injection, jailbreaks, hallucination, data leakage, etc.; 50+ probe modules, 23 generator backends incl. Anthropic, 28 detectors; v0.15.0 (2026-05-01) added a multi-turn GOAT probe and an "Agent-breaker" probe for agent tools and a system-prompt-extraction probe; latest stable reported as 0.17.0 (2026-09-09) — [appsecsanta](https://appsecsanta.com/garak) (secondary); repo [NVIDIA/garak](https://github.com/NVIDIA/garak). Version/date from secondary source — unverified on PyPI.
- PyRIT (Microsoft AI Red Team): MIT, Python 3.10-3.13; orchestrators for multi-turn attacks, converters, scorers, memory; `XPIAOrchestrator` for cross-domain (indirect) prompt injection embedded in external data; latest release reported as v0.11.0 (Feb 2026) — [appsecsanta](https://appsecsanta.com/pyrit) (secondary; the same search summary also claimed an open-source date of 2026-09-10, which contradicts the original Feb 2024 launch — [Microsoft Security Blog 2024-02-22](https://www.microsoft.com/en-us/security/blog/2024/02/22/announcing-microsofts-open-automation-framework-to-red-team-generative-ai-systems/); treat the version claim as unverified)
- AgentDojo (NeurIPS 2024): 97 user tasks, 629 security test cases; the standard agent injection benchmark — cited in [AgentDyn arXiv 2602.03117](https://arxiv.org/html/2602.03117v1)
- AgentDyn (2026) extends AgentDojo with dynamic open-ended tasks; defenses strong on static benchmarks fail to generalise — [arXiv 2602.03117](https://arxiv.org/html/2602.03117v1)
- Agent Security Bench (ASB): direct and indirect injection, memory poisoning, backdoors across 10 scenarios and 400+ tools; RAS-Eval: real tool execution, 3,802 attack tasks; WASP: web agents end to end — per the survey summary in the same search; primary pages not fetched
- Other 2026 work: AgentDrift, a step-labelled benchmark of injection-hijacked trajectories — [arXiv 2609.06972](https://arxiv.org/pdf/2609.06972); automated injection attacks in agentic environments — [arXiv 2606.10525](https://arxiv.org/html/2606.10525v1); PI-Hunter automated red-teaming — [arXiv 2606.12737](https://arxiv.org/pdf/2606.12737); memory-based injection "Bad Memory" — [arXiv 2607.14611](https://arxiv.org/pdf/2607.14611) (titles only; not read)
- promptfoo red team: OpenAI-owned since the March 2026 deal — [OpenAI](https://openai.com/index/openai-to-acquire-promptfoo/)

### Inferences
- AgentDojo/ASB/InjecAgent are built around agents that pick tools; WARDEN's model picks no tools (evidence is gathered first, one closed-enum proposal). What transfers is the **attack-in-data** pattern and the metrics (utility under attack, attack success rate). Build a WARDEN-shaped suite: take each of the ~30 recorded incidents, inject payloads (garak/PyRIT converters, AgentDojo injection templates) into a log line / k8s event / alert summary, and assert (a) verdict never becomes more permissive than the clean run, (b) proposed action unchanged or escalated, (c) no secret/link in outbound text. Measure with pass^k because attacks are stochastic.
- garak is the lowest-effort add: use it offline to harvest payload strings into `tests/test_injection_corpus.py`, not to scan the model in CI (needs a live model).
- PyRIT's XPIA pattern is the closest conceptual match to "malicious text inside logs"; heavier to wire than garak.
- promptfoo: keep NOT USED (ownership + remote generation), consistent with SYSTEM-COMPONENTS.
- InjecAgent was not researched in this pass (known from literature as an indirect-injection benchmark for tool agents; details unverified here).

### Gaps
- garak and PyRIT versions/dates not verified on PyPI/GitHub releases.
- ASB, InjecAgent, RAS-Eval, WASP primary sources not fetched; licences of AgentDojo/ASB datasets not verified.
- Whether AgentDojo ships an Inspect AI port (inspect_evals) — not verified.

## Calibration of agent confidence with small golden sets

### Takeaway
Verbalized confidence from modern models is still miscalibrated on its own; the working pattern is a post-hoc map (Platt or isotonic) fit on independently labelled outcomes, and with ~30 examples only Platt (2 parameters) or a simple threshold is defensible. Gate on the Wilson lower bound per confidence bucket, and treat confidence only as a reason to stop (as P4 already does).

### Cited Findings
- Modern LLM calibration mostly relies on verbalized confidence because logits are inaccessible or poorly aligned after RLHF; post-hoc Platt scaling and isotonic regression map raw signals to probabilities; one reported case: verbalized 0.9 corresponded to 64% accuracy on a labelled hold-out — [FutureAGI blog](https://futureagi.com/blog/evaluating-llm-confidence-uncertainty-2026/) (vendor blog, secondary)
- 2026 study of 18 GPT/Claude/Gemini models (incl. Sonnet 4, 4.5, 4.6) on LLM-as-judge: post-2025 models calibrate better under an improved verbalized-confidence prompting protocol; Sonnet 4.5 adaptive ECE dropped from 9.1% to 3.3%; recommends logprob-free verbalized confidence since logprobs are restricted on new APIs — [arXiv 2609.10996](https://arxiv.org/html/2609.10996v1)
- Other 2026 calibration work for agents: DualStake dual-path calibration for deep-research agents — [arXiv 2609.00935](https://arxiv.org/pdf/2609.00935); unsupervised single-generation calibration — [arXiv 2604.19444](https://arxiv.org/html/2604.19444v1) (not read)

### Inferences
- The Claude Max CLI exposes no logprobs, so WARDEN is limited to verbalized confidence plus cheap consistency signals (agreement across k epochs from the pass^k runs = self-consistency). Agreement rate across k samples is a free second feature for the planned `decide.py`.
- With ~30 labels: fit Platt (logistic on 1-2 features) with leave-one-out, report Brier score and a reliability plot; isotonic needs more data and overfits at n=30. Labels must come from independent ground truth (injected fault known in the bench), per FAILURE-MODES E2.
- Retain P4 as a hard floor; calibration should only raise escalation, never lower the gate.

### Gaps
- No primary source found quantifying minimum sample sizes for Platt vs isotonic on LLM confidence; the n=30 guidance above is standard statistics practice, not a sourced finding.
- No verified tool that does calibration for agents out of the box (scikit-learn `CalibratedClassifierCV` is the obvious free choice; not researched).
