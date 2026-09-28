# What DevOps/SRE practitioners use for AI-driven ops (research, 2026-09-28)

Search budget ran out partway; later findings came from direct page fetches. [unverified] where noted.

## Where the field stands

The industry position matches WARDEN's: the model proposes, a deterministic layer decides.
- **AWS DevOps Agent:** "investigates and provides recommendations rather than taking autonomous
  remediation actions" ([page](https://aws.amazon.com/devops-agent/)).
- **incident.io AI SRE:** "The only change Investigations can make to your systems is a pull request
  you review and merge yourself" ([page](https://incident.io/ai-sre)).
- **HolmesGPT, KubeCon EU 2026:** remediation "within strict RBAC boundaries, approval workflows, and
  audit trails" ([sched](https://kccnceu2026.sched.com/event/1ff722e8bc50da45979d6969e0503a49)).
- **SREcon 2026:** skeptical of agents ([notes](https://jpaulreed.com/thoughts/srecon-2026.html)).
- **SREcon26 EMEA** (13–15 Oct 2026; [program](https://www.usenix.org/conference/srecon26emea/program)):
  - "What Happens When Your AI SRE Has a Bad Day";
  - John Allspaw, "Incident Response & AI – The Hard Parts";
  - OpenAI, "The Hard Part of AISRE Isn't the AI".
- **Abhishek Veeramalla:** agents may generate Terraform but "should not directly run terraform apply
  in production". Repos: `terraform-drift-detector`, `awesome-enterprise-agent-guide`,
  `ai-assisted-devops`, `observability-zero-to-hero` ([GitHub](https://github.com/iam-veeramalla?tab=repositories),
  [newsletter](https://akvanewsletter.substack.com/p/5-reasons-why-companies-can-never)).
  His LinkedIn posts were not reachable [unverified].

## ADOPT

1. **GitOps awareness (correctness gap).**
   - Argo selfHeal and Flux revert direct patches. Read `argocd.argoproj.io/instance` and
     `kustomize.toolkit.fluxcd.io/*`.
   - When they are present, escalate or open a PR instead of patching.
   - Optional: read-only Argo and Flux MCP servers
     ([Argo MCP](https://github.com/argoproj-labs/mcp-for-argocd), [Flux MCP](https://fluxoperator.dev/mcp-server/)).
2. **AWS FIS** fault injection ([actions](https://docs.aws.amazon.com/fis/latest/userguide/fis-actions-reference.html)).
   - ECS actions: `aws:ecs:stop-task`, `task-cpu-stress`, `task-io-stress`, `task-kill-process`,
     `task-network-latency`, `task-network-packet-loss`, `task-network-blackhole-port`,
     `drain-container-instances`.
   - EKS actions: `aws:eks:pod-delete`, `pod-memory-stress`, `pod-cpu-stress`, `pod-network-*`,
     `terminate-nodegroup-instances`.
   - RDS actions: `aws:rds:reboot-db-instances`, `failover-db-cluster`; plus
     `aws:network:disrupt-connectivity`.
   - Stop conditions can be CloudWatch alarms.
   - Use it only for faults the harness cannot inject.
3. **Supply chain.**
   - cosign keyless signing plus GitHub build provenance (SLSA).
   - A **Kyverno `ImageValidatingPolicy`** (stable since v1.19) on EKS
     ([docs](https://kyverno.io/docs/policy-types/image-validating-policy/)).
   - **OpenSSF Scorecard** ([repo](https://github.com/ossf/scorecard)).
4. **Checkov** over terraform, k8s, Dockerfile and `.github` ([repo](https://github.com/bridgecrewio/checkov)).
   Skip **Terrascan** (archived 2025-11-20; [repo](https://github.com/tenable/terrascan)) and skip KICS.

## INTEGRATE

5. **Prometheus HTTP API evidence backend**, with deterministic PromQL.
   - Covers kube-state-metrics, OBI/Beyla eBPF (donated to OTel, v0.8.0;
     [blog](https://grafana.com/blog/opentelemetry-ebpf-instrumentation-beyla-donation/)) and Coroot
     ([repo](https://github.com/coroot/coroot)).
   - This is the biggest evidence gap; P11 would get real memory numbers.
6. **Serve warden-mcp over streamable HTTP** so these hosts can use it:
   - AWS DevOps Agent, which accepts private or remote MCP servers;
   - kagent (CNCF Sandbox, v0.10.0; [repo](https://github.com/kagent-dev/kagent));
   - Kestra 2.0 ([blog](https://kestra.io/blogs/2026-09-04-kestra-2-0-flows-as-agent-tools)).
7. **Document an agentgateway pattern**: CEL `mcpAuthorization`, default-deny
   ([docs](https://agentgateway.dev/docs/standalone/main/mcp/mcp-authz/), [repo](https://github.com/agentgateway/agentgateway)),
   combined with read-only MCP servers:
   - `kubernetes-mcp-server --read-only` ([repo](https://github.com/containers/kubernetes-mcp-server));
   - awslabs EKS/ECS servers, which are read-only by default ([docs](https://awslabs.github.io/mcp/servers/eks-mcp-server));
   - `mcp-grafana --disable-write` ([repo](https://github.com/grafana/mcp-grafana)).
8. **Incident platforms:** intake webhooks from PagerDuty, Grafana IRM and incident.io, and post the
   report back to the incident timeline.
9. **Backstage owner lookup:** only if the customer runs Backstage.

## TEST-WITH

10. **HolmesGPT and K8sGPT baselines** on the same scenarios
    ([Holmes](https://github.com/HolmesGPT/holmesgpt), [CNCF](https://www.cncf.io/projects/holmesgpt/), [K8sGPT](https://github.com/k8sgpt-ai/k8sgpt)).
11. **AIOpsLab** ([repo](https://github.com/microsoft/AIOpsLab)) and **ITBench**
    ([repo](https://github.com/itbench-hub/ITBench)): run the detection, localization and RCA tasks.
12. **Chaos Mesh** in the k3d CI job ([repo](https://github.com/chaos-mesh/chaos-mesh)). LitmusChaos
    would duplicate it.
13. **Sloth** SLO burn-rate alerts as test input ([repo](https://github.com/slok/sloth)); Pyrra is the
    alternative.
14. **TypeSafe Jev:** proprietary early access; at most one more diagnose provider later, never the gate.

## SKIP

- **Kestra or Dapr as orchestrator:** Temporal is already in place.
- **OPA / Kyverno as the gate:** Python stays the gate.
- **AgentCore Policy:** cite it as prior art only.
- **Teleport Agent Trust:** preview; revisit after GA.
- **ZeroDrift Anchor 3.0:** it governs communications compliance, not infrastructure
  ([release](https://www.globenewswire.com/news-release/2026/09/23/3367512/0/en/zerodrift-launches-anchor-3-0-the-first-family-of-models-built-for-enforcement-runtime-of-ai-agent-communications.html)).
- **Model-serving and GPU stack** (KAITO, llm-d, KServe, Kubeflow, kgateway, AI Conformance): not
  relevant ([CNCF](https://www.cncf.io/announcements/2026/03/24/cncf-nearly-doubles-certified-kubernetes-ai-platforms/)).
- **kubectl-ai:** chat-first, not evidence-first.
- **Falco / Tetragon / KubeArmor:** at most a Tetragon exec-allowlist for WARDEN's own Job.
- **Rundeck / StackStorm / SSM Automation:** a second approval system.
- **Crossplane / Port.**
- **OpenCost / Kubecost:** YAGNI.
- **Pixie and direct Coroot/Beyla integrations:** covered by the Prometheus backend.
