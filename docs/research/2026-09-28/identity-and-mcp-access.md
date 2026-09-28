# Agent identity, access control and secrets for AI agents operating production infrastructure (as of 2026-09-28)

Intended save path (blocked by plan mode; copy verbatim when allowed):
`<session scratch> AI ops tooling 2026\identity_access.md`

WARDEN context read first: `docs/PRODUCTION-ARCHITECTURE.md`, `docs/SYSTEM-COMPONENTS.md`, `iam/templates/boundary.json`, `docs/FAILURE-MODES.md` (read-only; nothing in C:\work\warden was modified).

## Q1. MCP authorization spec, MCP security best practices, known MCP attacks, open-source MCP gateways

### Takeaway
The current MCP revision is **2026-07-28** (final, released 28 July 2026). It makes remote MCP servers OAuth 2.1 resource servers that MUST publish Protected Resource Metadata (RFC 9728), MUST validate token audience (RFC 8707) and MUST NOT accept or pass through any other token. It also removes protocol sessions entirely. stdio servers are explicitly told NOT to use OAuth and to take credentials from the environment, so WARDEN's local stdio server is spec-conformant. The spec does not cover tool poisoning or rug pulls. Those are handled by hash-pinning tool definitions and allowlisting servers. The mature OSS gateways are agentgateway (Apache-2.0, Linux Foundation, Rust), IBM ContextForge (Apache-2.0, 1.0 RC), Docker MCP Gateway (MIT) and Microsoft MCP Gateway (MIT, K8s, Entra-only auth, parts in preview).

### Cited Findings
- 2026-07-28 is the released spec: "Today, we're officially pushing the release button on the next version of the MCP specification, `2026-07-28`" — [MCP blog](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- The release removes the `initialize`/`initialized` exchange and the `Mcp-Session-Id` header. Each request now carries its own protocol version, client identity and capabilities, so servers can sit behind ordinary load balancers — [MCP blog](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- Authorization is OPTIONAL overall. HTTP transports SHOULD conform. "Implementations using an STDIO transport **SHOULD NOT** follow this specification, and instead retrieve credentials from the environment." — [MCP Authorization spec (2026-07-28)](https://modelcontextprotocol.io/specification/latest/basic/authorization)
- Standards the spec builds on: OAuth 2.1 draft-13, RFC 6750, RFC 8414, RFC 7591 (DCR), RFC 8707, RFC 9728, RFC 9207, and the Client ID Metadata Document draft — [MCP Authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization)
- MCP servers MUST implement RFC 9728 Protected Resource Metadata, and clients MUST use it for authorization-server discovery. Authorization servers MUST offer RFC 8414 or OIDC Discovery — [MCP Authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization)
- Client registration: Client ID Metadata Documents (CIMD) are SHOULD. Dynamic Client Registration is MAY and now "deprecated and retained for backwards compatibility" — [MCP Authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization)
- Clients MUST send the RFC 8707 `resource` parameter (the canonical server URI) in both authorization and token requests, "regardless of whether authorization servers support it". Clients also use PKCE — [MCP Authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization)
- Servers "MUST validate that access tokens were issued specifically for them as the intended audience". "MCP servers MUST only accept tokens that are valid for use with their own resources" and "MUST NOT accept or transit any other tokens." Tokens must be in the Authorization header on every request and never in the query string — [MCP Authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization)
- New in 2026-07-28: RFC 9207 `iss` validation against the recorded issuer to prevent mix-up attacks. The server-side `iss` is SHOULD and is expected to become MUST later. Client credentials are bound to the issuer that minted them — [MCP Authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization); [MCP blog](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- Least privilege: servers SHOULD return a `scope` in `WWW-Authenticate`. Insufficient scope gets 403 `insufficient_scope`, followed by step-up authorization. `client_credentials` (machine) clients MAY step up or abort — [MCP Authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization)
- Optional authorization extensions are maintained in the `modelcontextprotocol/ext-auth` repo. Third-party write-ups describe Enterprise-Managed Authorization, where the corporate IdP grants access to MCP servers without per-user consent — [MCP Authorization spec](https://modelcontextprotocol.io/specification/latest/basic/authorization); [WorkOS blog](https://workos.com/blog/mcp-2026-spec-agent-authentication) (EMA details not verified on a primary page)
- The security best-practices page covers these attacks:
  - confused deputy (MCP proxy with a static client ID plus DCR plus a consent cookie; fix with per-client consent, exact redirect_uri match and single-use `state`);
  - token passthrough (forbidden: breaks audit, rate limits and trust boundaries);
  - SSRF during OAuth discovery (block private ranges and 169.254.169.254, use an egress proxy such as Smokescreen);
  - state-handle hijacking (now that sessions are gone, servers "MUST NOT treat possession of a state handle as authentication" and SHOULD bind handles to the authenticated user);
  - local server compromise (sandbox, show the exact command, prefer stdio);
  - OAuth URL scheme injection;
  - stdio escalation through proxies;
  - mix-up attacks;
  - localhost redirect impersonation;
  - scope minimisation.

  — [MCP Security Best Practices](https://modelcontextprotocol.io/specification/latest/basic/security_best_practices)
- Tool poisoning hides instructions in tool descriptions or parameter schemas, which the client passes to the model. The variants are description poisoning, rug pulls (the definition changes after approval) and tool shadowing — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-ai-agent-exfiltration-2/)
- CVE-2025-54136 (CVSS 8.8, July 2025) showed that tool approval did not survive later server-side changes, a real rug pull. Defences are to hash-pin tool definitions and reject silent changes, allowlist servers, and treat tool output as hostile — [CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-mcp-tool-poisoning-ai-agent-exfiltration-2/); [bytetools guide](https://bytetools.io/guides/mcp-security) (secondary)
- mcp-scan pins tool descriptions by hashing them on the first scan and alerts when they change. It also checks for poisoning and cross-origin escalation. Licence and current ownership were not verified — [mcpplaygroundonline](https://mcpplaygroundonline.com/blog/mcp-security-tool-poisoning-owasp-top-10-mcp-scan) (secondary)
- ETDI (academic) proposes OAuth-signed, versioned tool definitions plus policy-based access control to stop squatting and rug pulls. It is not in the MCP spec — [arXiv 2506.01333](https://arxiv.org/pdf/2506.01333)
- **agentgateway**: Apache-2.0, a Linux Foundation project, written in Rust, about 5.1k stars. It offers JWT, API-key and OAuth auth, "fine-grained RBAC with CEL policy engine", guardrails, OTel, and stdio/HTTP/Streamable HTTP federation. Latest version not shown on the page — [GitHub](https://github.com/agentgateway/agentgateway)
- **IBM ContextForge**: Apache-2.0, 1.0.0-RC-3, about 4.5k stars. It offers JWT, OAuth and Basic auth, RBAC with token-scoped permissions, encrypted credential storage, SSRF protection, OTel and 40+ plugins. It is Python with Redis — [GitHub](https://github.com/IBM/mcp-context-forge)
- **Docker MCP Gateway**: MIT, about 1.6k stars. It runs each MCP server as an isolated container, filters tools per profile (such as `github.create_issue`), and blocks and injects secrets through Docker Desktop — [GitHub](https://github.com/docker/mcp-gateway)
- **Microsoft MCP Gateway**: MIT, about 855 stars. It is an ASP.NET Core reverse proxy for Kubernetes with Entra ID bearer auth and RBAC (`mcp.admin`/`mcp.engineer`). Agent and session features are "Preview" — [GitHub](https://github.com/microsoft/mcp-gateway)

### Inferences
- WARDEN's local stdio MCP server with no approve tool matches the spec, since stdio takes credentials from the environment. It needs no OAuth. The spec's own guidance for local servers ("Use the stdio transport to limit access to just the MCP client") supports this choice.
- If WARDEN ever exposes MCP remotely (for example, other agents triggering `warden_diagnose_incident` over HTTP), it must implement RFC 9728 metadata, audience checks, CIMD or pre-registration, and it must never forward the caller's token to AWS or Temporal. The cheapest free option is agentgateway in front of a stateless server, with JWT validation and a CEL rule per tool. ContextForge is heavier (Python, Redis, admin UI) and still an RC.
- The 2026-07-28 removal of sessions makes "state handle hijacking" directly relevant to WARDEN. Workflow ids are `inc-<alert_id>` and planned as "alarm + transition time" (FAILURE-MODES C20), which is predictable. Any MCP or CLI tool that takes a workflow id (status, audit, re-run) must authorise the caller and must not treat the id as a secret.
- WARDEN's MCP server is first-party, so tool poisoning is a risk mainly if WARDEN's agent host also loads third-party MCP servers. The risk that matters more is the reverse direction: WARDEN's tool results contain log-derived text that the calling agent's model will read. The outbound gate (G2/G3/G5) should also apply to MCP tool results, not only to Slack.

### Gaps
- The exact Enterprise-Managed Authorization / ID-JAG extension text was not fetched from the `ext-auth` repo, so its current status is unverified.
- mcp-scan's current licence, ownership, and whether its hash-pinning uploads descriptions to a remote API were not verified on a primary page.
- Latest release numbers and dates for agentgateway, Docker MCP Gateway and Microsoft MCP Gateway were not visible on the fetched pages.
- Envoy AI Gateway and other gateways (Lasso, Bifrost) were not verified. Bifrost appears only in vendor listicles by its own maker (getmaxim.ai) and should be treated as marketing.

## Q2. Workload identity for agents: SPIFFE/SPIRE, IAM Roles Anywhere, EKS Pod Identity, ECS task roles, emerging "agent identity" standards and products

### Takeaway
Inside one AWS account, ECS task roles and EKS Pod Identity are the free, native, auto-rotating workload identity, and they are what WARDEN plans. SPIFFE/SPIRE adds value only for non-AWS peers or for issuing mTLS identities (for example worker to Temporal). Its AWS node attestor does not work on Fargate, so only a community ECS workload attestor exists. The IETF has converged on "compose existing standards": SPIFFE/WIMSE identifiers, short-lived attested credentials, RFC 8693 token exchange and audit. It is now a WIMSE WG draft, `draft-ietf-wimse-aims-00` (15 Sep 2026). There is no finished standard. AWS's agent-specific product (Bedrock AgentCore Identity) is part of a paid platform and is not needed.

### Cited Findings
- `draft-ietf-wimse-aims-00`, "AI Identity Management System", is an active WIMSE working-group draft dated 15 Sep 2026. Its authors are Kasselman (Defakto), Lombardo (AWS), Rosomakho (Zscaler), Campbell (Ping), Steele (OpenAI) and Parecki (Okta). It "leverages the Workload Identity in Multi-System Environments architecture alongside OAuth 2.0 specifications" rather than creating new protocols — [IETF datatracker](https://datatracker.ietf.org/doc/draft-ietf-wimse-aims/)
- Its predecessor `draft-klrc-aiagent-auth-03` (6 Jul 2026, now replaced) recommends SPIFFE/WIMSE identifiers, short-lived credentials with attestation, RFC 8693 token exchange for delegation, and audit and observability — [IETF datatracker](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/)
- A second individual draft, `draft-ni-wimse-ai-agent-identity-02`, covers how WIMSE applies to agents — [IETF datatracker](https://datatracker.ietf.org/doc/draft-ni-wimse-ai-agent-identity/)
- The OpenID Foundation's AI Identity Management Community Group published the whitepaper "Identity Management for Agentic AI" (arXiv 2510.25819). It is a landscape and recommendations paper, not a spec — [OpenID Foundation](https://openid.net/new-whitepaper-tackles-ai-agent-identity-challenges/); [arXiv](https://arxiv.org/abs/2510.25819)
- SPIRE on Fargate: an in-container SPIRE agent "will not be able to retrieve an instance ID", so `aws_iid` node attestation does not work. The community plugin `u21-public/spire-ecs-plugin` attests workloads through the ECS task metadata v4 endpoint instead — [spire-ecs-plugin](https://github.com/u21-public/spire-ecs-plugin)
- AWS Bedrock AgentCore Identity treats agent identities as "workload identities with specialized attributes" and brokers outbound OAuth and API keys. It has no extra charge when used through AgentCore Runtime or Gateway, which are themselves paid. Other call paths bill per request — [AWS docs](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/identity.html); [AgentCore pricing](https://aws.amazon.com/bedrock/agentcore/pricing/)
- The WARDEN boundary already allows `eks-auth:AssumeRoleForPodIdentity` (`iam/templates/boundary.json`, CeilingRegional).

### Inferences
- For WARDEN, "one ECS task role per worker type, no keys" is the current best free practice. No agent-identity product adds anything inside a single account.
- SPIFFE/SPIRE (Apache-2.0, CNCF; licence and graduation from prior knowledge, not re-verified) is worth it only if WARDEN wants per-worker mTLS identities for Temporal (FAILURE-MODES S15). On Fargate that means the community ECS attestor, or simpler: a small private CA whose per-worker certs are held in SSM and read through the task role. The simpler option is enough for a lab.
- IAM Roles Anywhere (X.509 to STS) suits the operator laptop because it replaces the long-lived access key without Identity Center. The service is believed to have no charge, and a self-run CA avoids paid AWS Private CA. This is unverified; see Gaps.
- The IETF direction (SPIFFE-style ids, short-lived creds, token exchange, audit keyed on the agent id) matches WARDEN's `inc-<id>` correlation design. WARDEN could adopt a SPIFFE-shaped naming scheme (`spiffe://warden/<env>/worker/<zone>`) in its audit rows at no cost, for future compatibility.

### Gaps
- EKS Pod Identity automatic session tags (cluster, namespace, service account) and ECS task-role mechanics (credentials endpoint 169.254.170.2, shared by all containers in the task) are from prior knowledge. They were not re-fetched this session.
- IAM Roles Anywhere pricing and the AWS Private CA price were not verified this session.
- The IAM Identity Center "account instance" limits (whether a standalone-account instance can grant AWS account access) were not re-verified. The PRODUCTION-ARCHITECTURE doc asserts it needs Organizations.
- No primary Microsoft Entra Agent ID or Google agent identity pages were checked.

## Q3. Human and machine access brokers: Teleport CE, OpenBao / Vault, Infisical, Secrets Manager vs SSM Parameter Store; JIT patterns

### Takeaway
None of the brokers is needed for WARDEN's one-account design. STS plus Parameter Store already gives short-lived, auditable, free access. Teleport Community Edition is no longer open source for companies: since v16 its binaries are under a commercial licence, free only below 100 employees and $10M ARR, or for personal use. Vault is BSL 1.1 under IBM. OpenBao (MPL-2.0, Linux Foundation, v2.6 on 22 Jul 2026) is the open fork to choose if a vault is ever needed. Infisical is MIT at its core, but dynamic secrets and approval workflows are Enterprise-only, and the free cloud tier caps at 5 identities.

### Cited Findings
- Teleport Community Edition from v16 (June 2024) ships binaries, images and AMIs under a commercial "Teleport Community Edition" licence, no longer Apache 2.0. Companies may use it only with "less than 100 employees and less than $10MM in annual recurring revenue". Personal and hobby use is unrestricted, and it must not be resold or embedded — [Teleport blog](https://goteleport.com/blog/teleport-community-license/); [LICENSE-community](https://raw.githubusercontent.com/gravitational/teleport/master/build.assets/LICENSE-community)
- The Teleport pricing page shows only "pay for active users and protected resources". It gave no edition feature matrix on fetch — [Teleport pricing](https://goteleport.com/pricing/)
- HashiCorp Vault moved from MPL 2.0 to BSL 1.1. IBM completed its HashiCorp acquisition in February 2025 — [bex.co](https://bex.co/blog/2026/07/09/vault-bsl-openbao-secrets-backend); [duokey](https://duokey.com/en/resources/hashicorp-vault-bsl-license-change-openbao-migration) (secondary)
- OpenBao is MPL-2.0 under Linux Foundation governance. v2.5.0 shipped on 4 Feb 2026 and v2.6 on 22 Jul 2026, with per-namespace sealing and features that were previously Vault-Enterprise-only — [OpenBao news](https://openbao.org/ecosystem/news/); [byteiota](https://byteiota.com/openbao-v2-6-namespace-sealing-and-a-reason-to-drop-vault/) (secondary for the v2.6 date)
- Infisical is MIT at its core with proprietary enterprise features. The free tier covers 5 identities and 3 projects, and self-hosting is allowed. Paid plans are about $18 per identity per month, and machines count as identities. Enterprise gates dynamic secrets, approval workflows, SCIM, LDAP, KMIP and HSM — [Infisical pricing](https://infisical.com/pricing); [EnvManager](https://envmanager.com/blog/infisical-pricing) (secondary)
- WARDEN's own register records Parameter Store standard-tier SecureString as free (up to 10,000 parameters, AWS-managed key) and Secrets Manager as $0.40 per secret per month — `docs/SYSTEM-COMPONENTS.md` §5. This was not re-verified on the AWS pricing page this session.

### Inferences
- The JIT pattern for an agent without a broker is: a long-lived workload identity (task role) that can only `sts:AssumeRole` into a narrow per-environment role, with a short duration, a session policy naming the exact ARNs, SourceIdentity set to the incident id, and approval required before the actor role is assumed. This is WARDEN's plan and is what Teleport, OpenBao and Infisical "dynamic secrets" automate for multi-cloud estates.
- Parameter Store is the right free choice for WARDEN's few static secrets (Slack webhook, optional model key). Secrets Manager is worth paying for only where AWS rotates the secret (RDS master password), which the docs already say.
- If WARDEN later needs database JIT credentials (a reader with `statement_timeout`, FAILURE-MODES O8), `rds-db:connect` IAM database auth is the free native option. The boundary already allows it, so a vault is not needed.

### Gaps
- Teleport's current licence text was not checked for 2026 changes after v16. No primary page listed which features (Access Requests, Machine and Workload ID, MCP access) are gated to Enterprise.
- The OpenBao v2.6 release notes were not fetched directly.
- The Infisical free-tier numbers come from secondary pages plus the pricing URL listing. The exact 2026 limits should be re-checked on infisical.com/pricing.

## Q4. Best practice for scoping an agent's cloud actions per incident, and proving it

### Takeaway
The effective permissions of an STS session are the intersection of the role's identity policy, its permissions boundary and the session policy, and any explicit deny wins. That makes WARDEN's "reader or actor role + exact-ARN session policy + boundary" the correct AWS-native pattern. There are two hard caveats. First, a resource-based policy that names the session ARN is not limited by the session policy or the boundary. Second, SourceIdentity is a caller-chosen string: AWS enforces only that it cannot change and that it persists through role chaining, not that it is true. It also requires `sts:SetSourceIdentity`, which WARDEN's boundary does not currently allow.

### Cited Findings
- "The permissions for a session are the intersection of the identity-based policies for the IAM entity ... and the session policies." Session policies can be passed on AssumeRole, AssumeRoleWithSAML and AssumeRoleWithWebIdentity as one inline `Policy` plus up to 10 managed `PolicyArns` — [AWS IAM policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html)
- With a permissions boundary, "the resulting session's permissions are the intersection of the session policy, the permissions boundary, and the identity-based policy. However, a permissions boundary does not limit permissions granted by a resource-based policy that specifies the ARN of the resulting session." — [AWS IAM policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html)
- If a resource policy names the session ARN, "The resource-based policy permissions are not limited by the session policy." — [AWS IAM policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html)
- SourceIdentity "cannot be changed during the role session" and persists through role chaining. `aws:SourceIdentity` is present on every later request, so policies can require or match it — [AWS IAM SourceIdentity](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html)
- "AWS doesn't control the value of the source identity ... you must ensure that you can control how those values are provided." The value is 2 to 256 characters of `[A-Za-z0-9_.,+=@-]` and must not start with `aws:` — [AWS IAM SourceIdentity](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html)
- `sts:SetSourceIdentity` is required as a permission. "When you assume a role with another role ... permissions for `sts:SetSourceIdentity` are required in both the permissions policy of the principal who is assuming the role and in the role trust policy of the target role. Otherwise, the assume role operation will fail." — [AWS IAM SourceIdentity](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html)
- "The source identity information is not captured by CloudTrail when an AWS service or service-linked role carries out an action on behalf of a federated or workforce identity." — [AWS IAM SourceIdentity](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html)
- CloudTrail shows `sourceIdentity` in `requestParameters` of the AssumeRole event and in `userIdentity.sessionContext.sourceIdentity` of every later call — [AWS IAM SourceIdentity](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html)
- WARDEN's boundary `CeilingPassAssumeOwnEnv` allows only `iam:PassRole` and `sts:AssumeRole` on `warden-${env}-*`. It contains no `sts:SetSourceIdentity` and no `sts:TagSession` — `iam/templates/boundary.json`

### Inferences
- **The plan as written will fail at run time.** Worker task roles are to be capped by `WardenEnvBoundary-<env>`, and the boundary has no `sts:SetSourceIdentity`. A permissions boundary caps identity-policy permissions, so the read and actor workers' `AssumeRole(... SourceIdentity=inc-<id>)` will be denied. The same applies to `sts:TagSession` if the plan tags sessions with the incident id ("tagged with the incident id" in PRODUCTION-ARCHITECTURE). Fix: add `sts:SetSourceIdentity` (and `sts:TagSession` if tags are used) to the boundary for `warden-${env}-*`, and to the trust policy of each reader and actor role.
- Trust policies on the reader and actor roles should pin the format with `"StringLike": {"sts:SourceIdentity": "inc-*"}` and should name only the specific worker task-role ARN as principal. Otherwise any role in the environment could assume the actor role.
- SourceIdentity proves correlation, not authorisation. AWS cannot check WARDEN's Ed25519 approval, so a compromised actor worker could assume the actor role with any `inc-*` value and a self-written session policy. Free mitigations:
  - (a) Mint the actor session in the separate Approval Lambda, which checks the Slack signature and the Ed25519 signature, and pass the credentials to the actor worker encrypted through the Temporal payload codec (FAILURE-MODES S2).
  - (b) Have the actor worker's trust path require a session tag that only the approval principal can set. This needs sts:TagSession and transitive tags, and is more complex.
  - (c) At minimum, detect: an EventBridge rule on CloudTrail `AssumeRole` of `warden-<env>-actor` that is cross-checked against the signed audit (every actor session must have a matching signed approval row) and pages Slack on a mismatch. This is free on the management-events trail WARDEN already plans in Phase 4.
- Because resource policies that name the session ARN bypass the session policy, the actor role must never be named in S3, SQS, KMS or similar resource policies. IAM Access Analyzer external-access findings (already enabled) do not cover same-account grants, so this needs a check in CI or in Helios.
- Service-driven follow-on actions lose SourceIdentity. After `ecs:UpdateService` or an autoscaling change, the resulting ECS or ASG actions appear under the service-linked role without `inc-<id>`. The change timeline should join on the triggering API call's request id and time window, not only on SourceIdentity.
- The runtime reader and actor roles should not reuse the deploy boundary as their only ceiling. `WardenEnvBoundary` allows `iam:CreateRole`/`PutRolePolicy`/`PassRole` and `ec2:*`/`lambda:*` in-region, because it is built for Terraform deploys. A separate, much tighter boundary for runtime roles (no `iam:*`, and no `sts:AssumeRole` except reader to nothing and actor to nothing) keeps a session-policy bug from widening into IAM writes.
- An ABAC option that is cheap on one account: resource tags `Environment=<env>` are already enforced. Adding a condition such as `aws:ResourceTag/warden-managed = true` on actor actions keeps WARDEN off resources nobody opted in.

### Gaps
- Inline session-policy size limits (packed-size percentage, 2,048-character plaintext limit) and the 1-hour maximum for role-chained sessions come from prior knowledge. They were not re-fetched this session, but they matter because an exact-ARN policy for a large plan may exceed the packed size.
- Whether AWS now offers a native approval-gated STS condition (for example, a "temporary elevated access" feature usable without Identity Center) was not checked.

## Q5. What WARDEN's plan misses (compared with the findings above)

### Takeaway
The core design (a task role per trust zone, JIT 15-minute reader and actor sessions with exact-ARN session policies and SourceIdentity, GitHub OIDC, Parameter Store, and a local stdio MCP server that cannot approve) matches 2026 best practice and the IETF AIMS direction. The concrete gaps are:
- the boundary blocks SourceIdentity;
- the actor role's approval gate is enforced only in application code;
- Temporal is an unauthenticated control plane between trust zones;
- workflow-id handles are guessable;
- the docs contradict each other on IAM Identity Center.

### Cited Findings
- The boundary lacks `sts:SetSourceIdentity` and `sts:TagSession` — `iam/templates/boundary.json`. Both are required for SourceIdentity with role chaining — [AWS IAM SourceIdentity](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html)
- Internal contradiction:
  - `docs/PRODUCTION-ARCHITECTURE.md` says "This lab can't use Identity Center: it needs AWS Organizations, which ends the Free plan".
  - `docs/SYSTEM-COMPONENTS.md` §5 lists IAM Identity Center as "PLANNED (secrets work)".
  - `docs/SYSTEM-COMPONENTS.md` §10 recommends it as the owner's next step.
- MCP servers "MUST NOT treat possession of a state handle as authentication" — [MCP Security Best Practices](https://modelcontextprotocol.io/specification/latest/basic/security_best_practices). WARDEN's workflow id `inc-<alert_id>` is planned as alarm + transition time (`docs/FAILURE-MODES.md` C20).
- Session policies do not limit resource-policy grants to the session ARN — [AWS IAM policies](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html)
- SourceIdentity is not captured for service-linked-role follow-on actions — [AWS IAM SourceIdentity](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html)
- SSRF guidance: block 169.254.0.0/16 (cloud metadata) and use egress proxies such as Smokescreen for server-side clients — [MCP Security Best Practices](https://modelcontextprotocol.io/specification/latest/basic/security_best_practices)

### Inferences (the gap list, ordered by severity)
1. **The boundary blocks SourceIdentity** (and session tags). The Phase 4 AssumeRole calls will fail. Add `sts:SetSourceIdentity` and `sts:TagSession` to the boundary and to the reader and actor trust policies, with `sts:SourceIdentity` `StringLike "inc-*"`.
2. **The approval gate is not enforced by IAM.** The actor worker can assume the actor role by itself. Move actor-credential minting to the Approval Lambda, or at least alarm on any actor `AssumeRole` that has no matching signed approval in the audit (free: EventBridge on CloudTrail management events).
3. **The Temporal trust boundary.** Open-source Temporal's default authorizer allows everything (prior knowledge; verify). So any process with a connection can poll any task queue (the actor queue included), complete activities and send the `approve(plan_hash)` signal. FAILURE-MODES S15 covers mTLS and a security group, but not per-worker authorisation. Needed:
   - per-worker client certificates (a SPIFFE-style SAN per trust zone);
   - a custom `Authorizer`/`ClaimMapper` limiting each identity to its own task queue;
   - the workflow re-verifying the Ed25519 approval signature itself, rather than trusting that a signal arrived.
4. **No separate runtime boundary.** Runtime roles would sit under the deploy ceiling (`iam:*` role writes, `ec2:*`, `lambda:*`). A second, tighter `WardenRuntimeBoundary-<env>` (read-only actions plus the closed action set; no IAM, no STS beyond reader and actor) limits the damage a session-policy bug can do.
5. **Resource-policy bypass.** Forbid any resource policy that names `warden-*-actor` or its sessions, and check this in CI or Helios. The session policy cannot stop it.
6. **Guessable workflow-id handles** on the MCP and CLI surface. Authorise the caller for status, audit and rerun tools, and add a random suffix, or bind ids to the caller and never treat them as secrets.
7. **MCP output hygiene.** The outbound gate (G2/G3/G5) should also sanitise MCP tool results, because the calling agent's model consumes them (indirect injection in the other direction). Pin the MCP server's own tool descriptions in tests (hash) so a code change that alters a description is reviewed as a security change.
8. **The remote-MCP path is not designed.** If `warden_diagnose_incident` is ever offered over HTTP, it needs RFC 9728, audience validation, CIMD or pre-registration, and no token passthrough. Recommended free front: agentgateway (Apache-2.0, LF) with JWT and per-tool CEL. Keep "cannot approve" as a server-side rule, not only an absent tool.
9. **Human access without Identity Center.** Fix the doc contradiction. Free options on a standalone account:
   - an IAM user with MFA only, whose sole permission is `sts:AssumeRole` into boundary-capped roles with `aws:MultiFactorAuthPresent` and a 1-hour maximum;
   - or IAM Roles Anywhere with a self-run CA (removes the static key; pricing unverified).

   The owner's console-only rule fits the MFA-plus-role option.
10. **Task-role credential exposure.** ECS task credentials are served at a link-local endpoint to every container in the task (prior knowledge). The llm worker should run in its own task with no task role at all, or with a role that has zero permissions. Any worker that makes outbound HTTP (notify worker, llm worker with an API key) should block link-local and private ranges on egress, per the MCP SSRF guidance.
11. **SourceIdentity does not cover service follow-ons.** The change timeline must join on request id and time window as well as SourceIdentity, or ECS and ASG actions triggered by WARDEN look unattributed.
12. **Secrets in Temporal history** are already a known gap (S2). If actor credentials are ever passed through Temporal (gap 2, option a), the payload codec becomes mandatory before Phase 4, not optional.

### Gaps
- Temporal OSS authorisation defaults (noop authorizer, whether task-queue-level authorisation is possible) were not verified on docs.temporal.io in this session. Treat gap 3 as needing confirmation.
- ECS task-role credential scoping per container was not re-verified this session.
- Whether the lab's single-account setup can use AWS's newer features (for example, IAM "temporary elevated access" or root-access management) without Organizations was not checked.
