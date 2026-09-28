# WARDEN external-dependency re-evaluation on quality (research, 2026-09-28)

**Verdict:** move audit-checkpoint signing to AWS KMS Ed25519, sign approvals with passkeys (WebAuthn)
over the plan, and keep identity AWS-native. Do not add a hosted guardrail, a network policy service
or Jev. Each of these is a quality decision; cost did not decide any of them.

## 1. Signing keys, KMS and transparency logs

**KMS**
- **KMS supports Ed25519**: key spec `ECC_NIST_EDWARDS25519`, announced 2025-11-07 for all regions
  ([announcement](https://aws.amazon.com/about-aws/whats-new/2025/11/aws-kms-edwards-curve-digital-signature-algorithm/), [key specs](https://docs.aws.amazon.com/kms/latest/developerguide/symm-asymm-choose-key-spec.html)).
- Use `ED25519_SHA_512` with `MessageType:RAW`. That is pure Ed25519, so the existing
  `Ed25519PublicKey.verify` still works. **Do not** use `ED25519_PH_SHA_512`.
- KMS HSMs are FIPS 140-3 Level 3 (Feb 2025) ([FIPS](https://aws.amazon.com/compliance/fips/)).
- Cost: $1 per key per month plus about $0.15 per 10k signatures; asymmetric operations are not in
  the free tier ([pricing](https://aws.amazon.com/kms/pricing/)). About 35k checkpoints a year costs
  roughly $13.
- CloudHSM is about $2.3k/month for an HA pair; only worth it when compliance mandates it.

**Prior art: CloudTrail log validation** uses the same design: an hourly signed digest chain in S3
([validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html)).
The strength comes from keeping a copy the writer cannot delete.

**Sigstore Rekor v2**
- Generally available since Oct 2025 on the Tessera backend, with yearly log shards and a 99.5% SLO
  ([Rekor v2](https://blog.sigstore.dev/rekor-v2-ga/)).
- Witness cosigning is not yet available ("soon"), and there are no terms of use for non-software data.
- Open question about using it for audit checkpoints:
  [issue #2993](https://github.com/sigstore/rekor/issues/2993) (no maintainer reply yet).
- Entries are public forever.

**Recommendation**
- A KMS Ed25519 key; its key policy grants `kms:Sign` only to a dedicated audit-signer role.
- CloudTrail's record of every `kms:Sign` call acts as a witness, delivered to a separate bucket.
- Checkpoints in S3 with Object Lock in Compliance mode.
- Rekor only as an optional third witness, and never able to block anything.
- Approver keys stay with the person (next section).

## 2. Human approval signatures

**Library.** py_webauthn 3.0.1 (2026-09-25), BSD-3-Clause, Python 3.10+, maintained by Duo Labs;
v3.0.0 added ML-DSA ([PyPI](https://pypi.org/project/webauthn/), [repo](https://github.com/duo-labs/py_webauthn)).

**How the signing works.** WebAuthn transaction signing sets the challenge to a hash of the thing
being approved ([Yubico](https://developers.yubico.com/WebAuthn/Concepts/Using_WebAuthn_for_Signing.html), [Transmit](https://developer.transmitsecurity.com/guides/orchestration/journeys/transaction_signing_webauthn)).
- WARDEN stores the assertion and the public key, so the approval can be re-verified offline.
- Use challenge = SHA-256(`SignedApproval.message()`) with user verification required.

**Caveats**
- The authenticator does not show what is being signed, so the page must render the plan and require
  the approver to type the target.
- Synced passkeys live in iCloud/Google accounts. For T3, require device-bound keys via attestation.

**How production systems approve today**
- GitHub environments: up to 6 reviewers, of whom 1 must approve ([docs](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)).
- Teleport: Slack access requests plus per-session MFA; moderated sessions re-prompt every 30 s
  ([moderated](https://goteleport.com/docs/admin-guides/access-controls/guides/moderated-sessions/), [slack](https://goteleport.com/docs/identity-governance/access-requests/plugins/slack/)).
- PagerDuty: human-in-the-loop steps are workflow tasks
  ([automation](https://www.pagerduty.com/platform/automation/workflow/)).

WebAuthn over the plan hash is stronger than any of these.

**Slack's in-app browser is unverified.** Passkeys work in SFSafariViewController and Chrome Custom
Tabs, but are unreliable in WKWebView and Android WebView
([Corbado](https://www.corbado.com/blog/passkeys-in-app-browsers)). Users can switch off in-app
browsing, and Enterprise Grid can mandate a browser ([Slack](https://slack.com/help/articles/360037782773-Use-a-mandatory-mobile-browser)).

**Recommendation**
- The Slack button opens an approval URL.
- The page renders the plan and requires the typed target.
- It asks for a passkey with user verification.
- If `PublicKeyCredential` is unavailable, it offers "Open in Safari/Chrome".
- The full assertion is written to the audit.
- The Ed25519 CLI stays as break-glass.
- T3 needs two approvers, plus hardware keys where policy says so.

## 3. Guardrail products

| Product | Notes |
|---|---|
| Lakera | Acquired by Check Point (Sep 2025, about $300M reported). A self-hosted container exists; pricing by quote ([Check Point](https://www.checkpoint.com/press-releases/check-point-acquires-lakera-to-deliver-end-to-end-ai-security-for-enterprises/), [self-hosting](https://docs.lakera.ai/docs/selfhosting)). |
| Prisma AIRS 3.0 | Enterprise platform ([blog](https://www.paloaltonetworks.com/blog/2026/03/prisma-airs-3-0-autonomous-ai/)). |
| Cisco AI Defense | Enterprise platform ([news](https://newsroom.cisco.com/c/r/newsroom/en/us/a/y2026/m02/cisco-redefines-security-for-the-agentic-era.html)). |
| LlamaFirewall AlignmentCheck | 83% detection at 2.5% false positives on Meta's own dataset ([paper](https://arxiv.org/pdf/2505.03574)); bypassed by control-flow hijacking ([arXiv 2510.17276](https://arxiv.org/abs/2510.17276)). |

**Recommendation:** none of these belongs in the approval path. At most, a self-hosted classifier that
feeds signals to the audit. Sending production logs to a third party is a security cost in itself.

## 4. Agent identity

- Teleport: priced by monthly active users plus resources. Its agent features are recent
  ([pricing](https://goteleport.com/pricing/guide/), [Agent Trust](https://goteleport.com/about/newsroom/press-releases/agent-trust-identity-security/), [Beams](https://goteleport.com/about/newsroom/press-releases/beams-llm-proxy-delegated-identity/)):
  - Agentic Identity Framework: Jan 2026;
  - Beams: beta Jun 2026;
  - Agent Trust: preview Jul 2026.
- IAM Identity Center requires AWS Organizations for account access
  ([instances](https://docs.aws.amazon.com/singlesignon/latest/userguide/identity-center-instances.html), [Aug 2026](https://aws.amazon.com/about-aws/whats-new/2026/08/aws-identity-center-accounts-optional/)).

**Recommendation:** AWS-native.
- Roles per tier and class.
- STS with a session policy naming the target ARN, a short duration, and SourceIdentity set to the
  workflow id.
- An MFA condition on the break-glass role.
- Teleport Machine ID (`tbot`) only where a customer already runs Teleport.

## 5. Policy engine

- Verified Permissions: $5 per million calls, available in ap-south-2, default 200 RPS
  ([price cut](https://aws.amazon.com/about-aws/whats-new/2025/06/amazon-verified-permissions-reduces-price/), [endpoints](https://docs.aws.amazon.com/general/latest/gr/verifiedpermissions.html)).
- Cedar: CNCF Sandbox since 2025-10-08 ([InfoQ](https://www.infoq.com/news/2026/01/cedar-joins-cncf-sandbox/)); Python bindings via `cedarpy` ([repo](https://github.com/k9securityio/cedar-py)).
- OPA: its maintainers moved to Apple in Aug 2025; it stays in CNCF ([blog](https://www.openpolicyagent.org/blog/note-from-teemu-tim-and-torin-to-the-open-policy-agent-community-2dbbfe494371)).
- AgentCore Policy covers AgentCore Gateway tools only ([docs](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html)).

**Recommendation:** keep a network policy service off the remediation hot path. Keep the Python
policies. Later, optionally, Cedar files evaluated in-process with `cedarpy`, with the policy version
included in the plan hash.

## 6. TypeSafe Jev

- Announced 2026-09-15; early access only; $0.042 per million input tokens; hosted only, with no
  weights or self-host option; retention and SOC 2 undocumented; vendor-run benchmarks only
  ([announcement](https://typesafe.ai/blog/introducing-system-one-models-and-jev), [MarkTechPost](https://www.marktechpost.com/2026/09/19/typesafe-ai-releases-jev/)).
- **Do not adopt.** Instead: calibration on independent labels, Wilson bounds, and conformal
  thresholds ([conformal risk control](https://arxiv.org/html/2606.29054v1), [calibration in production agents](https://zylos.ai/research/2026-04-18-llm-calibration-uncertainty-production-agents)).

## Cost of the recommendations

| Item | Cost |
|---|---|
| KMS signing | about $13/yr |
| S3 Object Lock, cross-bucket trail | a few $/month |
| WebAuthn, STS, `cedarpy`, Rekor | $0 |
