# AWS Agent Toolkit and the AWS MCP servers as evidence sources (requirement R57)

Read live 2026-10-03 (06:30 UTC / 12:00 IST). Question: should WARDEN read evidence through any AWS MCP server or
the Agent Toolkit instead of, or beside, its own fixed boto3 readers?

WARDEN's rule: the model never chooses what is read. WARDEN's code makes fixed reads with read-only IAM; untrusted
text is redacted and quarantined into typed facts before any model sees it.

Criteria: (1) adds a read WARDEN lacks; (2) can be pinned and restricted to a fixed read list WARDEN chooses;
(3) keeps the model from choosing reads, with untrusted text quarantined; (4) supply chain; (5) maintenance.

## Verdict: adopt none

Every server exists so that a model can choose calls - free-form API calls, Python, SQL, Logs Insights or Lake
queries - which is what WARDEN's design forbids. None returns typed facts: each returns raw text, so the
quarantine would still be needed and no WARDEN code would go away. The local awslabs servers are being replaced by
the managed one, and the SQL servers have repeated read-only bypass advisories.

The one gap found is CloudTrail: WARDEN's stack reader has no `cloudtrail` client. If CloudTrail evidence is
wanted, a fixed boto3 `cloudtrail.lookup_events` reader inside WARDEN - fixed filters for the resource and window,
read-only IAM, output quarantined - is cheaper and safer than any server. The change timeline (G6) plans it.

## Candidates

1. **AWS MCP Server (managed, in the Agent Toolkit for AWS).** GA 2026-05-06 (preview 2025-11-30); no extra
   charge. Repo aws/agent-toolkit-for-aws, Apache-2.0, "the successor to the MCP servers, plugins, and skills
   available on AWS Labs". Remote HTTPS, OAuth or SigV4 via `mcp-proxy-for-aws-cli` (v1.7.0, 2026-09-15). No India
   region. Tools include `aws___run_script` (Python with AWS API access in a sandbox); the 2026-03-02 Security Blog
   describes `aws__call_aws` ("can execute any AWS API operation"). The proxy's `--read-only` hides tools by the
   server's own `readOnlyHint`; AWS says IAM is the real boundary, with new keys `aws:ViaAWSMCPService` and
   `aws:CalledViaAWSMCP`. Raw text results. Fails (1), (2), (3): generic, model-chosen API access. Revisit only if
   it offers fixed typed operations, gets an India region, and WARDEN would call it deterministically - and even
   then it is a remote boto3 with an extra hop.
2. **AWS API MCP Server** (`awslabs.aws-api-mcp-server` 1.5.6, 2026-09-30). README: superseded by the AWS MCP
   Server. `call_aws` runs model-written CLI commands; `READ_OPERATIONS_ONLY` checks a known read-only list. README:
   "Do not connect this MCP server to data sources with untrusted data". CVE-2026-16584 (high: a failed start-up
   skipped the policy check for the process's life; fixed 1.3.47) and CVE-2026-4270 (file-access bypass; fixed
   1.3.9). Fails (2), (3), (5).
3. **CloudWatch MCP server** (0.3.1, 2026-09-22). Metric data, active alarms, alarm history, Logs Insights,
   PromQL; read-only, stdio. Raw logs, no injection guidance. WARDEN already reads metrics and runs Logs Insights;
   alarm history would be one boto3 call. Fails (1), (3).
4. **CloudTrail MCP server** (0.1.1, 2026-09-08). `lookup_events`, `lake_query`. Passes (1); fails (2), (3) - the
   model picks filters and writes SQL - and is pre-1.0. CloudTrail Lake is closed to new customers since
   2026-05-31 (see build-or-adopt.md).
5. **ECS MCP server** (local 0.1.36, labelled legacy; managed in preview since 2025-11-21). Writes off by default,
   sensitive data redacted by default. WARDEN already reads ECS. Fails (1), (5).
6. **EKS MCP server** (local 0.2.1; managed in preview). `--allow-write` off by default; logs and events need
   `--allow-sensitive-data-access`. `get_eks_insights` is a modest addition. Fails (3), (5) while in preview.
7. **DynamoDB MCP server** (2.1.8): data modelling and code generation only; GHSA-35jj-hwvm-792x (code injection,
   high, 2026-09-08). Not relevant.
8. **ElastiCache MCP server** (0.2.1): `--readonly`, but 40+ tools including jump hosts and SSH tunnels. WARDEN
   already reads ElastiCache. Fails (1), (2).
9. **Aurora PostgreSQL / MySQL MCP servers** (1.2.2 / 1.1.3): model-generated SQL; the postgres README calls its
   read-only checks "best-effort". GHSA-fph8-pg5w-78fv (critical: read-only bypass to OS command execution,
   2026-09-09), GHSA-pwr4-hmph-gqgc, GHSA-x25m-ph3m-3r9q. Fails (2), (3), (4).
10. **Performance Insights:** no server found on PyPI today (an earlier summary of the awslabs README listed one;
    unconfirmed). WARDEN already calls `pi.get_resource_metrics`.
11. **Lambda Tool MCP server** (2.1.1): invokes functions - running code, not reading evidence. Not relevant.

## Sources (all read 2026-10-03)

1. https://aws.amazon.com/about-aws/whats-new/2026/05/agent-toolkit
2. https://github.com/aws/agent-toolkit-for-aws
3. https://docs.aws.amazon.com/agent-toolkit/latest/userguide/getting-started-aws-mcp-server.html
4. https://docs.aws.amazon.com/aws-mcp/latest/userguide/understanding-mcp-server-tools.html
5. https://aws.amazon.com/blogs/security/understanding-iam-for-managed-aws-mcp-servers
6. https://github.com/aws/mcp-proxy-for-aws ; https://pypi.org/pypi/mcp-proxy-for-aws-cli/json
7. https://raw.githubusercontent.com/awslabs/mcp/main/src/aws-api-mcp-server/README.md
8. https://aws.amazon.com/security/security-bulletins/2026-063-aws/
9. https://osv.dev/vulnerability/GHSA-2cpp-j2fc-qhp7 (CVE-2026-4270)
10. https://raw.githubusercontent.com/awslabs/mcp/main/src/cloudwatch-mcp-server/README.md
11. https://raw.githubusercontent.com/awslabs/mcp/main/src/cloudtrail-mcp-server/README.md
12. https://aws.amazon.com/about-aws/whats-new/2025/11/amazon-eks-ecs-fully-managed-mcp-servers-preview/
13. https://raw.githubusercontent.com/awslabs/mcp/main/src/ecs-mcp-server/README.md
14. https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-mcp-introduction.html
15. https://raw.githubusercontent.com/awslabs/mcp/main/src/eks-mcp-server/README.md ;
    https://docs.aws.amazon.com/eks/latest/userguide/eks-mcp-introduction.html
16. https://raw.githubusercontent.com/awslabs/mcp/main/src/dynamodb-mcp-server/README.md
17. https://raw.githubusercontent.com/awslabs/mcp/main/src/elasticache-mcp-server/README.md
18. https://raw.githubusercontent.com/awslabs/mcp/main/src/postgres-mcp-server/README.md
19. https://github.com/awslabs/mcp (Apache-2.0; server list)
20. https://github.com/awslabs/mcp/security/advisories
21. PyPI JSON API (`https://pypi.org/pypi/<package>/json`) for every version and release date above.
