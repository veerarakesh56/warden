# Setting up WARDEN in your own AWS account and GitHub repository

This guide takes you from a fork of this repository to a running WARDEN: the AWS roles, the GitHub
environments, the secrets, Temporal Cloud, Slack and the model key. It describes what the code in this
repository expects today. Where a value is yours (account id, repository name, domain), it is written as a
placeholder such as `<ACCOUNT_ID>` or `<your-org>/<your-repo>`.

Nothing here stores a long-lived AWS key. GitHub Actions reaches AWS through OpenID Connect (OIDC), and every
secret WARDEN reads at run time lives in AWS Secrets Manager.

> **Read [ai-boundary.md](ai-boundary.md) and [ARCHITECTURE.md](ARCHITECTURE.md) first.** WARDEN can change
> infrastructure after a signed approval. Set it up in an account you can afford to experiment in.

## 1. Before you start

You need:

- An AWS account, and an administrator identity for the one-time steps below (not the root user).
- A GitHub repository holding this code (a fork or a copy).
- Python 3.12 and [uv](https://docs.astral.sh/uv/) on the machine you set up from; Terraform 1.16 for local plans.
- A Temporal Cloud namespace (section 6), a Slack workspace where you may install an app (section 7), and an
  Anthropic API key (section 8).

Costs: IAM, OIDC, GitHub environments and Parameter Store (Standard tier) are free. Each Secrets Manager secret
costs about USD 0.40 a month. The runtime itself (section 5) and the full-stack lab
([FULLSTACK-LAB.md](FULLSTACK-LAB.md)) bill by the hour while they are up; check current AWS prices for your
Region before you start them.

## 2. Tell the code about your account and repository

Two data files hold every per-install value the code needs. Code never names a Region, an account or an
environment of its own.

`src/warden/data/environments.yaml`:

| Key | Set it to |
|---|---|
| `aws_region` | the Region everything runs in. Any process honours `AWS_REGION` first, as every AWS tool does. |
| `display_zone` | the IANA time zone times are shown in beside UTC (for example `Europe/London`). |
| `runtime` | WARDEN's own environment name (`ops` by default). |
| `fault_environments` | the only environments where the benchmark harness and the undo lab may inject faults. |
| `github.repository` | `<your-org>/<your-repo>` |
| `github.subject` | GitHub's immutable OIDC subject for your repository, `<owner>@<owner-id>/<repo>@<repo-id>`. Read the two ids with `gh api repos/<your-org>/<your-repo> --jq '.owner.id, .id'`. |
| `environments.<name>` | one entry per application environment, with what WARDEN may do there. An unlisted environment falls to `default`, which can only do nothing or escalate. |

`src/warden/data/providers.yaml` lists the models WARDEN has qualified. The runtime refuses a model that is not
on its `qualified` list (section 8).

Some of these files are safety-pinned: `docs/safety-pins.sha256` holds their hashes and a test fails when a file
changes without the pins being re-rendered. After editing them, run:

```bash
PYTHONPATH=src python scripts/safety_pins.py
```

## 3. AWS identities

All IAM documents are rendered from `iam/templates/` into `iam/<env>/` by one script:

```bash
python scripts/render_env_iam.py            # the committed files, with <ACCOUNT_ID> as a placeholder
python scripts/render_env_iam.py --account  # also *.local.json copies with your real account id, for pasting
```

The `*.local.json` files are git-ignored and must never be committed. `tests/test_env_iam.py` fails if a
committed file drifts from its template. `scripts/check_live_iam.py` compares what is live in your account with
these files (read-only).

### 3a. GitHub's identity provider (once per account)

IAM → **Identity providers** → **Add provider** → **OpenID Connect**, provider URL
`https://token.actions.githubusercontent.com`, audience `sts.amazonaws.com`. Skip this if it already exists.

### 3b. One deploy role per application environment

For each environment in `environments.yaml` that you deploy (`dev` shown):

1. Create three managed policies from the complete files: `WardenEnvBoundary-dev` from `iam/dev/boundary.json`,
   `WardenEnvDeploy-dev` from `iam/dev/deploy.json` and `WardenEnvDeployEc2-dev` from `iam/dev/deploy-ec2.json`.
   (The deploy permissions are two policies because one would pass IAM's 6,144-character limit.)
2. Create the role `warden-dev-deploy` with a custom trust policy: the whole of `iam/dev/trust.local.json`.
   Attach the two deploy policies, set the permissions boundary to `WardenEnvBoundary-dev`, and tag it
   `Project=warden`, `Environment=dev`.
3. Create the state bucket `warden-dev-tfstate-<random suffix>` in your Region: versioning on, public access
   blocked, default encryption.
4. Create two Parameter Store values (Standard tier): `/warden/dev/tf/my_ip_cidr` (String, the CIDR allowed to
   reach the EKS API, never `0.0.0.0/0`) and `/warden/dev/tf/budget_email` (SecureString, where budget alarms go).

The trust policy accepts only a token from your repository's GitHub environment of the same name, running one of
the two reusable deploy workflows (`_infra-deploy.yml`, `_apps-deploy.yml`) from the branch the template names.
The callers (`deploy-<env>.yml`, `on-merge-<env>.yml`) can be renamed; the two reusable workflows cannot, unless
the template changes with them.

### 3c. WARDEN's own roles in each watched environment

The runtime worker reads and acts in an application environment through two roles there, both rendered into
`iam/<env>/`:

| Role | Policies | What it is for |
|---|---|---|
| `warden-<env>-platform-reader` | `platform-reader.json` and `platform-diagnose.json` | reading the evidence a diagnosis and a fix need |
| `warden-<env>-actor` | `actor.json` | one approved change: the worker takes it for 15 minutes, for one plan, with the incident and the approvers as session tags |

Create each with its `*-trust.local.json`, a maximum session of 1 hour, and the tags `Project=warden`,
`Environment=<env>`. Create them after the runtime (section 5) exists, because their trust names the runtime's
zone roles.

### 3d. Optional: the operator and the fault-injection harness

- `iam/operator/` is a read-only operator role for a person's workstation (it sees the runtime's secret names,
  never their values, and may assume only the read-only
  sweep role `warden-ops-sweep`, whose policy is `iam/operator/sweep-policy.json`, and the harness role). `scripts/roles_anywhere_cert.py` issues a certificate for IAM Roles
  Anywhere, so the workstation needs no access key.
- `iam/<env>/harness.json` and `harness-trust.json` exist only for the environments in `fault_environments`. The
  harness role breaks and restores only that environment's resources; render it with
  `python scripts/render_env_iam.py --account --cluster-resource-id <id>` once the lab's Aurora cluster exists.

### 3e. Account-wide pieces

- **API access-log delivery** (for the lab's HTTP API): one CloudWatch Logs resource policy letting
  `delivery.logs.amazonaws.com` write to `/aws/vendedlogs/warden-*` in your account and Region. The deploy role
  may not create resource policies, so an administrator creates it once.
- **Global-services alarms** (CloudFront, Route 53 health checks) live only in AWS's global Region
  (`aws_global_region`). `python scripts/forward_global_alarms.py` prints the forwarding rule it would make;
  `--apply` makes it and `--undo` removes it.
- **IAM Access Analyzer** (free): an external-access analyzer in your Region flags any role, bucket, key, queue,
  secret or function reachable from outside the account.
- **A budget** for the whole account, alarming on forecast as well as actual spend.

### AWS Config, so WARDEN can undo a recorded change

The `revert_change` fix sets a value back to what AWS Config recorded just before the change. Without a
recorder those plans are refused and nothing else changes. One recorder per account and Region.

1. **AWS Config** → your Region → **Settings**.
2. Recording strategy **Specific resource types**, frequency **Continuous**, with these types (the ones
   `src/warden/platforms/aws.py` reads): `AWS::ECS::Service`, `AWS::Lambda::Function`,
   `AWS::AutoScaling::AutoScalingGroup`, `AWS::ApiGateway::Stage`, `AWS::SQS::Queue`, `AWS::Kinesis::Stream`,
   `AWS::EC2::RouteTable`, `AWS::DynamoDB::Table`.
3. IAM role: the AWS Config service-linked role.
4. Delivery: a new bucket such as `warden-<env>-config-<suffix>`, no SNS topic.

Check it, read-only: `python scripts/check_live_config.py`. It exits 0 when the recorder is on, records
continuously, delivers, and records every type the code reads. `tests/test_restore_table_g10f.py` fails if the
code reads a type this list does not name.

## 4. GitHub

### 4a. Environments

Repository → **Settings** → **Environments**. Create one environment per deployable environment and one for the
runtime:

| Environment | Secrets | Variables | Protection |
|---|---|---|---|
| each application environment (`dev`, `prod`, ...) | `AWS_ROLE_ARN` (the `warden-<env>-deploy` role); optional `EKS_ADMIN_ROLE_ARNS` (roles given EKS admin access, comma-separated) | `AWS_REGION`, `TF_STATE_BUCKET`; optional `EKS_PUBLIC_CIDRS` (who may reach the EKS API during a deploy) | `prod`: a required reviewer, so a person approves every prod deploy |
| `ops` (the runtime) | `AWS_ROLE_ARN` (`warden-ops-deploy`), `RUNTIME_ECR_REPOSITORY` (the image repository URI), `HF_TOKEN` (a Hugging Face read token for the gated Prompt Guard 2 weights the image bakes in) | `AWS_REGION`, `TF_STATE_BUCKET` | a required reviewer: the runtime spends model credit and runs paid infrastructure |

Role ARNs and the repository URI are secrets, not variables, because they contain the account id and GitHub
prints variables unmasked in a public repository's logs.

<!-- branch-model -->
### 4b. Which branch deploys what

An environment deploys only from the branch of its own name, and `main` deploys nothing.

| Branch | What a push to it does |
|---|---|
| `main` | CI only: tests, lint and scans. No workflow that can reach AWS runs on a push to `main` or on a pull request. |
| `dev` | Deploys the `dev` environment (`on-merge-dev.yml`). `dev` is `main` fast-forwarded: `git push origin <main-sha>:dev`. |
| `prod` | Deploys the `prod` environment (`on-merge-prod.yml`); every job waits for the `prod` environment's required reviewer, so a person approves it. `prod` is `dev` merged by pull request with "Create a merge commit". |

A deploy can also be run by hand from the same branch (`deploy-<env>.yml`). Before any job holds a credential, it
checks that the commit was promoted: it is on the upstream branch (`main` for dev, `dev` for prod), or it is a merge
of it that changes nothing. A commit pushed straight onto `dev` or `prod` is refused, and the push that creates a
branch deploys nothing. The deploy roles' trust policies (`iam/<env>/trust.json`) accept only `refs/heads/<env>`.

The runtime pipeline (`runtime.yml`, GitHub environment `ops`) runs from the branch `environments.yaml` names in
`github.runtime_branch`: `dev`, until prod exists.

Set each GitHub environment's **Deployment branches** to the single branch of its own name (`dev` for dev, `prod`
for prod, the runtime branch for `ops`), and give `prod` and `ops` a required reviewer.

An infra change is never applied on a push. A push plans and keeps the saved plan and its SHA-256 in the state
bucket; the apply is a manual `deploy-<env>.yml` run with `infra_action=apply-plan`, that run id and that hash, at
the same commit.
<!-- /branch-model -->

### 4c. Repository settings worth turning on

- A ruleset on the default branch that blocks deletion and force pushes.
- Rulesets on `dev` and `prod` that block deletion and force pushes and require the `zizmor` status check;
  on `prod`, also require a pull request and allow merge commits only.
- **Require actions to be pinned to a full-length commit SHA** (every workflow here is pinned, and
  `tests/test_ci_lanes.py` checks it).
- Dependabot alerts and security updates, and CodeQL default setup. All free on a public repository.

## 5. WARDEN's runtime (`ops`)

The runtime is `terraform/runtime` (with `terraform/modules/warden-runtime`), deployed only by
`.github/workflows/runtime.yml`, by hand. Its actions are `image` (build, push by commit SHA, sign keylessly with
cosign and attest), `plan`, `apply` (each verifies that signature first) and `restart`.

1. Create `WardenEnvBoundary-ops`, `WardenEnvDeploy-ops` and `WardenEnvDeployEc2-ops` from `iam/ops/`, and the
   role `warden-ops-deploy` with `iam/ops/trust.local.json` (maximum session 2 hours: creating the audit database
   can take most of one).
2. Create the state bucket `warden-ops-tfstate-<suffix>` and an ECR repository `warden-ops-runtime` with
   immutable tags and scan on push. Allow Lambda to pull from it with a repository policy limited to your
   account's `warden-ops-*` functions.
3. Create an SNS topic for WARDEN's own pages (subscribe your on-call address) and these Parameter Store values:

   | Name | Value |
   |---|---|
   | `/warden/ops/tf/page_topic_arn` | the topic's ARN |
   | `/warden/ops/tf/watched_environments` | the environments WARDEN watches, comma-separated |
   | `/warden/ops/tf/model_provider`, `/warden/ops/tf/model` | `anthropic` and a model on the `qualified` list (section 8) |
   | `/warden/ops/tf/audit_db_instances`, `/warden/ops/tf/worker_instances` | optional, default 2 each |
   | `/warden/ops/tf/approval_domain`, `/warden/ops/tf/approval_certificate_arn` | the approval page's domain (for example `approve.warden.<your-domain>`) and a DNS-validated ACM certificate for it in your Region; leave unset for no approval page |
   | `/warden/ops/tf/paused` | optional: `true` turns compute, the NAT route and alarm intake off between uses |
   | `/warden/ops/env/WARDEN_TEMPORAL_NAMESPACE`, `/warden/ops/env/WARDEN_TEMPORAL_ADDRESS` | section 6 |

4. Fill in the `ops` GitHub environment (section 4a), then run **Runtime · ops** with `image`, then `plan`. Read
   the plan before you run `apply`.
5. After the first apply, Terraform has created empty secret slots named `warden/ops/<name>`
   (`terraform/modules/warden-runtime/secrets.tf` lists them). Set the values in the console, never in a file or a
   chat, then run **Runtime · ops** with `restart`. Each trust zone's role reads only its own secrets.
6. Approvers: create each approver's Ed25519 key pair with
   `warden audit keygen --private ~/.warden/<name>.pem --public ~/.warden/<name>.pub.pem`. It asks for a passphrase
   and encrypts the private key with it. Both files must be inside the key folder, `WARDEN_KEY_DIR` (default
   `~/.warden`, created private if missing); a path outside it, through a symlink, or naming a file that exists is
   refused. Then `warden enrol --approver <name> --key ~/.warden/<name>.pem`
   opens a 15-minute link where the approver creates a passkey. Save the approver list the page shows as the
   Parameter Store value `/warden/ops/approvers` and restart the workers. [OPERATIONS.md](OPERATIONS.md) covers
   rotating keys and passkeys.
7. WARDEN's own pages repeat, in Slack and by email, every 15 minutes until an approver acknowledges them with a
   passkey at `https://<approval domain>/p` (`terraform/modules/warden-runtime/paging.tf`). `/p` needs Sign in with
   Slack (below) and an approver entry with no `environments` whose `slack` is that person's member id: without the
   Slack app nobody reads or acknowledges the pages there, and they repeat until it is set up. Confirm the topic's
   email subscription, and make `warden/ops/slack-webhook` a webhook of the channel to page. Optional:
   - `/warden/ops/env/WARDEN_TEMPORAL_KEY_EXPIRES`: each Temporal API key's end, ISO times, comma-separated; a key
     ending within 7 days pages. Update it whenever a key is rotated.
   - `/warden/ops/tf/page_repeat_minutes`: how often a page repeats (default 15).
   - `/warden/ops/tf/monthly_budget_usd`: a monthly cost budget before credits, emailing the topic at 80% spent and
     100% forecast. It needs `budgets:ViewBudget` and `budgets:ModifyBudget` in `WardenEnvBoundary-ops` and
     `WardenEnvDeploy-ops`, and a statement in the topic's access policy letting `budgets.amazonaws.com` publish.
   A fix that was verified and did not hold is not offered again on WARDEN's own until an approver signs
   `warden offer-again <incident> --approver <name> --key <private key file>` where the audit is reached.

## 6. Temporal Cloud

WARDEN's workflows run on Temporal. Create a namespace in Temporal Cloud and note its name (`name.account`) and its
gRPC address (`host:7233`); neither is secret, and they go into the two Parameter Store values above.

Create one namespace-scoped service account per trust zone, so Temporal's audit log names the zone that called:
`warden-ops-core`, `-read`, `-llm`, `-notify`, `-act` and `-critic` (Eldane, below), each with the namespace permission **Write** (a worker
needs it to poll and complete tasks). Store each API key in its slot `warden/ops/temporal-api-key-<zone>`. Give
every key an expiry and replace it before then.

Workflow payloads are encrypted before they reach Temporal (`src/warden/codec.py`). Store 32 random bytes,
base64-encoded, in `warden/ops/temporal-key`, for example from CloudShell without displaying it:

```bash
aws secretsmanager put-secret-value --secret-id warden/ops/temporal-key \
  --secret-string "$(head -c 32 /dev/urandom | base64)"
```

### Eldane, the AI critic (dev's approver)

The sixth zone, `critic`, runs Eldane (`src/warden/eldane.py`). Until the two steps below are done it does nothing,
and a person approves every plan in dev as in prod. Its model key is the diagnosis's own
`warden/ops/anthropic-api-key`, which the critic zone may read too; it uses, for each incident, the other Claude
model from the one that diagnosed it (`src/warden/data/providers.yaml`, `critic`).

1. Its Temporal key: the service account `warden-ops-critic` above, its key in `warden/ops/temporal-api-key-critic`.
2. Its signing key, on your own machine: `warden audit keygen --private eldane.pem --public eldane.pub.pem
   --unencrypted`. Put the whole of `eldane.pem` into `warden/ops/eldane-key`, then delete the file. Add Eldane to the
   approver list (`/warden/ops/approvers`) with the contents of `eldane.pub.pem`:
   `eldane: {public_key: "<eldane.pub.pem>", tiers: [T1, T2], environments: [dev], ai: true}`. WARDEN always shows it
   as "Eldane · AI critic", refuses it for T3 and in prod, and a person's "no" on the approval page stops any plan it
   approved until the apply step starts. Demotions and a person's re-enable are in [OPERATIONS.md](OPERATIONS.md).

## 7. Slack

WARDEN posts one message per incident to an alerts channel and can answer questions in a second, discussion
channel. Create one Slack app (api.slack.com/apps):

| What | Where it goes |
|---|---|
| an incoming webhook for the alerts channel | secret `warden/ops/slack-webhook` |
| or, instead of the webhook, the bot token and channel id | secret `warden/ops/slack-bot-token`; plain value `/warden/ops/env/WARDEN_SLACK_CHANNEL` |
| Sign in with Slack on the approval page and the records page: the app's client id and client secret | plain value `/warden/ops/env/WARDEN_SLACK_CLIENT_ID`; secret `warden/ops/slack-client-secret` |
| the discussion channel (Socket Mode): an app-level token with `connections:write`, bot scopes `app_mentions:read`, `chat:write`, `channels:history` (and `groups:history` for a private channel), the `app_mention` event | secret `warden/ops/slack-app-token`; plain value `/warden/ops/env/WARDEN_DISCUSS_CHANNEL` |
| each environment's own channels, so one environment's incidents never reach another's channel (with the bot token; recommended once there is more than one environment) | plain values `/warden/ops/env/WARDEN_SLACK_CHANNELS` (alerts) and `/warden/ops/env/WARDEN_DISCUSS_CHANNELS` (discussion), each `env=channel-id[,env=channel-id]`; with them the webhook is not used for Slack, and an environment the map does not name gets no Slack message |
| who besides the approvers may read the records page | plain value `/warden/ops/env/WARDEN_RECORD_VIEWERS` (Slack member ids, comma-separated) |

Socket Mode means WARDEN connects out to Slack, so Slack needs no public address of yours and no signing secret.
[OPERATIONS.md](OPERATIONS.md) has the discussion-channel steps and the per-environment channel maps in detail.

## 8. The model

The runtime calls Claude through the Anthropic API. Create an API key for the runtime alone (a service account in
the Claude Console, with an expiry) and store it in `warden/ops/anthropic-api-key`. Only the llm zone can read it.

The model must be on `qualified` in `src/warden/data/providers.yaml`, measured on the pinned prompt (`prompt.sha`
there). The deploy checks only that the model is on the list; at run time a model with no row on the pinned prompt is
refused, and every incident is then escalated to a person on the rules alone. As of 2026-10-21 no model is qualified
on the pinned prompt: `claude-sonnet-5-5` passed on an earlier prompt only, so the runtime runs on the rules alone
until it is measured again. To qualify a model, run `scripts/qualify_cloud.py` (one command, with the runtime's own
key; it spends API credit and writes the result into the repository: see [BENCHMARKS.md](BENCHMARKS.md)).

## 9. Check the setup

- `python scripts/check_live_iam.py` - every policy and trust live in AWS against its file (read-only).
- `python scripts/check_live_config.py` - the AWS Config recorder (read-only).
- `python scripts/account_sweep.py` (through the read-only sweep role) - every Region and service, listed by service, never trusting tags: what
  exists and what it costs. Run it after every tear-down.
- A first **Deploy · dev** run with `part=infra`, `infra_action=plan` proves the deploy role's trust without
  changing anything.
- An alarm in a watched environment (or a test alert to the Alertmanager webhook) should produce one Slack
  message with a **Full record** link. See [RUNBOOK-WARDEN-INCIDENT.md](RUNBOOK-WARDEN-INCIDENT.md) for what to
  do when WARDEN itself misbehaves.

## Undo

Delete in reverse order: the runtime (`runtime.yml` cannot destroy it; run `terraform destroy` in
`terraform/runtime` with the `ops` workspace and the deploy role), its secrets, parameters, repository and state
bucket; then each environment's actor, reader and deploy roles, their policies and state buckets; then the GitHub
environments. Finish with `python scripts/account_sweep.py`.
