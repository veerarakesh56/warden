"""Turn the raw output of `scripts/aws_proof.sh` into a readable, publishable evidence bundle.

Two jobs, and the second matters as much as the first:

1. **Summarise what WARDEN actually said** about each situation, from the JSON reports rather than
   from anyone's memory of the terminal.
2. **Make the bundle safe to publish.** A real run names a real AWS account in every ARN, and the
   RDS DSN carries a password. Both are stripped here, so the file that gets read by other people
   is the file that was produced - not a hand-edited copy of it.

⚠ This does NOT re-verify anything. It reports what the reports contain. A situation that failed
says so; there is no path in this file that turns a failure into a pass.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re

SITUATIONS = [
    ("A-ecs-healthy", "ECS, healthy", "Real task counts from `ecs:DescribeServices` and real CPU/memory from `cloudwatch:GetMetricData`."),
    ("B-ecs-force-new-deployment", "ECS, restarted", "`--force-new-deployment`: a new deployment record with the **same** task definition. WARDEN must report **no deploy**."),
    ("C-ecs-bad-deploy", "ECS, bad deploy", "A real image change plus real OOM kills produced by Fargate. The rollback is proposed and the policy gate permits it."),
    ("D-eks", "EKS", "The existing Kubernetes backend on **managed EKS**, not k3d. No new code, no IRSA, no cloud API call from the pod."),
    ("E-rds", "RDS PostgreSQL", "The existing database backend against a real RDS instance. RDS speaks the ordinary wire protocol; there is no bespoke RDS backend and this says so."),
]


def _redact(text: str, account: str) -> str:
    """Account id, then anything that still looks like one, then any password in a DSN."""
    if account:
        text = text.replace(account, "<ACCOUNT>")
    text = re.sub(r"\b\d{12}\b", "<ACCOUNT>", text)
    text = re.sub(r"(?<=://)([^:/@\s]+):([^@/\s]+)(?=@)", r"\1:********", text)
    return text


def _load(path: pathlib.Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def _summarise(report: dict) -> list[str]:
    ctx = report.get("context") or {}
    verdict = report.get("verdict") or {}
    proposal = report.get("proposal") or {}
    root = report.get("root_cause") or {}
    metrics = ctx.get("metrics") or {}

    read = (
        f"- **evidence read**: {len(ctx.get('logs') or [])} log lines, "
        f"{len(metrics)} metrics, {len(ctx.get('recent_deploys') or [])} deploy(s)"
    )
    lines = [read]
    if metrics:
        shown = ", ".join(f"`{k}`={v:g}" for k, v in sorted(metrics.items()))
        lines.append(f"- **metrics**: {shown}")
    if ctx.get("tool_errors"):
        lines.append(f"- **partial context** (policy P8 sees this): {'; '.join(ctx['tool_errors'])}")
    if root:
        lines.append(f"- **hypothesis**: {root.get('hypothesis', '?')} (confidence {root.get('confidence', 0):.2f})")
    if proposal:
        lines.append(f"- **proposed**: `{proposal.get('action')}` -> `{proposal.get('target')}`, blast radius `{proposal.get('blast_radius')}`")
    if verdict:
        policies = ", ".join(verdict.get("policy_ids") or []) or "none fired"
        lines.append(f"- **verdict**: **{str(verdict.get('status', '?')).upper()}** ({policies})")
    cost = report.get("cost") or {}
    if cost:
        lines.append(f"- **model cost**: ${cost.get('usd', 0):.4f} over {cost.get('calls', 0)} call(s)")
    return lines


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--account", default="")
    ap.add_argument("--region", default="")
    ap.add_argument("--cluster", default="")
    ap.add_argument("--service", default="")
    ap.add_argument("--eks", default="")
    args = ap.parse_args()

    out = pathlib.Path(args.dir)
    reports = out / "reports"

    # Redact EVERY file in the bundle in place. Anything published comes from these files, so they
    # are the ones that must be clean — not a copy made later by hand.
    #
    # ⛔ The JSON reports are not the only exposure and were nearly the only thing scrubbed. The
    # terminal transcript in run.log carries `terraform output`, `aws ecs describe-services` and
    # `kubectl` output, and an ECS or IAM ARN contains the account id in full. A bundle committed
    # to a public repo with a clean PROOF.md and an unredacted run.log beside it is the same leak
    # with an extra step.
    for path in sorted([*reports.glob("*.json"), *reports.glob("*.txt"), *out.glob("*.log"),
                        *out.glob("*.txt")]):
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        path.write_text(_redact(raw, args.account), encoding="utf-8")

    body: list[str] = [
        "# WARDEN against a real AWS account",
        "",
        f"Run: `{out.name}` · region `{args.region}` · account `<ACCOUNT>` (redacted)",
        "",
        "Every number below was read from a live AWS account by `src/warden/aws_backend.py`,",
        "`src/warden/k8s_backend.py` and `src/warden/database.py`. Nothing here is a fixture.",
        "",
        "| | Read by | Service |",
        "|---|---|---|",
        f"| ECS + CloudWatch | `WARDEN_BACKEND=aws` | cluster `{args.cluster}`, service `{args.service}` |",
        f"| EKS | `WARDEN_BACKEND=k8s` | {'cluster `' + args.eks + '`' if args.eks else '_skipped_'} |",
        "| RDS | `WARDEN_BACKEND=postgres` | `db.t4g.micro`, PostgreSQL 16 |",
        "",
    ]

    b_verdict = (reports / "B-verdict.txt").read_text(encoding="utf-8").strip() if (reports / "B-verdict.txt").exists() else "unknown"

    for key, title, why in SITUATIONS:
        report = _load(reports / f"{key}.json")
        body += [f"## {title}", "", why, ""]
        if report is None:
            body += ["_not run, or the report was not written._", ""]
            continue
        body += _summarise(report)
        if key == "B-ecs-force-new-deployment":
            body += [
                "",
                {
                    "pass": "✅ **No deploy was reported.** A `--force-new-deployment` moves the "
                            "deployment record without changing the task definition, so it is not a "
                            "template change. Reporting it would have handed policy P5 the evidence "
                            "it requires for a rollback that could not possibly have helped.",
                    "fail": "⛔ **A deploy WAS reported for a restart.** This is the exact defect the "
                            "design exists to prevent, and it is recorded here rather than quietly "
                            "dropped.",
                }.get(b_verdict, f"_check inconclusive: {b_verdict}_"),
            ]
        body.append("")

    body += [
        "## What this does not prove",
        "",
        "- The proving ground runs in **public subnets with public IPs**. That is a cost decision",
        "  (a NAT Gateway costs more than everything else here combined), not a recommendation. The",
        "  deployment module in `terraform/` uses private subnets.",
        "- The ECS incident is **staged**: a task definition that allocates more memory than the",
        "  task is given. The *kill* is real and so is every signal WARDEN reads, but the cause was",
        "  chosen rather than encountered.",
        "- One run of each situation. This is a demonstration that the path works end to end against",
        "  real AWS, not a measurement of how often it is right.",
        "",
        "## Screenshots worth taking while it is up",
        "",
        "The JSON in `reports/` is the evidence; console screenshots are for people who will not",
        "read JSON. Take them during situation C, when the service is visibly unhealthy.",
        "",
        "| Console page | What it shows | ⛔ Crop out |",
        "|---|---|---|",
        "| ECS -> cluster -> service -> **Deployments** | two revisions, the failed rollout | account id in the top bar |",
        "| ECS -> service -> **Tasks**, filter *Stopped* | stopped reason: `OutOfMemoryError: Container killed due to memory usage` | task ARNs contain the account id |",
        "| CloudWatch -> **Log groups** -> `/ecs/checkout` | the allocation lines, then the container dying | — |",
        "| CloudWatch -> **Metrics** -> ECS -> ClusterName, ServiceName | the CPU/memory series WARDEN read | — |",
        "| IAM -> Roles -> `warden-task` -> the inline policy | **exactly four actions** | account id in the ARN |",
        "| EKS -> cluster -> **Compute** | one node, `SPOT` | account id |",
        "| RDS -> databases | `db.t4g.micro`, `available` | endpoint contains the account id |",
        "| **Billing -> Budgets** | the $5 budget that guards the run | — |",
        "",
        "⛔ **Before posting any of them:** blur the 12-digit account id (top-right menu and every",
        "ARN), the RDS endpoint, and any public IP. None of it is catastrophic on its own; all of it",
        "is free reconnaissance for someone else.",
        "",
        "## Cost of this run",
        "",
        "About **$0.13 per hour** while it was up, dominated by the EKS control plane at $0.10/hour.",
        "`terraform destroy` runs from an EXIT trap, and `teardown-remaining.txt` in this directory",
        "records how many tagged resources were still alive afterwards. **It should read `0`.**",
        "",
    ]

    text = _redact("\n".join(body), args.account)
    (out / "PROOF.md").write_text(text, encoding="utf-8")
    print(f"wrote {out / 'PROOF.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
