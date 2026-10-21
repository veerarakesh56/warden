"""Reduce a `terraform show -json` document (state or plan) to the topology Helios reads.

    python scripts/scrub_tfjson.py plan.json > fixtures/<name>/terraform-show.json
    python scripts/check_publishable.py --dir fixtures/<name>   # then check it

The input must lie inside the working directory (or come on stdin as `-`).

Real Terraform JSON carries every `sensitive` value in plaintext (database passwords,
`random_password.result`), environment variables, the account id in every ARN, and public IPs.
This keeps ONLY:

- resources whose type Helios models or uses to link resources (KEEP_TYPES);
- per resource, only topology attributes (KEEP_ATTRS, applied recursively into nested blocks such
  as `vpc_config`, `network_configuration`, `route`), and of `tags` only `Name`;
- in `configuration`, only the `references` arrays (every `constant_value` is dropped), plus the
  address/type/name that locate them;
- top-level `format_version`, `terraform_version`, `values`, `planned_values`, `prior_state`,
  `configuration`. Everything else (`variables`, `resource_changes`, outputs, ...) goes.

Then, in every remaining string: 12-digit account ids become 123456789012, and real resource ids
(`subnet-`, `vpc-`, `vpce-`, `nat-`, `rtb-`, `sg-`, `igw-`, `eni-`, `i-` with 8 or 17 hex digits,
any other 17-hex id, the 16-hex id a load balancer ARN ends in, and UUIDs) become deterministic
placeholders, the same one everywhere the id appears.

It is an allowlist, so a new attribute is dropped until someone adds it here on purpose.
Stdlib only.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import Any

KEEP_TYPES = {
    # Modelled today (crates/helios-graph/src/resource.rs).
    "aws_vpc", "aws_subnet", "aws_instance", "aws_lb", "aws_db_instance",
    "aws_elasticache_cluster", "aws_lambda_function", "aws_s3_bucket",
    # Modelled or used for links in 0.2.
    "aws_rds_cluster", "aws_rds_cluster_instance", "aws_db_subnet_group",
    "aws_elasticache_replication_group", "aws_elasticache_subnet_group",
    "aws_ecs_cluster", "aws_ecs_service", "aws_eks_cluster", "aws_eks_node_group",
    "aws_sqs_queue", "aws_lambda_event_source_mapping", "aws_vpc_endpoint",
    "aws_nat_gateway", "aws_route_table", "aws_route", "aws_route_table_association",
    "aws_main_route_table_association", "aws_default_route_table", "aws_iam_role",
}

# One allowlist for every kept type (and their nested blocks): these names mean the same topology
# thing wherever they appear, and none of them holds a secret.
# ponytail: one global set, not per type; split per type if a name ever means a secret somewhere.
KEEP_ATTRS = {
    # identity
    "id", "arn", "name", "bucket", "identifier", "cluster_identifier", "cluster_id",
    "cluster_name", "cluster", "replication_group_id", "node_group_name", "function_name",
    "function_arn", "service_name", "vpc_endpoint_type",
    # placement
    "region", "availability_zone", "availability_zones", "preferred_availability_zones",
    "preferred_cache_cluster_azs", "az_mode", "vpc_id", "subnet_id", "subnet_ids", "subnets",
    "cidr_block", "db_subnet_group_name", "subnet_group_name", "member_clusters",
    "cluster_members", "writer",
    # nested topology blocks
    "network_configuration", "vpc_config", "scaling_config",
    # capacity / failover
    "desired_count", "desired_size", "min_size", "max_size", "num_cache_clusters",
    "automatic_failover_enabled", "multi_az_enabled", "replicas_per_node_group", "multi_az",
    "launch_type",
    # queues / event sources
    "redrive_policy", "event_source_arn",
    # routing
    "nat_gateway_id", "gateway_id", "route", "route_table_id", "route_table_ids",
    "default_route_table_id",
    "destination_cidr_block",
    # IAM principals (iam-revocation)
    "role", "role_arn", "iam_role_arn", "node_role_arn", "iam_instance_profile",
    # handled specially: only Name survives
    "tags",
}

RESOURCE_KEYS = ("address", "mode", "type", "name", "index")
TOP_KEYS = ("format_version", "terraform_version", "values", "planned_values", "prior_state",
            "configuration")

PLACEHOLDER_ACCOUNT = "123456789012"
ACCOUNT_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
ID_RE = re.compile(
    r"\b(?:(subnet|vpc|vpce|nat|rtb|sg|igw|eni|i)-[0-9a-f]{8}"
    r"|(?:([a-z][a-z0-9]*)-)?[0-9a-f]{17})\b"
)
# The 16-hex id a load balancer / target group ARN ends in (`.../app/<name>/<id>`), and UUIDs
# (an event-source mapping's id, the end of a node group's ARN).
ELB_ID_RE = re.compile(r"(?<=/)[0-9a-f]{16}\b")
UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")


class Scrubber:
    def __init__(self) -> None:
        self.ids: dict[str, str] = {}
        self.counters: dict[str, int] = {}

    def _placeholder(self, m: re.Match[str]) -> str:
        real = m.group(0)
        if real not in self.ids:
            prefix = m.group(1) or m.group(2) or ""
            n = self.counters[prefix] = self.counters.get(prefix, 0) + 1
            self.ids[real] = f"{prefix}-{n:017x}" if prefix else f"{n:017x}"
        return self.ids[real]

    def _numbered(self, real: str, kind: str, fmt: str) -> str:
        if real not in self.ids:
            n = self.counters[kind] = self.counters.get(kind, 0) + 1
            self.ids[real] = fmt.format(n)
        return self.ids[real]

    def text(self, s: str) -> str:
        # Account first; the UUID placeholder starts its last group with a letter, so it is never an account id.
        s = ID_RE.sub(self._placeholder, ACCOUNT_RE.sub(PLACEHOLDER_ACCOUNT, s))
        s = UUID_RE.sub(lambda m: self._numbered(m[0], "uuid", "00000000-0000-0000-0000-a{:011x}"), s)
        return ELB_ID_RE.sub(lambda m: self._numbered(m[0], "elb", "{:016x}"), s)

    def strings(self, v: Any) -> Any:
        """Rewrite account and resource ids in every string (keys too), in document order."""
        if isinstance(v, str):
            return self.text(v)
        if isinstance(v, list):
            return [self.strings(x) for x in v]
        if isinstance(v, dict):
            return {self.text(k): self.strings(x) for k, x in v.items()}
        return v


def keep_attrs(v: Any) -> Any:
    if isinstance(v, list):
        return [keep_attrs(x) for x in v]
    if not isinstance(v, dict):
        return v
    out = {}
    for k, x in v.items():
        if k not in KEEP_ATTRS:
            continue
        if k == "tags":
            if isinstance(x, dict) and "Name" in x:
                out[k] = {"Name": x["Name"]}
            continue
        out[k] = keep_attrs(x)
    return out


def scrub_module(mod: dict) -> dict:
    """A `values.root_module` / `child_modules[]` entry."""
    out: dict[str, Any] = {}
    if "address" in mod:
        out["address"] = mod["address"]
    out["resources"] = [
        {**{k: r[k] for k in RESOURCE_KEYS if k in r}, "values": keep_attrs(r.get("values", {}))}
        for r in mod.get("resources", [])
        if r.get("type") in KEEP_TYPES
    ]
    if mod.get("child_modules"):
        out["child_modules"] = [scrub_module(c) for c in mod["child_modules"]]
    return out


def references_only(v: Any) -> Any:
    """Keep `references` arrays and the nesting that leads to them; drop everything else."""
    if isinstance(v, list):
        kept = [references_only(x) for x in v]
        return [x for x in kept if x not in (None, {}, [])]
    if not isinstance(v, dict):
        return None
    out = {}
    for k, x in v.items():
        if k == "references":
            out[k] = x
        elif k != "constant_value":
            sub = references_only(x)
            if sub not in (None, {}, []):
                out[k] = sub
    return out


def scrub_config_module(mod: dict) -> dict:
    out: dict[str, Any] = {"resources": []}
    for r in mod.get("resources", []):
        if r.get("type") not in KEEP_TYPES:
            continue
        entry = {k: r[k] for k in ("address", "mode", "type", "name") if k in r}
        if "expressions" in r:
            exprs = {k: x for k, x in r["expressions"].items() if k in KEEP_ATTRS}
            entry["expressions"] = references_only(exprs) or {}
        for k in ("count_expression", "for_each_expression"):
            if k in r:
                entry[k] = references_only(r[k]) or {}
        out["resources"].append(entry)
    calls = {
        name: {"module": scrub_config_module(call.get("module", {}))}
        for name, call in mod.get("module_calls", {}).items()
    }
    if calls:
        out["module_calls"] = calls
    return out


def scrub(doc: dict) -> dict:
    out: dict[str, Any] = {}
    for key in TOP_KEYS:
        if key not in doc:
            continue
        v = doc[key]
        if key in ("values", "planned_values"):
            out[key] = {"root_module": scrub_module(v.get("root_module", {}))}
        elif key == "prior_state":
            out[key] = {k: v[k] for k in ("format_version", "terraform_version") if k in v}
            if "values" in v:
                root = scrub_module(v["values"].get("root_module", {}))
                out[key]["values"] = {"root_module": root}
        elif key == "configuration":
            out[key] = {"root_module": scrub_config_module(v.get("root_module", {}))}
        else:
            out[key] = v
    return Scrubber().strings(out)


def inside_cwd(arg: str) -> pathlib.Path:
    """The real path of `arg` (symlinks resolved) when it lies inside the working directory; else
    ValueError.

    The input path may come from an agent's command line: without this, `../../` or an absolute
    path would read (and print, scrubbed or not) any JSON file the user can read."""
    base = pathlib.Path.cwd().resolve()
    real = pathlib.Path(arg).resolve()
    if not real.is_relative_to(base):
        raise ValueError(f"{arg} is outside the working directory {base}; run from its folder, "
                         "or pipe it in with `-`")
    return real


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    if sys.argv[1] == "-":
        doc = json.load(sys.stdin)
    else:
        try:
            real = inside_cwd(sys.argv[1])
        except ValueError as e:
            print(f"scrub_tfjson: {e}", file=sys.stderr)
            return 2
        with real.open(encoding="utf-8") as f:
            doc = json.load(f)
    sys.stdout.reconfigure(encoding="utf-8")
    json.dump(scrub(doc), sys.stdout, indent=2, ensure_ascii=False)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
