# Architecture

Helios is a Cargo workspace with a Python sidecar and a TypeScript viewer.
This document is the deeper version of the architecture sketch in the
README. It explains every crate, the data flow from Terraform JSON to a
verified fix, and the boundary between deterministic and AI-driven layers.

## Workspace layout

```
helios/
├── Cargo.toml                     # workspace root
├── crates/
│   ├── helios-cli/                # `helios` binary
│   ├── helios-graph/              # Terraform JSON -> typed resource graph
│   ├── helios-models/             # availability models per resource kind
│   ├── helios-engine/             # Z3 SMT engine, scenario, fix, verify
│   └── helios-aws/                # stub, not implemented: AWS API client
├── helios-ai/                     # Python shell (uv-managed)
│   ├── pyproject.toml
│   └── src/helios_ai/
│       ├── explain.py             # FailureChain -> markdown narration
│       ├── fix_generator.py       # FailureChain -> FixProposal (structured)
│       ├── models.py              # Pydantic mirror of Rust types
│       └── _mock.py               # MockAnthropic for offline tests
├── web/                           # Vite + React + cytoscape.js viewer
├── action/                        # composite GitHub Action
├── fixtures/                      # canned TF projects + scenarios + fixes
└── docs/
```

## The five Rust crates

### `helios-graph`

Reads `terraform show -json` output and builds a `petgraph::DiGraph<R, D>`
keyed on Terraform addresses (e.g. `aws_subnet.public_a`). Eighteen resource
kinds: `aws_vpc`, `aws_subnet`, `aws_instance`, `aws_lb`, `aws_db_instance`,
`aws_elasticache_cluster`, `aws_lambda_function`, `aws_s3_bucket`,
`aws_rds_cluster`, `aws_rds_cluster_instance`,
`aws_elasticache_replication_group`, `aws_ecs_cluster`, `aws_ecs_service`,
`aws_eks_cluster`, `aws_eks_node_group`, `aws_sqs_queue`, `aws_vpc_endpoint`,
`aws_nat_gateway`; nine more (subnet groups, event source mappings, route
tables and their associations, IAM roles) are read only to resolve edges.
Edges are derived structurally:

- `Contains(via_attr)` -- e.g. `subnet -> vpc` via `vpc_id`.
- `MemberOf(via_attr)` -- e.g. `alb -> subnet` via `subnets`.
- `Spread(via_attr)` -- one member of a placement group: every Spread edge
  out of a resource with the same `via` is one group (an ECS service's
  subnets, an Aurora cluster's instances).
- `Egress(via_attr)` -- `subnet -> NAT gateway` via the default route
  (`nat_gateway_id`): compute in the subnet loses egress with the NAT; the
  subnet and non-compute resources do not.

Each resource also records what the graph could not determine: `unresolved`
(a zone-deciding attribute names nothing Helios can place -- zone outages in
its region become inconclusive), `inexact` (a plan reference linked every
candidate -- the group is evaluated worst case), `pending_principals` (plan
roles) and `sensitive_values` (Terraform's mask, used to redact).

The distinction matters for the SMT encoding. `Contains` propagates failure
downward (a subnet failure forces every contained EC2 instance to fail).
`MemberOf` is mostly topology and does *not* propagate -- it would
over-constrain regional services. Two are read: an ALB with no declared
zones is down when all of its `subnets` are, and an in-VPC Lambda when all
of its `subnet_ids` are down or have lost egress (any of them, when a plan
could not say exactly which). A `Spread` group propagates by its
`helios_models::spread_rule`, read from the attrs at solve time:
`AnySurvivor` (down when every member is), `FailsIfAnyDown` (capacity 1 or
placement unknown: down when any member is) or `Ignore`. `Egress` is read
only by compute in the subnet (a subnet's own `down` never reads it). The
edges a resource's `down` reads -- `Contains`, `Spread` and the two read
`MemberOf`s -- must be acyclic (`Error::DependencyCycle`); a cycle that
only an over-connected plan reference closes is dropped with a warning.

A saved plan (`terraform show -json <planfile>`) is read from
`planned_values`; an attribute unknown until apply is resolved through the
`configuration` block's `references` (a specific instance, else the
same `count.index` / `each.key`, else every instance).

### `helios-models`

Pure-data crate. `availability_for(tf_type, attrs, default_region)` returns
an `AvailabilityModel` for a resource:

```rust
enum AvailabilityModel {
    SingleAz { az: String },
    MultiAz { azs: Vec<String>, failover_seconds: Range<u32> },
    Regional { region: String },
    GlobalEdge,
}
```

Authoring a new resource type means adding a branch here. The crate has
zero external dependencies and is the easiest place for contributors to
land their first PR.

### `helios-engine`

The simulator. Splits across:

- `smt.rs` -- the `Encoder`. One `Bool` constant per resource, per AZ, per
  region. Biconditionals from `AvailabilityModel`: a `MultiAz` resource
  fails iff *all* its AZs fail; a `Regional` resource fails iff its region
  fails; a `SingleAz` resource fails iff its AZ fails. `Contains` edges
  add `child.failed -> parent_member.failed` propagation.
- `scenario.rs` -- `ScenarioKind` enum: `RegionOutage`, `AzOutage`,
  `IamRevocation`, `SlowRdsFailover`, `SingleNatDeath`. `apply_scenario`
  asserts the scenario's predicates onto the solver context.
- `simulate.rs` -- the top-level entry point. `simulate(graph, scenario)
  -> FailureChain`.
- `report.rs` -- `FailureChain { failures: Vec<FailedResource> }`.
- `fix.rs` -- `FixProposal { scenario_name, explanation, edits:
  Vec<FixEdit::SetAttr> }`. `apply_fix(graph, fix) -> ResourceGraph`
  clones the petgraph and mutates per-node attrs.
- `verify.rs` -- `verify(graph, scenarios, fix) -> VerifyReport { scenarios:
  [ScenarioDiff { pre_fix, post_fix, resolved, new_failures, remaining }] }`.
  Runs the fix's scenario (it must match `scenario_name`), every other scenario
  given, and `standard_scenarios` (every zone, region and NAT outage of the
  graph before and after the fix); BTreeSet diff over the failure-id sets of
  each. `verdict()`: new failures anywhere > target still failing >
  inconclusive > resolved.
- `inspect.rs` -- the `helios inspect` data flatten. Hand-rolled
  `{nodes, edges, scenario, chain}` shape -- not petgraph's native serde,
  because petgraph encodes `NodeIndex` integers that are unstable across
  builds and meaningless to a viewer.

`z3 0.20` is built WITHOUT its `gh-release` feature (which downloads Z3 at
build time with no hash check). `scripts/fetch_z3.py` downloads the official
Z3 4.16.0 release zip, checks it against a pinned sha256, and unpacks the
link library into `target/z3/bin`; `.cargo/config.toml` hands that to z3-sys
as `Z3_LIBRARY_PATH_OVERRIDE`. Static on Linux/macOS; `libz3.dll` on Windows.

### `helios-cli`

Seven subcommands:

- `helios scenarios <tf-json> --out <dir>` -- write the standard scenarios
  (`standard_scenarios`: an az-outage per zone, a region-outage per region,
  a single-nat-death per NAT gateway) as YAML, one file each.

- `helios plan <tf-json-dir>` -- print the source (`state` or `plan`) and
  resource and edge counts.
- `helios propose-fix <tf-json> --scenario <yaml>` -- simulate, then pipe
  the chain and the scrubbed attrs of the failed resources to
  `python -m helios_ai propose-fix`; prints the FixProposal JSON.
- `helios simulate <tf-json> --scenario <yaml> [--json]` -- run the engine,
  print or emit the chain. Exits non-zero on any failure.
- `helios explain` -- read `FailureChain` JSON on stdin, shell out to
  `python -m helios_ai explain` for the markdown narration.
- `helios verify <tf-json> --scenario <yaml>... --fix <json> [--json]` --
  run the pre/post diff for every scenario (see `verify.rs`). Exits 1 if the
  fix's scenario still fails or any scenario has a new failure, 3 if one
  cannot be evaluated, 0 only otherwise.
- `helios inspect <tf-json> --scenario <yaml>` -- emit the combined
  `{scenario, graph, chain}` JSON for the Action and viewer. Always exits
  zero.

### `helios-aws`

Stub crate. Will hold the live-state ingestion path (AWS API responses
merged into the graph for drift detection). Not implemented.

## The Python shell (`helios-ai/`)

A small uv-managed Python 3.12 package. Two commands on the same stdio
shape:

- `python -m helios_ai explain` -- input: `FailureChain` JSON. Output:
  markdown.
- `python -m helios_ai propose-fix` -- input: `{chain, attrs_snapshot}`
  JSON. Output: `FixProposal` JSON.

Both call the synchronous `anthropic.Anthropic` client with two cache
breakpoints (system persona + availability-model glossary). Set
`HELIOS_AI_MOCK=1` to swap in `MockAnthropic` -- the mock emits ASCII-only
text so Windows cp1252 stdout does not mangle JSON for the Rust
consumer.

The Python types in `models.py` mirror the Rust types byte-for-byte:
`FailureChain`, `FailedResource`, `FixProposal`, `FixEdit`. `extra="forbid"`
keeps schema drift loud.

## The web viewer (`web/`)

Vite 5 + React 18 + TypeScript 5 + cytoscape 3.30. Single-page app. Loader
is pure JSON validation. The Graph component is a `useEffect`-mounted
cytoscape canvas with kind-keyed pastels, failed resources red, `Contains`
edges thick + solid, `MemberOf` edges thin + dashed, `Spread` edges medium +
dotted, breadthfirst layout.

The viewer is local-only: file picker, paste-textarea, "Load sample"
button. Workflow-artifact deep-linking via `?artifact=<url>` is not
implemented.

## The GitHub Action (`action/`)

Composite action. Inputs: `terraform-json` (required), `scenarios-glob`,
`fixes-dir`, `github-token`, `artifact-name`, `fail-on`. Steps:

1. Hash the action's own `Cargo.lock` + crate sources (in
   `${{ github.action_path }}/..`; `hashFiles()` reads only the caller's
   workspace) and `actions/cache@v4` the binary on it.
2. Cache miss -> in `${{ github.action_path }}/..`: `scripts/fetch_z3.py`,
   `cargo build --release --locked --bin helios` -> copy to
   `${{ github.action_path }}/bin/helios`. Never in the caller's workspace.
3. `terraform-json` is required. With no `scenarios-glob`, `helios
   scenarios` writes the plan's standard set (zone / region / NAT outages).
4. `action/scripts/run-scenarios.sh` -- loops the glob, writes
   `<stem>.json` per scenario plus `<stem>.verify.txt` if
   `fixes/<stem>.json` exists. The gate (`fail-on: failures`) judges the
   real plan's chain only; the verify report is advisory and never passes a
   scenario, since a fix file edits the in-memory graph, not the Terraform.
5. `action/scripts/build-comment.sh` -- jq-aggregates the per-scenario
   summaries into one `<details>`-collapsible markdown body marked with
   `<!-- helios-action -->`.
6. `actions/upload-artifact@v4` uploads the per-scenario JSON dir.
7. `action/scripts/post-sticky.sh` -- `gh api --paginate` lists comments,
   matches the marker, PATCHes if found else POSTs. Idempotent.

The marker is the literal `<!-- helios-action -->` on the first line. One
PR -> one comment, every push.

## Data flow end-to-end

```
terraform show -json
        |
        v
helios-graph::parse  -->  ResourceGraph (petgraph::DiGraph<R, D>)
        |
        v
helios-models::availability_for  -->  per-node AvailabilityModel
        |
        v
helios-engine::scenario::apply_scenario  -->  Z3 constraints
        |
        v
helios-engine::simulate  -->  FailureChain { failures: [...] }
        |
        +---> helios-cli prints, or
        +---> helios inspect emits combined JSON for Action + viewer, or
        +---> helios-ai explain  -->  Claude  -->  markdown, or
        +---> helios-ai propose-fix  -->  Claude  -->  FixProposal
                          |
                          v
                helios-engine::apply_fix  -->  ResourceGraph'
                          |
                          v
                helios-engine::simulate  -->  FailureChain (post)
                          |
                          v
                helios-engine::verify  -->  VerifyReport
                          |
                          v
                helios-cli verify  -->  exit 0 or 1
```

The deterministic path is everything in Rust. Claude appears only at the
two `propose-fix` and `explain` arrows. See `docs/ai-boundary.md` for the
boundary rule and how `helios verify` enforces it.

## Why these choices

- **Z3 not a custom solver.** Industry-grade, well-documented, both Rust
  and Python bindings. We do not want to debug a custom DPLL.
- **petgraph not a custom graph.** Standard library for graph algorithms in
  Rust. The hand-rolled `inspect` shape exists only for serialization.
- **Composite Action not Docker / JS action.** Zero Node deps in the
  runtime; runs the same `gh` and `bash` the user already has;
  `actions/cache` for the prebuilt binary.
- **uv not pip.** Lockfile-based, fast, deterministic resolves.
- **Hand-rolled flat graph JSON for `inspect`.** petgraph's native serde
  encodes `NodeIndex` integers; useless to a viewer.

## Where to land your first PR

- A new resource kind: add a branch to `helios-models::availability_for`,
  add a fixture under `fixtures/<your-kind>/`, add a unit test.
- A new scenario kind: add a `ScenarioKind` variant in
  `helios-engine/src/scenario.rs`, an `apply_scenario` arm, a YAML fixture,
  a fixture-based integration test.
- A docs fix: PRs against `docs/` need only `cargo doc` and `lychee` to
  pass.

See `CONTRIBUTING.md` for the contributor flow.
