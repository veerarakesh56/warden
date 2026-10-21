# Changelog

All notable changes to Helios are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **`scripts/scrub_tfjson.py` reads only inside the working directory.** Its input path can come
  from an agent's command line; `../` or an absolute path used to read any JSON file the user
  could. A path that resolves (symlinks included) outside the working directory is refused, exit 2;
  stdin (`-`) is unchanged.
- **CI installs nothing that runs setup code.** `uv sync --frozen --no-build --no-install-project`
  (locked wheels only; helios-ai is put on `PYTHONPATH` rather than built with an unlocked
  hatchling), ruff and pytest run from the venv instead of `uv run`, `npm ci --ignore-scripts`,
  and `pull-requests: write` is granted only to the two jobs that run the Action.
- **`.sonarcloud.properties` excludes `fixtures/`** from SonarQube Cloud analysis: deliberately
  weak test infrastructure that the simulator and golden tests depend on, not product code.

### Fixed

- **`helios verify` checks every scenario, not only the fix's.** It re-simulates the fix's scenario,
  every other `--scenario` given (now repeatable), and every zone, region and NAT-gateway outage of
  the graph, before and after the fix, and exits 1 on a new failure in ANY of them. The shipped
  `fixes/az-outage.json` (move every 1a resource to 1b) used to verify as "Resolved 3, exit 0";
  under a 1b outage it takes 5 resources down instead of 1, and verify now says so. A fix whose
  `scenario_name` is not one of the scenarios given is rejected. `verify --json` emits the
  per-scenario report; `VerifyReport` is now `{ scenarios: [ScenarioDiff] }` with `verdict()`.
- **The Action's gate judges the real plan only.** A committed `fixes/<stem>.json` used to pass its
  scenario whenever `helios verify` exited 0 -- but a fix edits Helios's in-memory graph, not the
  Terraform, so a PR passed with its Terraform unchanged. A scenario now fails the gate when the
  plan's chain has failures (or it is inconclusive), fix or no fix; the verify report is shown in
  the comment as advisory output.

- **The Action works from another repository.** It ran `cargo build`, `cp target/release/helios`
  and `hashFiles('Cargo.lock', 'crates/**')` in the CALLER's workspace and defaulted to Helios's own
  `fixtures/`, so `uses: veerarakesh56/helios/action@...` failed anywhere else. It now builds from
  `${{ github.action_path }}/..` with a cache key hashed from the files there, `terraform-json` is
  required, and an empty `scenarios-glob` (the new default) runs the plan's standard scenarios,
  written by the new `helios scenarios <tf-json> --out <dir>`. A CI job (`action-consumer`) runs the
  action from a separate directory with only `terraform-json` set.

- **Unsupported resources are no longer skipped quietly.** `simulate --json`, `inspect` and
  `verify --json` append `skipped: [{type, count, addresses}]`; every command prints
  `helios: NOT SIMULATED: N resource(s) ...` on stderr whatever the log level; `plan` prints the
  count; the Action's comment shows it. New global `--fail-on-unsupported` exits 3 (inconclusive)
  when there are any; the default is unchanged. The three-tier golden outputs gain
  `"skipped": []`; helios-ai's `FailureChain` accepts the field (`ChainDoc` is the inspect chain).

### Security

- **The PR comment escapes what the PR controls.** Scenario names, file stems, resource ids, kinds
  and reasons went into the comment's markdown/HTML raw (a `|` broke the table; `<`, backticks or a
  newline could inject markup). They are now HTML-escaped in `<summary>`/`<pre>` and
  markdown-escaped in table cells; captured verify/inconclusive text is a `<pre>` block, not a
  ``` fence its content could close.

- **Every GitHub Action is pinned to a full commit SHA** (tag in a comment, resolved 2026-10-16;
  each is the commit its major tag pointed at, so behaviour is unchanged). `dtolnay/rust-toolchain`
  now names its `toolchain:` explicitly, as a SHA ref requires. `scripts/test_action_pins.py` fails
  on any unpinned `uses:`.

### Changed

- **README counts are derived and held.** The header said 216 tests (161 Rust / 55 Python / 9
  guards) while the Tests section said 200 (148 / 52 / 7); "Five kinds ship" sat beside 6 scenario
  kinds, and no `resource-loss` example shipped. Both now state the real counts (224: 168 Rust, 56
  Python; 7 viewer; 20 scripts), the scenario table lists all six kinds,
  `fixtures/scenarios/resource-loss.yaml` ships (with three-tier goldens), and
  `scripts/test_readme_counts.py` fails when a count, the kind count, a kind's table row or its
  example file drifts.
- **web/ dev dependencies upgraded** to clear `npm audit` (14 findings, 2 critical, 7 high, all
  dev-only, via vite 5 / vitest 2): vite 8.3, vitest 5.0, @vitejs/plugin-react 6.1, jsdom 29.
  `npm audit` reports 0. CI's web job runs Node 22 (vitest 5 requires ^22.12).
- The default model is `claude-opus-5-5` (was `claude-opus-5`).

- **Z3 is pinned by version and sha256.** z3-sys's `gh-release` feature downloaded the Z3 binary at
  build time with no hash check (still true of z3-sys 0.13.1, checked 2026-10-16). Helios drops the
  feature: `scripts/fetch_z3.py` downloads the official Z3 4.16.0 release zip, refuses it unless its
  sha256 is the pinned one (from the release's published digests, read 2026-10-16), and unpacks the
  link library into `target/z3/bin`, which `.cargo/config.toml` hands to z3-sys as
  `Z3_LIBRARY_PATH_OVERRIDE`. CI, the Action and the Makefile run it. The build no longer pulls
  `reqwest`/`zip` and their tree. The CI comment saying z3-sys used `GITHUB_TOKEN` was wrong (it
  reads `READ_ONLY_GITHUB_TOKEN`); the variable is gone.

## [0.2.0] - 2026-09-26

### Added

- Action input `fail-on: never|failures` (default `never`). With `failures`, a final step — after the
  comment and artifacts are posted — fails the job when any scenario failed: its chain has failures
  and no fix is committed, or `helios verify` exits non-zero.
- Golden `inspect` / `simulate --json` outputs for the five three-tier scenarios, and a test that the
  CLI reproduces them byte for byte.
- `scripts/check_publishable.py` (secret / state-file / public-IP / account-id guard, run in CI) and
  `scripts/scrub_tfjson.py` (reduces a `terraform show -json` document to the topology Helios reads).
- CI `msrv` job: `cargo check` on the declared minimum Rust.
- **Ten new resource kinds**: `aws_rds_cluster`, `aws_rds_cluster_instance`,
  `aws_elasticache_replication_group`, `aws_ecs_cluster`, `aws_ecs_service`, `aws_eks_cluster`,
  `aws_eks_node_group`, `aws_sqs_queue`, `aws_vpc_endpoint`, `aws_nat_gateway`. Nine more types are
  read only to link resources and never become nodes: `aws_db_subnet_group`,
  `aws_elasticache_subnet_group`, `aws_lambda_event_source_mapping`, `aws_route_table`, `aws_route`,
  `aws_route_table_association`, `aws_main_route_table_association`, `aws_default_route_table`
  and `aws_iam_role`.
- **`Dependency::Spread(via)`, a placement group.** Every Spread edge out of a resource with the
  same `via` is one group: an ECS service's or node group's subnets, the subnets of an Aurora
  instance's or Redis group's subnet group, an interface endpoint's subnets, an Aurora cluster's
  instances. `helios_models::spread_rule` says how the group fails: `AnySurvivor` (down only when
  every member is), `FailsIfAnyDown` (capacity 1 or placement unknown until apply: down when any
  member is) or `Ignore`. The rule is read from the attributes **at solve time**, so a `set_attr`
  fix such as `desired_count = 2`, `scaling_config[0].desired_size = 2` or
  `automatic_failover_enabled = true` re-verifies. Mirrored in `inspect` (`DepDoc::Spread`), the
  Pydantic and TypeScript types, and the viewer (medium, dotted edges).
- **`terraform show -json <planfile>`.** Helios reads `planned_values` when there is no `values`,
  and an attribute unknown until apply is resolved through the `configuration` block's
  `references`: a reference to a specific instance names only it; otherwise `count.index` /
  `each.key` pairs the same index or key; otherwise every instance (with a warning when the
  attribute holds one value). Module calls are followed. References through `local.*`, `var.*`,
  module outputs and `dynamic` blocks are not, and say so in a warning. `helios plan` prints
  `source: state` or `source: plan`; a document with neither key is `Error::NotTerraformJson`.
- **NAT gateways, as egress.** `Dependency::Egress`: a subnet points at the NAT gateway its route
  table's default route (`0.0.0.0/0`, inline or `aws_route`; with no association, the VPC's main
  route table) goes through. Losing the NAT, or its zone, fails the COMPUTE in such subnets
  (instances, ECS services, EKS node groups, and an in-VPC Lambda once all its subnets have lost
  egress) — not the subnets, and not a database, cache or endpoint in them. `single-nat-death`
  accepts an `aws_nat_gateway` address. Mirrored in `inspect`, Pydantic, TypeScript and the viewer.
- New scenario kind **`resource-loss { resource_id }`**: forces any one resource down (as
  `slow-rds-failover` does) without calling a cache or a queue a database. `slow-rds-failover` also
  targets an `aws_rds_cluster` (the whole cluster is down for the window) or an
  `aws_rds_cluster_instance` (writer loss). Reasons say which.
- `iam-revocation` also reads `node_role_arn` (EKS node groups); an EKS cluster's revoked role takes
  its node group with it.
- **`helios propose-fix <tf-json> --scenario <yaml>`**: simulates, then pipes the chain and the
  **scrubbed attributes of the failed resources only** to `python -m helios_ai propose-fix` and
  prints the FixProposal. Nothing failing: nothing printed, no model call.
- `fixtures/wave4-synthetic/`: a hand-written state of WARDEN's Wave 4 topology (ap-south-2) and a
  plan derived from it the way `terraform show -json <planfile>` renders it — including the real
  config's gap: the Lambdas' `dynamic "vpc_config"` has no references — with exact-failure-set
  tests, plus NAT, plan-reference, resolver and "not a pass" tests.
- `fixtures/wave4-fullstack/`: WARDEN's Wave 4 stack **as it ran on AWS** (2026-09-26), scrubbed:
  the applied state, a plan of the same configuration against an empty state, and ten scenarios
  (each zone, the region, the NAT, Redis, the node group, a queue, two roles).
  `crates/helios-engine/tests/wave4_real.rs` locks the exact failure sets, cross-checked against
  the live account's placement (subnets, NAT, the EKS node, ECS tasks, Redis members, endpoints).
  The scrubbed fixtures give the same verdicts as the raw documents for all ten scenarios, on both.
- **Inconclusive is a result.** `SimulateError::Inconclusive`; the CLI exits **3** with nothing on
  stdout; the Action records `<stem>.inconclusive.txt`, shows it in the PR comment and fails the
  `fail-on: failures` gate. See the ⛔ entries under Fixed for what triggers it.

### Fixed

- **A fix could be "verified" without being evaluated.** `set_attr` stored its key verbatim, so
  `scaling_config.desired_size` became a new top-level attribute with a dot in its name, which nothing
  read; the node group stayed failed and a correct fix looked wrong. Keys are now paths
  (`scaling_config.desired_size`, `scaling_config[0].desired_size`; a list of blocks is entered at its
  first element), and a path into nothing is an error. An edit to an attribute the graph's edges are
  built from (`subnet_id`, `subnet_ids`, `vpc_config`, `cluster`, ... - `fix::PLACEMENT_KEYS`, checked
  against `resource.rs` by a test) is **refused**: edges are derived once, so moving a resource by
  `set_attr` changed nothing. Found by a real Claude run on WARDEN's Wave 4 stack, which proposed moving
  the NAT; with the rules in its prompt it now proposes the capacity edit, which verifies, and says the
  NAT and endpoints need Terraform changes.
- Windows input: `helios explain` piped from Windows PowerShell 5.1 failed on the byte-order mark it
  prepends, with a raw pydantic traceback. The BOM is stripped (Rust and Python), a Terraform JSON
  written as UTF-16LE (`terraform show -json > x` in PowerShell 5.1) is decoded, and input that is not
  a chain is one line on stderr, exit 2.
- **Losing a NAT on a plan could under-report.** When some compute's subnets could not be placed
  (WARDEN's Wave 4 Lambdas: `dynamic "vpc_config"`), `single-nat-death` returned the NAT alone as
  a verdict; the applied state loses three Lambdas with it. It is now **inconclusive** (exit 3),
  naming them, as a zone outage already was.
- `scripts/scrub_tfjson.py` dropped `aws_iam_role`, `aws_main_route_table_association` and
  `aws_default_route_table` (and the `default_route_table_id` attribute), all of which Helios reads:
  a scrubbed plan turned `iam-revocation` verdicts into INCONCLUSIVE. A test now reads the type
  tables in `resource.rs` and fails when the scrubber would drop one. It also left the 16-hex id of
  a load balancer ARN and UUIDs (event-source mappings, node groups) in place; they are now
  placeholders.
- A resource that fails with the thing it is inside (an instance with its subnet, a service with its
  cluster, a NAT gateway with its zone's subnet) read "failure propagated from a dependency". It now
  names the parent and the attribute: `its subnet_id aws_subnet.public_a is down`. The only change
  in the golden outputs: the `single-nat-death` reason for `aws_instance.web`.
- Data sources were logged as one WARN line each (six on WARDEN's Wave 4 state), burying real
  warnings. They are now one INFO line listing them: a data source cannot fail, so nothing is lost.
- `rust-version` said 1.75; the dependency tree needs **1.88** (`time`, `zip`). Declared and checked in CI.
- `make` recipes `cd helios-ai` and then ran a *relative* `HELIOS_AI_PYTHON`, and broke on a checkout
  path with a space. The path is now absolute and quoted. `make demo` now defaults to
  `HELIOS_AI_MOCK=1`, as the 0.1.0 entry already claimed; `HELIOS_AI_MOCK=0` runs the real model.
- `helios explain` fell back to `python` on PATH; it now tries `helios-ai/.venv` first.
- The two Python e2e tests in `crates/helios-cli/tests/cli.rs` passed silently when the venv was
  missing; with `HELIOS_REQUIRE_PY=1` (set in CI) they fail instead.
- `glossary.py` (the prompt's model reference) called S3 global and RDS regional; the code models S3
  as Regional and RDS as SingleAz / MultiAz by `multi_az`.
- `helios_ai.__version__` said 0.0.1; it now reads the installed package version.
- **Real `aws_lb` state never failed a zone outage.** It has `subnets` but no
  `availability_zones`, so the ALB was modelled as surviving every zone loss. A multi-AZ resource
  with no declared zones is now down when every subnet it is a member of is down. (The three-tier
  fixture declares its zones, so its outputs are unchanged.)
- **List-shaped blocks were read as objects.** Real state stores `vpc_config`,
  `network_configuration` and `scaling_config` as one-element lists; an in-VPC Lambda had no
  edges. The resolver walks objects and lists alike.
- **Edge targets were matched on `id` alone, of any type.** They are now matched on `id`, `arn`
  or `name`, and only against the types the edge allows — WARDEN's DB subnet group is named
  exactly like its Aurora cluster.
- ⛔ **A resource whose zone could not be modelled answered zone outages anyway.** A subnet, database
  or cache without an `availability_zone` was placed in the region's `a` zone — a guess, so a `b`
  outage "passed". And a zone-deciding attribute that names nothing in the graph (an ECS service
  or node group in a data-source subnet, an Aurora instance with no zone and no subnet group, an
  ALB whose `subnets` are external) left the resource with no placement at all: Regional, so it
  survived every zone outage — exit 0, "resilient". Both now make an `az-outage` in that region
  **inconclusive**. An instance with no zone of its own is placed by its subnet.
- ⛔ **Linking every candidate made a group look SAFER, not worse.** When a plan reference could
  not be resolved exactly, every instance was linked "worst case" — but for a group that survives
  while any member does (an ECS service with `desired_count = 2`, an ALB's subnets) more members is
  the BEST case. Such groups are now evaluated as lost when any member is, and say "placement
  could not be resolved exactly from the plan".
- ⛔ **A NAT failure failed everything in the subnet** — Redis, Aurora instances, endpoints, internal
  ALBs — though only egress is lost. Now `Egress`, and only compute follows (see Added).
- `count.index` pairing inside a counted/`for_each` module counted the referencing block across
  every module instance, so it never matched and over-linked (an instance in 1b failed a 1a
  outage). It now counts within the module instance.
- A subnet associated with a route table Helios cannot see fell back to the VPC's main route table
  and got a NAT edge that does not exist. The main table is used only when there is no
  association. A cycle that only an over-connected plan reference closes is dropped with a warning
  instead of aborting; a cycle of exact edges is still `Error::DependencyCycle`.
- The ALB zone fallback reads its `MemberOf("subnets")` edges (and a Lambda its `subnet_ids`, for
  egress), but the acyclicity check skipped `MemberOf`: those two are now checked.
- `propose-fix` and `inspect` redacted by attribute name only, so a Lambda's
  `environment[0].variables` (`DATABASE_URL = "postgres://app:pw@…"`), `user_data`,
  `user_data_base64` and `container_definitions` went out whole. Those are now redacted wholesale,
  and every path Terraform itself marks in `sensitive_values` is redacted too.
- Resources of unsupported types are reported in ONE warning per graph ("skipped N resources of M
  unsupported types: type (count), ..."), not one line each.
- **Unresolvable associations no longer make everything inconclusive.** A subnet no resolvable
  association names gets the NAT set that every table it could be in agrees on (the tables of the
  unresolvable associations, plus the main table when there are fewer of those than such
  subnets); only when they disagree is its egress unknown — and only a subnet with compute in it
  (an instance, ECS service, EKS node group or in-VPC Lambda) records that. An association whose
  `route_table_id` is indirect (`local.table_ids[count.index]`), or a default route whose table or
  NAT is, makes egress unknown too, where it used to be silently absent. Associations are resolved
  once per graph, and each warning is printed once.
- Every forcing scenario — `single-nat-death`, `resource-loss`, `slow-rds-failover` — aimed at a
  NAT gateway or at a subnet a NAT lives in is inconclusive while a compute subnet's egress is
  unknown (only `single-nat-death` at a NAT checked before).
- **A multi-region plan put everything in the majority region.** A resource with no region of its
  own now takes its provider's constant `region` (`configuration.provider_config`, e.g. an
  `aws.west` alias), and a region outage in an estate spanning several regions is inconclusive
  while any resource's region is still unknown.
- **Local Zones and Wavelength Zones** (`us-west-2-lax-1a`, `us-east-1-wl1-bos-wlz-1`) were rejected
  as malformed, and mapped to a non-region; they now belong to their parent region.
- ⛔ **An outage aimed where the estate is not was a SILENT PASS.** The default `us-east-1a`
  scenario against an ap-south-2 plan, a region name typo (`us-east1`), a zone with no letter: "no
  failures", exit 0. Now `SimulateError::UnknownRegion` ("scenario targets region X; the modelled
  estate is in Y") or `SimulateError::Malformed`, exit 1. An empty zone in the estate's own region
  is still a real pass (with a warning when nothing declares that zone). When nothing declares a
  region at all, the us-east-1 fallback no longer decides that an unplaceable resource is
  elsewhere: it counts in every region, and a region outage is inconclusive.
- ⛔ **An in-VPC Lambda had no zone at all.** `vpc_config.subnet_ids` that name nothing in the graph
  now make a zone outage inconclusive (as for ECS and EKS), and a Lambda is lost when every one of
  its subnets is down or has lost egress — any of them, when a plan could not say exactly which.
  Before apply, WARDEN's `dynamic "vpc_config"` Lambdas make every zone outage of its plan
  inconclusive: the honest answer until apply.
- ⛔ **An association Helios could not resolve fell back to the main route table.** With `for_each =
  aws_subnet.public` / `subnet_id = each.value.id`, a managed default route table through the NAT
  gave the NAT's own subnet an egress edge to it — `DependencyCycle`, every command failed — and
  without one, private subnets silently had no egress. The fallback now applies only when no
  association could name the subnet; otherwise its egress is unknown and zone outages / NAT deaths
  are inconclusive. `Egress` no longer counts for acyclicity: a subnet's `down` never reads it.
- A reference list mixing a variable, local, module output, data source or `each.value` with real
  resources (`var.ha ? [a.id, b.id] : [a.id]`) linked the union and called it exact; those are now
  candidates, evaluated worst case.
- `helios` wrote ANSI colour codes into non-terminal stderr (CI logs, the Action's
  `.inconclusive.txt`), and the Action's `grep INCONCLUSIVE` also caught graph-build warnings. Colour
  is now off unless stderr is a terminal, and the Action keeps only the `helios: INCONCLUSIVE` line.
  An instance placed by its subnet no longer gets a "zone unknown" warning.
- ⛔ **An `iam-revocation` whose principal NOTHING uses was a silent pass** ("no failures", exit 0),
  in state and plan alike — the 0.1.4 unknown-target defect in another form. It is now
  `SimulateError::UnknownPrincipal` (exit 1). The shipped three-tier scenario matches its Lambda
  and is unchanged.
- The "spawning python" error message carried a run of spaces from a broken string continuation.
- ⛔ **An `iam-revocation` on a plan would have been a SILENT PASS.** Role ARNs are unknown before
  apply, so nothing matched and the run read "resilient". A resource's role is now matched
  through the `aws_iam_role` its configuration references (ARN name, role name or address), and
  when a role cannot be followed — a variable, local, module output or data source, even as one
  branch of a conditional next to a real role — the run is
  `SimulateError::Inconclusive`: the CLI exits **3** with nothing on stdout, and the Action records
  `<stem>.inconclusive.txt`, shows it in the PR comment and fails the `fail-on: failures` gate.
- `count.index` pairing assumed the index WAS `count.index`; `[count.index % 2]` records the same
  references. Pairing now requires equal instance counts (or, for `each.key`, an existing key);
  otherwise every instance is linked, with a warning.
- A subnet with no route-table association had no NAT edge: it now uses the VPC's main route table
  (`aws_main_route_table_association`, else `aws_default_route_table`).

### Changed

- The Action clears its artifact directory at the start of each run, so a second invocation in one
  job does not report the first one's scenarios.
- The edges a resource's `down` reads (`Contains`, `Spread`, and the two read `MemberOf`s) must be
  acyclic: a cycle would let the solver
  choose between "all up" and "all down". `Error::DependencyCycle` names the resources. The unused
  `Error::MissingReference` is gone.
- `ResourceKind::tf_type()` is the inverse of `from_tf_type`, read from one table; the engine's
  private copy of the mapping is gone. `ResourceKind` is now `Copy`.
- Reasons: a resource lost through a placement group says so ("every one of its N `<via>`
  placements is down", or, for a group that cannot lose a member, why — "desired_count 1 (where its
  task runs is unknown)", "its zone is unknown until apply", "no automatic failover to a replica",
  "placement could not be resolved exactly from the plan" — then "lost when any of its N `<via>`
  placements is lost (worst case)"); compute lost through a NAT says "egress via NAT X (the default
  route of S), which is down".

### Corrections

- The 0.1.0 entry listed a `launch/` folder (Show-HN draft, CFP abstract, outreach templates). It was
  never in this repository; the bullet has been removed.

## [0.1.4] - 2026-09-06

### Fixed

- ⛔ **A scenario naming a resource that is not in the graph was a SILENT PASS.** `apply_scenario` did
  `if let Some(idx) = …find(…)` with no `else`, so a typo in `db_id` or `subnet_id` — or naming one of
  the resource kinds Helios skips, such as `aws_nat_gateway` — asserted nothing. The run then printed
  *"No failures — configuration is resilient"* and exited **0**. A typo read as a clean bill of health.
  The *fix* path already errored on an unknown resource id, so the asymmetry ran the wrong way: the
  safety-critical direction was the forgiving one. `apply_scenario` now returns the target it could
  not find (`#[must_use]`), and `simulate` turns that into `SimulateError::UnknownTarget`, naming the
  id and suggesting the likely cause.

### Testing

- **85 tests** (65 Rust, 20 Python). The new test asserts an unknown target is reported rather than
  ignored; the eleven existing call sites now assert the target *was* found, which is stricter than
  discarding the result. The five shipped scenarios are unchanged at 3 / 9 / 2 / 1 / 1.

## [0.1.3] - 2026-09-06

### Fixed

- ⛔⛔ **Helios silently gave the WRONG ANSWER for any estate outside `us-east-1`.** `region_of` read
  only an explicit `region` attribute, which `terraform show -json` almost never carries, so every
  other resource fell back to a hard-coded default. Measured, both directions wrong: a `eu-west-2`
  multi-AZ database **survived** a `eu-west-2` region outage, and **fell** with a `us-east-1` one.
  Nothing warned — the tool just answered incorrectly, which is the worst failure mode for something
  whose selling point is that its answers are proofs.

  The region is now derived from what Terraform does emit, in order: an explicit `region`, the
  `availability_zone` it declares, the first of `availability_zones`, or the region field of any ARN
  it carries (`arn:partition:service:REGION:...`, ignoring the empty field global services use).
  A multi-AZ RDS still *guesses* which two zones it occupies — Terraform does not say — but it now
  guesses inside the resource's own region.

  ⭐ And because some resources carry no region signal at all (the shipped fixture's Lambda is one),
  a per-resource rule is not enough on its own: `infer_region` takes the region the rest of the graph
  agrees on and uses that as the fallback, so those resources land where their estate is rather than
  in `us-east-1`. Ties break alphabetically, so the answer stays deterministic.

### Testing

- **84 tests** (64 Rust, 20 Python). A new regression test asserts both directions on a `eu-west-2`
  estate whose region has to be found three different ways — from an ARN, from a declared zone, and
  (the Lambda) from nothing at all: losing `eu-west-2` takes all three down, and losing `us-east-1`
  takes **nothing** down. The five shipped scenarios are unchanged at 3 / 9 / 2 / 1 / 1.

## [0.1.2] - 2026-09-06

Three correctness bugs, all found by generating synthetic `terraform show -json` documents and
**running** them — not by reading the code. None of them affect the shipped fixture, which is exactly
why they survived: every existing test uses that one document.

### Fixed

- ⛔ **A multi-AZ resource with no `availability_zones` was reported down in EVERY scenario.**
  `azs_from_subnets` returns an empty vec when the attribute is absent, and the encoder built
  `Bool::and(&[])` — Z3's *empty conjunction*, which is `true`. So "all of its zones are down" was
  vacuously satisfied. An `aws_lb` with no declared zones failed even under a scenario naming a zone
  nothing lives in, and its reason string read `multi-AZ across []`. An unknown AZ set now
  contributes nothing (the resource still falls with its region) and the run warns that the
  resource's AZ behaviour is not modelled.
- ⛔ **A data source of a modelled type was ingested as infrastructure.** `RawResource` never read
  Terraform's `mode` field, so `data.aws_subnet.selected` became a subnet and was reported as a
  failed service — a false positive about infrastructure Terraform does not even own. `mode` is now
  read (defaulting to `managed`, so hand-written fixtures stay valid) and anything not managed is
  skipped with a warning.
- ⛔ **Diagnostics went to stdout, which corrupted the JSON the GitHub Action parses.**
  `tracing_subscriber::fmt()` defaults to stdout; `action/scripts/run-scenarios.sh` redirects the
  command's stdout into the document that `build-comment.sh` reads with `jq`. One skipped resource
  would therefore break the PR comment on any real repository. Logs now go to stderr.
- The `IamRevocation` doc comment still listed only `iam_role_arn` and `role_arn`; v0.1.1 added
  `role`.

### Changed

- **The default Claude model id is now `claude-opus-5`** (was `claude-opus-4-7`). v0.1.1 made the id
  configurable via `HELIOS_AI_MODEL` but shipped a default that was already behind the current model
  family, while this author's other project was on `claude-sonnet-5` — the mechanism was fixed and
  the value was left stale. Making a stale value overridable is not the same as updating it.
- **The README no longer claims the GitHub Action "gates" pull requests** (it reports), nor that the
  Python shell does "natural-language scenario parsing" (it has two subcommands and no scenario
  module; YAML is parsed in Rust).

### Testing

- **83 tests** (63 Rust, 20 Python) plus 6 for the viewer. Two new regression tests: one asserts a
  zone-less multi-AZ resource does **not** fail an AZ outage while the subnet actually in the dead
  zone still does; one asserts a data source never enters the graph.

## [0.1.1] - 2026-09-06

Correctness release. Every item below was found by running the shipped fixture
through every shipped scenario and reading the output, not the code.

### Fixed

- **The SMT encoding was under-constrained.** A scenario pinned only the zone
  or region it named; every other `az_down_*` / `region_down_*` variable was
  free, so the other zones' survival was Z3's default assignment for a free
  Boolean rather than a property of the encoding. Every unnamed AZ, region and
  forced variable is now pinned `false`, and a test asserts the other zone
  *cannot* be chosen down (`Unsat`).
- **Forcing a resource down took its whole zone with it.** `slow-rds-failover`
  and `single-nat-death` forced the target's `down` Boolean, which is *defined*
  by its availability rule, so the solver satisfied it by taking the AZ (or both
  AZs of a multi-AZ database) down — six failures for one slow failover, and an
  unrelated cache failing on a NAT death. Each resource now has a dedicated
  `forced_*` variable, and `down ⇔ availability ∨ forced ∨ (any Contains-parent
  down)` is the definition, so only the target and what it contains fail.
- **`iam-revocation` never matched the shipped fixture.** The matcher read
  `iam_role_arn` / `role_arn`; `aws_lambda_function` carries its principal under
  `role`, and the fixture's Terraform JSON did not include the attribute at all,
  so the bundled scenario reported "resilient" for the wrong reason. The matcher
  now reads `role` too, the fixture carries the Lambda's role as `main.tf`
  declares it, and the scenario names it.
- **`helios inspect` leaked raw attributes.** The document is uploaded as a CI
  artifact; a real `terraform show -json` carries plaintext passwords and keys.
  Attribute values whose name contains `password`, `passwd`, `secret`, `token`,
  `private_key`, `access_key`, `credential` or `api_key` are now replaced with
  `<redacted>` (keys kept, nested objects included).
- **The Claude model id was hard-coded** in two files. `HELIOS_AI_MODEL` now
  overrides the default without a code change. (The default value itself was
  brought current after this release — see Unreleased.)
- Workspace and package versions were still `0.0.1` under a `v0.1.0` release;
  both now carry the release version.

### Changed

- Reason strings: under `iam-revocation`, only the matched resource reads
  "principal … was revoked"; resources that fail through containment read
  "failure propagated from a dependency".
- Rust tests 56 → 61, Python tests 18 → 20.

## [0.1.0] - 2026-04-25

First public release. Eight AWS resource kinds, five scenario kinds, a
deterministic Z3-backed simulator, a Claude-powered explanation and
fix-proposal shell, a composite GitHub Action, and a cytoscape.js web
viewer.

### Added

#### Engine and graph
- Cargo workspace with five crates: `helios-cli`, `helios-graph`,
  `helios-models`, `helios-engine`, `helios-aws` (stub).
- `helios-graph` parses `terraform show -json` for eight AWS resource kinds:
  VPC, Subnet, EC2 instance, ALB, RDS, ElastiCache, Lambda, S3.
- `helios-models::availability_for` returns an `AvailabilityModel` per
  resource (`SingleAz`, `MultiAz`, `Regional`, `GlobalEdge`).
- `helios-engine` Z3-backed SMT encoder. One `Bool` per resource / AZ /
  region; biconditionals from the availability model; `Contains` edges
  propagate failure downward.
- Scenario kinds `RegionOutage` and `AzOutage`; `helios simulate`
  CLI entry point that prints the failure chain and exits non-zero on
  any failure.
- Pre-compiled Z3 4.16.0 via the `z3 0.20` `gh-release` feature; no
  system Z3 install needed on Linux or Windows.

#### AI shell and structured fixes
- `helios-ai/` uv-managed Python 3.12 package. Pydantic models mirror the
  Rust `FailureChain`, `FailedResource`, `FixProposal`, `FixEdit` byte
  for byte (`extra="forbid"` keeps schema drift loud).
- `helios-ai explain` -- reads `FailureChain` JSON on stdin, returns a
  markdown narrative on stdout via Claude with prompt caching on the
  system prompt and the availability-model glossary.
- `helios-ai propose-fix` -- reads `{chain, attrs_snapshot}` on stdin,
  returns a structured `FixProposal` via Claude `output_config.format`
  with the same two cache breakpoints reused.
- `MockAnthropic` (`HELIOS_AI_MOCK=1`) for offline tests; ASCII-only
  output so Windows cp1252 stdout does not mangle JSON.
- New scenario kinds: `IamRevocation`, `SlowRdsFailover`, `SingleNatDeath`.
- `helios verify <tf-json> --scenario <yaml> --fix <json>` -- engine
  re-runs the simulation with the fix applied and reports
  `Resolved` / `Still failing` / `New failures introduced`. Exits non-zero
  if any failure remains.
- Structured `set_attr` edit op (only edit op in v0.1).

#### Action, viewer, and combined inspect
- `helios inspect <tf-json> --scenario <yaml>` emits a single JSON
  document `{scenario, graph: {nodes, edges}, chain}`. Hand-rolled flat
  graph shape (not petgraph's native serde, whose `NodeIndex` integers
  are unstable across builds and meaningless to a viewer).
- Composite GitHub Action at `action/`. `actions/cache@v4` keys on
  `Cargo.lock` plus crate sources; cache miss builds and copies the
  `helios` binary. Loops every scenario in `fixtures/scenarios/*.yaml`,
  optionally runs `verify` if `fixes/<stem>.json` exists, uploads
  per-scenario artifacts, upserts a single sticky PR comment marked with
  `<!-- helios-action -->`.
- Vite + React + TypeScript + cytoscape 3.30 web viewer at `web/`.
  File-picker, paste-textarea, and "Load sample" entry points.
- Three-layer schema mirror: Rust source of truth in
  `helios-engine::inspect`, Pydantic mirror in
  `helios-ai/src/helios_ai/models.py`, TypeScript mirror in
  `web/src/types.ts`.

#### Docs, release scaffolding, and demo
- `docs/ai-boundary.md` -- canonical "AI never produces a safety verdict"
  essay with the differential-testing rationale and a Cedar prior-art
  reference.
- `docs/ARCHITECTURE.md` -- per-crate map, end-to-end data flow, and
  rationale for every locked design choice.
- `Makefile` -- `make demo`, `make test`, `make fmt`, `make check`.
  `make demo` runs the spec choreography with `HELIOS_AI_MOCK=1`.
- `docs/demo.gif` -- animated demo embedded at the top of the README.
- `CONTRIBUTING.md` and `.github/ISSUE_TEMPLATE/{bug,feature}.yml`.

### Changed

- `simulate` reports the failure chain in a stable plain renderer; JSON
  emission via `--json` for downstream tooling.
- CI matrix grew from one `check` job to four jobs: `check`,
  `python-check`, `web-check`, `action-smoke`.
- `.gitattributes` pins LF on `*.sh`, `*.yml`, `*.yaml` so Windows-side
  edits round-trip on Linux runners.

### Fixed

- `helios-graph` rustdoc: bare URL wrapped in angle brackets to satisfy
  `rustdoc -D warnings`.

## Pre-0.1.0

Internal-only. The public history starts with this release.

[Unreleased]: https://github.com/veerarakesh56/helios/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/veerarakesh56/helios/releases/tag/v0.2.0
[0.1.4]: https://github.com/veerarakesh56/helios/releases/tag/v0.1.4
[0.1.3]: https://github.com/veerarakesh56/helios/releases/tag/v0.1.3
[0.1.2]: https://github.com/veerarakesh56/helios/releases/tag/v0.1.2
[0.1.1]: https://github.com/veerarakesh56/helios/releases/tag/v0.1.1
[0.1.0]: https://github.com/veerarakesh56/helios/releases/tag/v0.1.0
