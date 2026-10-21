# Scenario YAML schema

A scenario is a declarative failure the engine simulates against a resource graph.

## Top-level

```yaml
name: <string>       # human id for the scenario, echoed in the report
kind: <ScenarioKind> # the failure itself (see below)
```

## Kinds

### `az-outage`

```yaml
kind:
  type: az-outage
  az: us-east-1a
```

Takes a single availability zone offline. Regional and multi-AZ resources survive.

The zone must be `<region><letter>` and its region one the estate is in: an
outage aimed elsewhere (a us-east-1 zone against an ap-south-2 plan) is an
error, not a pass. A zone in the estate's own region where nothing lives is a
real pass (with a warning if nothing declares that zone).

If a resource in that zone's region cannot be placed — no `availability_zone`,
or a subnet attribute (`network_configuration.subnets`, `subnet_ids`, a subnet
group, an ALB's `subnets`) naming nothing in the graph — the run is
**inconclusive**: `INCONCLUSIVE (not a pass)` on stderr, exit **3**.

### `region-outage`

```yaml
kind:
  type: region-outage
  region: us-east-1
```

Takes an entire region offline. Only `GlobalEdge` resources survive. A region
the estate is not in, or a malformed region name (`us-east1`), is an error; when
no resource declares any region at all, the run is inconclusive.

### `iam-revocation`

```yaml
kind:
  type: iam-revocation
  principal_arn: arn:aws:iam::123456789012:role/lambda-worker
```

Fails any resource whose `attrs.iam_role_arn`, `attrs.role_arn` or `attrs.role`
(the attribute `aws_lambda_function` actually uses) matches the principal, plus
everything those resources contain. It is a string match over the
Terraform-JSON attr set; IAM is not modelled as graph nodes, so multi-hop policy
chains do not propagate. `node_role_arn` (EKS node groups) is read too.

On a **plan**, role ARNs are unknown until apply. A resource whose role attribute
references an `aws_iam_role` in the plan is matched through it: `principal_arn`
may be the role's ARN (matched on the role name), its name, or its Terraform
address (`aws_iam_role.lambda["checkout"]`). If any resource's role comes through
a variable, local or module output, the scenario is **inconclusive**: `helios`
prints `INCONCLUSIVE (not a pass)` on stderr and exits **3** (`simulate`,
`inspect`, `verify`, `propose-fix`), and the GitHub Action lists it as
inconclusive and counts it as failing. A role referenced through a variable
next to a real role (`var.x != null ? var.x : aws_iam_role.r.arn`) is
inconclusive too, unless the revoked role is the real one.

A principal that **no** resource uses is an error (exit 1), not a pass.

### `slow-rds-failover`

```yaml
kind:
  type: slow-rds-failover
  db_id: aws_db_instance.primary
```

Models a multi-AZ RDS whose failover takes longer than expected: during the
window the DB is treated as unavailable and dependents inherit the failure via
`Contains` edges. The DB is forced down *directly* — its availability zones stay
up, so nothing else in those zones is affected. (Before 0.1.1 the DB was forced
down through its availability rule, which made the solver take both zones down.)

`db_id` may also name an Aurora `aws_rds_cluster` (the whole cluster is down for
the window) or an `aws_rds_cluster_instance` (writer loss: the cluster survives
while another of its instances does).

### `resource-loss`

```yaml
kind:
  type: resource-loss
  resource_id: aws_elasticache_replication_group.redis
```

Forces any one resource down, exactly like `slow-rds-failover`, without calling
it a database — so "cache loss" or "queue loss" reads as what it is. Its zone
stays up. What `Contains` it follows, and so does a placement group it belongs
to, by that group's rule: an `AnySurvivor` group only if it was the last
member standing, a `FailsIfAnyDown` group (capacity 1, or placement unknown)
at once.

### `single-nat-death`

```yaml
kind:
  type: single-nat-death
  subnet_id: aws_subnet.public_a
```

`subnet_id` names either a subnet or an `aws_nat_gateway`.

- A **NAT gateway**: the NAT is forced down, and every subnet whose route table's
  default route (`0.0.0.0/0`, an inline `route` block or a separate `aws_route`;
  for a subnet with no association, the VPC's main route table) goes through it
  loses **egress**. Compute in those subnets fails — instances, ECS services, EKS
  node groups, and an in-VPC Lambda once all of its subnets have lost egress.
  The subnets themselves, and a database, cache or endpoint in them, do not.
- A **subnet**: that subnet is treated as down, with everything inside it.

The availability zone stays up either way. Because egress follows the NAT, an
`az-outage` of the NAT's zone also takes out compute in *other* zones that share
it.

If a subnet with compute in it has an unknown egress — an association Helios
cannot resolve whose possible route tables disagree on the NAT, or a route
table or default route named through a local or variable — then losing a NAT,
or a subnet a NAT lives in, is **inconclusive** (exit 3), whether by
`single-nat-death`, `resource-loss` or `slow-rds-failover`.

Add a new scenario by creating a YAML file in `fixtures/scenarios/` and running:

```bash
helios simulate <tf-dir> --scenario fixtures/scenarios/<name>.yaml
```

## JSON output

Pass `--json` to emit the `FailureChain` as JSON on stdout instead of the default pretty text:

```bash
helios simulate <tf-dir> --scenario fixtures/scenarios/<name>.yaml --json
```

Shape:

```json
{
  "scenario": "lose-us-east-1a",
  "failures": [
    { "id": "aws_instance.web", "kind": "Instance", "reason": "single-AZ in us-east-1a, which is down" }
  ]
}
```

Authoritative schema: `helios_engine::report::{FailureChain, FailedResource}` in [`crates/helios-engine/src/report.rs`](../crates/helios-engine/src/report.rs). Consumed by [`helios-ai`](../helios-ai/) to produce human-readable narratives.
