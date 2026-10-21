"""Static reference text describing how Helios models AWS resource availability
and the scenarios the engine supports.

Included verbatim in every explain() and propose_fix() prompt, cache-marked.
The text must stay aligned with the `AvailabilityModel` enum in
`helios/crates/helios-models/src/lib.rs` and the `ScenarioKind` enum in
`helios/crates/helios-engine/src/scenario.rs` — when new variants or
failover semantics are added, update here in the same PR.
"""

AVAILABILITY_MODEL_GLOSSARY = """\
# Helios Availability Model Glossary

Every AWS resource in a Helios graph carries an `AvailabilityModel` that
tells the SMT engine what it takes to make that resource unavailable.
There are four variants.

## SingleAz { az }

Lives in exactly one availability zone. Unavailable iff that AZ is
unavailable. Example kinds: aws_subnet (single-AZ), aws_instance,
aws_elasticache_cluster (non-replicated), aws_db_instance with
`multi_az = false` (its `availability_zone`).

## MultiAz { azs, failover_seconds }

Spans two or more AZs. Available as long as at least one of its AZs is
available. `failover_seconds` is the expected window during which a
failover is visible to clients; for the purposes of SMT availability
this is treated as "temporarily unavailable" during an AZ loss but
recovers within the window. Example kinds: aws_db_instance with
`multi_az = true` (Terraform state does not say which zones, so the pair
is assumed to be `<region>a` and `<region>b`), aws_lb spanning subnets in
2+ AZs.

## Regional { region }

Control-plane resource scoped to a region, not a specific AZ. Available
iff the region is available. Note: a "region outage" scenario takes out
every Regional resource in that region, even if individually each AZ
might still be up. Example kinds: aws_lambda_function, aws_vpc,
aws_s3_bucket, aws_rds_cluster, aws_elasticache_replication_group,
aws_ecs_cluster, aws_ecs_service, aws_eks_cluster, aws_eks_node_group,
aws_sqs_queue, aws_vpc_endpoint, aws_nat_gateway, an
aws_rds_cluster_instance whose zone is not known until apply, and any
resource type Helios does not model specifically. For most of these the
zonal exposure comes from their graph edges (below), not from a zone
attribute. An aws_rds_cluster_instance with a known `availability_zone` is
SingleAz.

## GlobalEdge

Edge / global resource. Treated as always available for current
scenario semantics — not affected by region or AZ outages. No modelled
kind maps here yet; Route53 and CloudFront are the intended future
examples.

## Propagation rules

- `Contains` edges propagate availability: if a resource's container
  fails, the contained resource fails. (Example: subnet fails → every
  instance in that subnet fails.)
- `MemberOf` edges do NOT propagate (over-constrains Regional
  resources like Lambda-in-VPC). They record topology only: an ALB's
  subnets, a database's subnet-group subnets, the queue a Lambda consumes
  (`event_source_arn`), a queue's dead-letter queue (`redrive_policy`).
  One exception: an ALB with no declared `availability_zones` (real state
  never has them) is down when every subnet it is a member of is down.
- `Spread` edges form placement groups: all Spread edges out of one
  resource with the same `via` are one group — the subnets an ECS service
  (`network_configuration.subnets`) or EKS node group (`subnet_ids`) runs
  in, the subnets of an Aurora instance's or Redis replication group's
  subnet group, the subnets of an interface VPC endpoint, the instances of
  an Aurora cluster (`cluster_identifier`). A spread rule, read from the
  resource's attributes, says how many members it can lose:
  - **AnySurvivor**: up while any member is up. Aurora clusters (over their
    instances), interface endpoints, ECS services with `desired_count >= 2`,
    node groups with `scaling_config.desired_size >= 2`, Redis replication
    groups with `automatic_failover_enabled` and at least two nodes.
  - **FailsIfAnyDown**: capacity 1, or placement unknown until apply —
    assume the worst: down when ANY member is down. A `desired_count = 1`
    service, a `desired_size = 1` node group, a Redis group without
    automatic failover, an Aurora instance whose zone is not yet known.
  - **Ignore**: the group does not decide (an Aurora instance whose zone is
    known is simply SingleAz).
  Raising the capacity with `set_attr` (e.g. `desired_count = 2`,
  `automatic_failover_enabled = true`) is a verifiable fix.
- An ECS service `Contains` its cluster, a node group `Contains` its EKS
  cluster, and a NAT gateway `Contains` its subnet.
- `Egress` edges: a subnet whose 0.0.0.0/0 route goes through a NAT gateway
  has an Egress edge to it. Losing the NAT loses EGRESS only: compute in the
  subnet (EC2 instances, ECS services, EKS node groups, and an in-VPC Lambda
  once all of its subnets have lost egress) fails; the subnet itself and a
  database, cache or VPC endpoint in it do not.
- When a plan reference could not say exactly which subnets or instances a
  resource uses (every candidate was linked), its placement group is
  evaluated FailsIfAnyDown and its reason says the placement could not be
  resolved exactly.

## Inconclusive results

Some scenarios cannot be evaluated, and Helios then refuses to answer rather
than report a pass (the CLI exits 3, "INCONCLUSIVE (not a pass)"): an
az-outage in a region where a resource's zone cannot be modelled (no
`availability_zone`, or a subnet attribute naming nothing Helios can see), or
an iam-revocation on a plan where a resource's role comes through a variable,
local, module output or data source. An iam-revocation whose principal no
resource uses is an error. A chain handed to you never comes from such a run.

## Scenario kinds

- **az-outage** { az }: a single availability zone is offline. SingleAz
  resources in that AZ fail; MultiAz resources survive if any of their AZs
  is still up; Regional/GlobalEdge unaffected.
- **region-outage** { region }: an entire region offline. Only GlobalEdge
  resources survive.
- **iam-revocation** { principal_arn }: a role/principal is revoked.
  A string match on `attrs.iam_role_arn`, `attrs.role_arn`, `attrs.role` or
  `attrs.node_role_arn`; any resource naming that principal fails (dependents cascade
  via Contains). Its availability zone stays up.
- **slow-rds-failover** { db_id }: an RDS failover takes longer than
  expected. The target alone is forced unavailable: an aws_db_instance, an
  aws_rds_cluster (the whole cluster is down for the window) or an
  aws_rds_cluster_instance (writer loss — the cluster survives if another
  instance does). Dependents fail via Contains / Spread edges; its zones
  stay up.
- **single-nat-death** { subnet_id }: names an aws_nat_gateway (every
  subnet routing 0.0.0.0/0 through it loses egress, so the compute in them
  fails; the subnets and non-compute resources survive) or a subnet (that
  subnet is treated as down with everything inside). The zone stays up.
- **resource-loss** { resource_id }: any one resource (a cache, a queue, a
  node group) is lost — forced down like slow-rds-failover, without being
  called a database.

When proposing fixes, propose the minimal set of `set_attr` edits that
resolve the failure chain while preserving AWS semantics (e.g. enabling
`multi_az` on an RDS, moving a SingleAz service to a different AZ, or
widening an ALB's `availability_zones` list, raising an ECS service's
`desired_count` or a node group's `scaling_config` `desired_size` to 2, or
enabling `automatic_failover_enabled` on a Redis replication group).

## Reading a FailureChain

A `FailureChain` has a scenario name and a list of failed resources.
Each failed resource has:

- `id`: the Terraform address (e.g. `aws_instance.web`)
- `kind`: the AWS kind (e.g. `Instance`, `DbInstance`, `ElasticacheCluster`)
- `reason`: a short human-readable reason from the SMT counter-example

When narrating, tie each failure back to the scenario's root cause via
the Contains chain. Avoid restating internal model semantics unless the
user asks. Describe observable impact, not SMT mechanics.
"""
