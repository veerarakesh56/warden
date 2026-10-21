use std::collections::HashMap;

use petgraph::graph::{DiGraph, EdgeIndex, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::Error;
use crate::tfjson::RawResource;

pub type ResourceId = String;

/// A typed AWS resource node in the graph.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Resource {
    /// Terraform address, e.g. `aws_vpc.main`. Unique within a plan.
    pub id: ResourceId,
    pub kind: ResourceKind,
    /// Raw attrs, service-specific. Parsed further by helios-models.
    pub attrs: serde_json::Value,
    /// Plan only: principal attributes that are unknown until apply (see [`PendingPrincipal`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_principals: Vec<PendingPrincipal>,
    /// Why this resource's ZONE cannot be modelled: an attribute that decides where it runs names
    /// nothing Helios can place (a subnet that is external, a data source, a literal id, or a
    /// reference it cannot follow). An az-outage in its region is then inconclusive, not a pass.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved: Vec<String>,
    /// The `via`s of this resource's edges that a plan reference could not resolve exactly, so
    /// every instance was linked. A placement group with such members is evaluated worst case.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inexact: Vec<String>,
    /// Terraform's own `sensitive_values` mask for `attrs`: `true` wherever a value is sensitive.
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub sensitive_values: Value,
}

impl Resource {
    /// A resource with nothing unresolved, inexact, pending or sensitive.
    pub fn new(id: impl Into<ResourceId>, kind: ResourceKind, attrs: Value) -> Self {
        Resource {
            id: id.into(),
            kind,
            attrs,
            pending_principals: Vec::new(),
            unresolved: Vec::new(),
            inexact: Vec::new(),
            sensitive_values: Value::Null,
        }
    }
}

/// The attribute names under which a Terraform resource carries an IAM principal ARN. `role` is
/// what `aws_lambda_function` uses, `node_role_arn` what `aws_eks_node_group` uses; the others
/// cover EKS clusters, ECS tasks, EC2 instance profiles and similar.
pub const PRINCIPAL_ATTRS: [&str; 4] = ["iam_role_arn", "role_arn", "role", "node_role_arn"];

/// A principal attribute a plan cannot know yet (a role's ARN is assigned at apply).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingPrincipal {
    pub attr: String,
    /// The address and name of every `aws_iam_role` its configuration references. EMPTY when the
    /// references cannot be followed (a variable, a local, a module output): then nothing can be
    /// said about which principal it will be.
    pub roles: Vec<String>,
    /// The configuration ALSO references something Helios cannot follow (a variable, a local, a
    /// module output, a data source), so the value may be something other than `roles`.
    #[serde(default)]
    pub opaque: bool,
}

/// The resource types helios models as graph nodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceKind {
    Vpc,
    Subnet,
    Instance,
    Lb,
    DbInstance,
    ElasticacheCluster,
    LambdaFunction,
    S3Bucket,
    RdsCluster,
    RdsClusterInstance,
    ElasticacheReplicationGroup,
    EcsCluster,
    EcsService,
    EksCluster,
    EksNodeGroup,
    SqsQueue,
    VpcEndpoint,
    NatGateway,
}

/// The one table between node kinds and Terraform types; both directions read it.
const KINDS: &[(ResourceKind, &str)] = &[
    (ResourceKind::Vpc, "aws_vpc"),
    (ResourceKind::Subnet, "aws_subnet"),
    (ResourceKind::Instance, "aws_instance"),
    (ResourceKind::Lb, "aws_lb"),
    (ResourceKind::DbInstance, "aws_db_instance"),
    (ResourceKind::ElasticacheCluster, "aws_elasticache_cluster"),
    (ResourceKind::LambdaFunction, "aws_lambda_function"),
    (ResourceKind::S3Bucket, "aws_s3_bucket"),
    (ResourceKind::RdsCluster, "aws_rds_cluster"),
    (ResourceKind::RdsClusterInstance, "aws_rds_cluster_instance"),
    (
        ResourceKind::ElasticacheReplicationGroup,
        "aws_elasticache_replication_group",
    ),
    (ResourceKind::EcsCluster, "aws_ecs_cluster"),
    (ResourceKind::EcsService, "aws_ecs_service"),
    (ResourceKind::EksCluster, "aws_eks_cluster"),
    (ResourceKind::EksNodeGroup, "aws_eks_node_group"),
    (ResourceKind::SqsQueue, "aws_sqs_queue"),
    (ResourceKind::VpcEndpoint, "aws_vpc_endpoint"),
    (ResourceKind::NatGateway, "aws_nat_gateway"),
];

/// Types that are never nodes (they cannot fail on their own) but that edges are resolved through:
/// a subnet group names the subnets of a database, an event source mapping ties a Lambda to a
/// queue, route tables tie a subnet to its NAT.
const LINK_ONLY: &[&str] = &[
    "aws_db_subnet_group",
    "aws_elasticache_subnet_group",
    "aws_lambda_event_source_mapping",
    "aws_route_table",
    "aws_route",
    "aws_route_table_association",
    "aws_main_route_table_association",
    "aws_default_route_table",
    "aws_iam_role",
];

/// Route tables, whether created or the VPC's adopted default.
const TABLES: &[&str] = &["aws_route_table", "aws_default_route_table"];

impl ResourceKind {
    pub fn from_tf_type(tf_type: &str) -> Option<Self> {
        KINDS.iter().find(|(_, t)| *t == tf_type).map(|(k, _)| *k)
    }

    /// The Terraform type this kind is read from; the inverse of [`Self::from_tf_type`].
    pub fn tf_type(self) -> &'static str {
        KINDS
            .iter()
            .find(|(k, _)| *k == self)
            .map(|(_, t)| *t)
            .expect("every ResourceKind is in KINDS")
    }
}

/// Edge kind between two resources.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Dependency {
    /// Child contains parent via an explicit `*_id` attr (subnet.vpc_id, instance.subnet_id, ...).
    Contains(&'static str),
    /// Load-balancer-style many-to-many membership (alb.subnets[]). Topology only: no failure
    /// travels along it.
    MemberOf(&'static str),
    /// One member of a placement group: the subnets an ECS service or node group runs in, the
    /// instances of an Aurora cluster. All edges out of a resource with the same `via` form one
    /// group, and `helios_models::spread_rule` says how many members it can lose.
    Spread(&'static str),
    /// A subnet's default route (`0.0.0.0/0`) goes through this NAT gateway. Losing the NAT loses
    /// the subnet's EGRESS: compute in it (instances, Lambdas, ECS services, EKS node groups)
    /// fails; the subnet itself, and a database, cache or endpoint in it, do not.
    Egress(&'static str),
}

impl Dependency {
    /// The attribute the edge was derived from.
    pub fn via(&self) -> &'static str {
        match self {
            Dependency::Contains(v)
            | Dependency::MemberOf(v)
            | Dependency::Spread(v)
            | Dependency::Egress(v) => v,
        }
    }

    /// Does a resource's own `down` read the target's `down` along this edge? These edges must
    /// form a DAG, or the definitions `down ⇔ …` have more than one solution. Most `MemberOf`
    /// edges are topology only; an ALB's `subnets` (its zones, when it declares none) and a
    /// Lambda's `subnet_ids` are read. `Egress` is NOT: a subnet's `down` never reads its NAT --
    /// the COMPUTE in the subnet does (instance -> subnet --Egress--> NAT), and nothing a NAT's
    /// `down` reads (its own subnet, via `Contains`) reads that compute back. So a NAT inside the
    /// very subnet whose default route it serves is a broken network, not an ambiguous encoding.
    fn propagates(&self) -> bool {
        match self {
            Dependency::MemberOf(via) => matches!(*via, "subnets" | "subnet_ids"),
            Dependency::Egress(_) => false,
            _ => true,
        }
    }
}

/// Every managed resource the graph builder can see: the nodes, and resources that are resolved
/// *through* but never become nodes (link-only, such as subnet groups).
#[derive(Clone, Copy)]
struct Entry<'a> {
    address: &'a str,
    tf_type: &'a str,
    values: &'a Value,
    /// The resource block's `expressions` (plan documents only): where an attribute that is
    /// unknown until apply still says which resources it will name.
    expressions: Option<&'a Value>,
    node: Option<NodeIndex>,
}

impl<'a> Entry<'a> {
    fn new(
        raw: &'a RawResource,
        config: &'a HashMap<String, Value>,
        node: Option<NodeIndex>,
    ) -> Self {
        Entry {
            address: &raw.address,
            tf_type: &raw.tf_type,
            values: &raw.values,
            expressions: config.get(&strip_keys(&raw.address)),
            node,
        }
    }
}

/// Resources of one type Helios does not model: they are not in the graph, and NOT assumed healthy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Skipped {
    #[serde(rename = "type")]
    pub tf_type: String,
    pub count: usize,
    pub addresses: Vec<String>,
}

/// `config` maps a config address (`module.net.aws_subnet.a`, no instance keys) to its block's
/// expressions; it is empty for a state document. `regions` maps the same keys to the region of
/// the provider the block uses: a resource with no `region` of its own gets that one (a plan has
/// no ARN yet, and a multi-region plan has no majority to fall back on).
pub(crate) fn build_graph(
    raw_resources: Vec<RawResource>,
    config: &HashMap<String, Value>,
    regions: &HashMap<String, String>,
) -> Result<(DiGraph<Resource, Dependency>, Vec<Skipped>), Error> {
    WARNED.with(|w| w.borrow_mut().clear());
    let mut graph = DiGraph::<Resource, Dependency>::new();
    let mut entries: Vec<Entry> = Vec::new();
    let entry = |raw, node| Entry::new(raw, config, node);
    // Unsupported type -> how many resources of it were skipped: ONE summary line, not one each.
    let mut skipped: std::collections::BTreeMap<&str, Vec<String>> = Default::default();
    let mut data_sources: Vec<&str> = Vec::new();

    for raw in &raw_resources {
        // A data source describes infrastructure Terraform does not own. It cannot fail, and
        // treating `data.aws_subnet.selected` as a subnet reports a failure that does not exist.
        if raw.mode != "managed" {
            data_sources.push(&raw.address);
            continue;
        }
        let Some(kind) = ResourceKind::from_tf_type(&raw.tf_type) else {
            if LINK_ONLY.contains(&raw.tf_type.as_str()) {
                entries.push(entry(raw, None));
            } else {
                skipped
                    .entry(raw.tf_type.as_str())
                    .or_default()
                    .push(raw.address.clone());
            }
            continue;
        };
        if kind != ResourceKind::Instance {
            warn_if_zone_unknown(kind, raw); // an instance: once its subnet is known, below
        }
        let mut resource = Resource::new(raw.address.clone(), kind, raw.values.clone());
        if let (Some(region), Some(attrs)) = (
            regions.get(&strip_keys(&raw.address)),
            resource.attrs.as_object_mut(),
        ) {
            if attrs
                .get("region")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                attrs.insert("region".into(), Value::String(region.clone()));
            }
        }
        resource.sensitive_values = raw.sensitive_values.clone();
        let node = graph.add_node(resource);
        entries.push(entry(raw, Some(node)));
    }

    if !data_sources.is_empty() {
        // Not a warning: nothing is lost. One line, so a real warning is not buried under them.
        tracing::info!(
            "ignored {} data sources (they cannot fail): {}",
            data_sources.len(),
            data_sources.join(", ")
        );
    }
    let mut skipped: Vec<Skipped> = skipped
        .into_iter()
        .map(|(t, addresses)| Skipped {
            tf_type: t.to_string(),
            count: addresses.len(),
            addresses,
        })
        .collect();
    skipped.sort_by(|a, b| b.count.cmp(&a.count).then(a.tf_type.cmp(&b.tf_type)));
    if !skipped.is_empty() {
        let total: usize = skipped.iter().map(|s| s.count).sum();
        let list: Vec<String> = skipped
            .iter()
            .map(|s| format!("{} ({})", s.tf_type, s.count))
            .collect();
        tracing::warn!(
            "skipped {total} resources of {} unsupported types (not in the graph, not assumed \
             healthy): {}",
            skipped.len(),
            list.join(", ")
        );
    }
    let edges = collect_edges(&entries);
    for (from, to, dep, exact) in edges.links {
        if !exact && !graph[from].inexact.iter().any(|v| v == dep.via()) {
            graph[from].inexact.push(dep.via().to_string());
        }
        graph.add_edge(from, to, dep);
    }
    for (node, why) in edges.unresolved {
        // An unknown egress matters only to compute in the subnet (see `Dependency::Egress`).
        if why.starts_with("egress unknown") && !has_compute(&graph, node) {
            continue;
        }
        tracing::warn!(
            resource = %graph[node].id,
            "{why} -- a zone outage in its region is INCONCLUSIVE"
        );
        graph[node].unresolved.push(why);
    }
    // An instance with no zone of its own is placed by a subnet whose zone is known: no warning.
    for (e, raw) in entries.iter().zip(managed(&raw_resources)) {
        let Some(node) = e.node else { continue };
        if graph[node].kind == ResourceKind::Instance
            && !graph.edges(node).any(|edge| {
                matches!(edge.weight(), Dependency::Contains(_))
                    && graph[edge.target()].kind == ResourceKind::Subnet
                    && has_zone(&graph[edge.target()].attrs)
            })
        {
            warn_if_zone_unknown(ResourceKind::Instance, raw);
        }
    }
    for e in &entries {
        if let Some(node) = e.node {
            graph[node].pending_principals = pending_principals(&entries, e);
        }
    }
    check_acyclic(&mut graph)?;
    Ok((graph, skipped))
}

/// The raw resources that became entries, in entry order.
fn managed(raw: &[RawResource]) -> impl Iterator<Item = &RawResource> {
    raw.iter().filter(|r| {
        r.mode == "managed"
            && (ResourceKind::from_tf_type(&r.tf_type).is_some()
                || LINK_ONLY.contains(&r.tf_type.as_str()))
    })
}

/// Does compute (an instance, ECS service, EKS node group or in-VPC Lambda) run in this subnet?
fn has_compute(graph: &DiGraph<Resource, Dependency>, subnet: NodeIndex) -> bool {
    graph
        .edges_directed(subnet, petgraph::Direction::Incoming)
        .any(|e| {
            let kind = graph[e.source()].kind;
            matches!(
                (kind, e.weight()),
                (ResourceKind::Instance, Dependency::Contains(_))
                    | (ResourceKind::EcsService, Dependency::Spread(_))
                    | (ResourceKind::EksNodeGroup, Dependency::Spread(_))
                    | (
                        ResourceKind::LambdaFunction,
                        Dependency::MemberOf("subnet_ids")
                    )
            )
        })
}

fn has_zone(attrs: &Value) -> bool {
    attrs
        .get("availability_zone")
        .and_then(Value::as_str)
        .is_some_and(|z| !z.is_empty())
}

/// Reference prefixes Helios cannot follow to a resource: whatever they contribute is unknown.
const INDIRECT: &[&str] = &["var.", "local.", "module.", "data.", "each.value"];

fn is_indirect(reference: &str) -> bool {
    INDIRECT.iter().any(|p| reference.starts_with(p))
}

thread_local! {
    /// Warnings already printed while building the current graph: resolving the same attribute
    /// again (once per subnet, per group) must not repeat them.
    static WARNED: std::cell::RefCell<std::collections::HashSet<String>> = Default::default();
}

/// True the first time `key` is seen while building this graph.
fn first_time(key: String) -> bool {
    WARNED.with(|w| w.borrow_mut().insert(key))
}

/// Resolved targets (entry indices), and whether they are EXACTLY what the attribute names --
/// false when a plan reference could only be resolved by linking every instance.
type Hits = (Vec<usize>, bool);

/// What [`collect_edges`] found: edges (with exactness) and zone-deciding attributes that name
/// nothing Helios can place.
struct Edges {
    links: Vec<(NodeIndex, NodeIndex, Dependency, bool)>,
    unresolved: Vec<(NodeIndex, String)>,
}

/// The edge rules, one arm per kind, applied in node order.
fn collect_edges(entries: &[Entry]) -> Edges {
    use Dependency::{Contains, Egress, MemberOf, Spread};
    const SUBNET: &[&str] = &["aws_subnet"];
    const VPC: &[&str] = &["aws_vpc"];
    let mut links = Vec::new();
    let mut unresolved = Vec::new();
    let routing = subnet_egress(entries);
    for (me, from) in entries.iter().enumerate() {
        let Some(idx) = from.node else { continue };
        let Some(kind) = ResourceKind::from_tf_type(from.tf_type) else {
            continue;
        };
        // Link `from` to the node targets; how many edges that made.
        let mut push = |(targets, exact): Hits, dep: Dependency| -> usize {
            let before = links.len();
            for t in targets {
                if let Some(target) = entries[t].node {
                    links.push((idx, target, dep.clone(), exact));
                }
            }
            links.len() - before
        };
        // A zone-deciding attribute that linked nothing: the resource cannot be placed.
        let mut unplaced = |made: usize, what: &str| {
            if made == 0 {
                unresolved.push((idx, format!("{what} names no subnet Helios can place")));
            }
        };
        let direct = |path: &str, types: &[&str]| resolve(entries, from, path, types);
        let then = |froms: Hits, path: &str, types: &[&str]| then(entries, froms, path, types);
        // The entries of `tf_type` whose `path` names me (an Aurora cluster's instances).
        let naming_me =
            |tf_type: &str, path: &str| naming(entries, tf_type, path, &[me], &[from.tf_type]);
        let zone_known = from
            .values
            .get("availability_zone")
            .and_then(Value::as_str)
            .is_some_and(|z| !z.is_empty());
        match kind {
            ResourceKind::Subnet => {
                push(direct("vpc_id", VPC), Contains("vpc_id"));
                // A subnet's egress is its route table's default route: when that goes through a
                // NAT gateway, compute in the subnet loses egress with the NAT (or its zone).
                match routing.get(&me) {
                    Some(RouteEgress::Unknown(why)) => unresolved.push((idx, why.clone())),
                    Some(RouteEgress::Known(nats, exact)) => {
                        push((nats.clone(), *exact), Egress("nat_gateway_id"));
                    }
                    None => {}
                }
            }
            ResourceKind::Instance => {
                push(direct("subnet_id", SUBNET), Contains("subnet_id"));
            }
            ResourceKind::Lb => {
                let made = push(direct("subnets", SUBNET), MemberOf("subnets"));
                let declares_zones = from
                    .values
                    .get("availability_zones")
                    .and_then(Value::as_array)
                    .is_some_and(|z| !z.is_empty());
                if !declares_zones {
                    unplaced(made, "`subnets`");
                }
            }
            ResourceKind::DbInstance | ResourceKind::RdsCluster => {
                if kind == ResourceKind::RdsCluster {
                    push(
                        naming_me("aws_rds_cluster_instance", "cluster_identifier"),
                        Spread("cluster_identifier"),
                    );
                }
                let groups = direct("db_subnet_group_name", &["aws_db_subnet_group"]);
                push(
                    then(groups, "subnet_ids", SUBNET),
                    MemberOf("db_subnet_group_name"),
                );
            }
            ResourceKind::RdsClusterInstance => {
                let clusters = direct("cluster_identifier", &["aws_rds_cluster"]);
                let groups = then(clusters, "db_subnet_group_name", &["aws_db_subnet_group"]);
                let made = push(
                    then(groups, "subnet_ids", SUBNET),
                    Spread("db_subnet_group_name"),
                );
                if !zone_known {
                    unplaced(
                        made,
                        "its zone is unknown until apply, and its cluster's subnet group",
                    );
                    if made > 0 {
                        tracing::warn!(
                            resource = %from.address,
                            "availability zone unknown until apply: treated as lost when ANY \
                             subnet of its subnet group is lost (worst case)"
                        );
                    }
                }
            }
            ResourceKind::ElasticacheCluster | ResourceKind::ElasticacheReplicationGroup => {
                let groups = direct("subnet_group_name", &["aws_elasticache_subnet_group"]);
                let subnets = then(groups, "subnet_ids", SUBNET);
                if kind == ResourceKind::ElasticacheCluster {
                    push(subnets, MemberOf("subnet_group_name"));
                } else {
                    let made = push(subnets, Spread("subnet_group_name"));
                    unplaced(made, "its subnet group");
                }
            }
            ResourceKind::LambdaFunction => {
                let made = push(
                    direct("vpc_config.subnet_ids", SUBNET),
                    MemberOf("subnet_ids"),
                );
                let in_vpc = from
                    .values
                    .get("vpc_config")
                    .and_then(Value::as_array)
                    .is_some_and(|blocks| !blocks.is_empty());
                if in_vpc {
                    unplaced(made, "`vpc_config.subnet_ids`");
                }
                let mappings = naming_me("aws_lambda_event_source_mapping", "function_name");
                push(
                    then(mappings, "event_source_arn", &["aws_sqs_queue"]),
                    MemberOf("event_source_arn"),
                );
            }
            ResourceKind::EcsService => {
                push(direct("cluster", &["aws_ecs_cluster"]), Contains("cluster"));
                let made = push(
                    direct("network_configuration.subnets", SUBNET),
                    Spread("network_configuration.subnets"),
                );
                unplaced(made, "`network_configuration.subnets`");
            }
            ResourceKind::EksCluster => {
                push(
                    direct("vpc_config.subnet_ids", SUBNET),
                    MemberOf("vpc_config.subnet_ids"),
                );
            }
            ResourceKind::EksNodeGroup => {
                push(
                    direct("cluster_name", &["aws_eks_cluster"]),
                    Contains("cluster_name"),
                );
                let made = push(direct("subnet_ids", SUBNET), Spread("subnet_ids"));
                unplaced(made, "`subnet_ids`");
            }
            ResourceKind::SqsQueue => {
                push(
                    direct("redrive_policy.deadLetterTargetArn", &["aws_sqs_queue"]),
                    MemberOf("redrive_policy"),
                );
            }
            // An interface endpoint has an ENI per subnet; a gateway endpoint has no subnets.
            ResourceKind::VpcEndpoint => {
                if from.values.get("vpc_endpoint_type").and_then(Value::as_str) != Some("Gateway") {
                    let made = push(direct("subnet_ids", SUBNET), Spread("subnet_ids"));
                    unplaced(made, "`subnet_ids`");
                }
            }
            ResourceKind::NatGateway => {
                let made = push(direct("subnet_id", SUBNET), Contains("subnet_id"));
                unplaced(made, "`subnet_id`");
            }
            ResourceKind::Vpc | ResourceKind::S3Bucket | ResourceKind::EcsCluster => {}
        }
    }
    Edges { links, unresolved }
}

/// Where a subnet's default route (`0.0.0.0/0`) goes.
#[derive(Clone, Debug)]
enum RouteEgress {
    /// Through these NAT gateways (none: an internet gateway, or no default route), exactly or not.
    Known(Vec<usize>, bool),
    /// Cannot be told; the reason starts with "egress unknown".
    Unknown(String),
}

const NAT: &[&str] = &["aws_nat_gateway"];
const SUBNET_T: &[&str] = &["aws_subnet"];
const VPC_T: &[&str] = &["aws_vpc"];

/// Every subnet's egress, worked out once for the whole graph: each association is resolved once.
///
/// A subnet named by an association uses its table. A subnet no resolvable association names uses
/// -- if some association's `subnet_id` cannot be resolved (`subnet_id = each.value.id` over a
/// `for_each`) -- one of THOSE associations' tables, or the VPC's main table when there are fewer
/// of them than such subnets; if every candidate table has the same NAT set, that is its egress,
/// otherwise it is unknown. With no unresolvable association, it uses the main table. A table
/// whose association's `route_table_id`, default route, or default route's NAT is set through a
/// reference Helios cannot follow has an unknown egress. Without any NAT gateway in the graph,
/// egress cannot go through one: nothing is recorded.
fn subnet_egress(entries: &[Entry]) -> HashMap<usize, RouteEgress> {
    let mut out = HashMap::new();
    if !entries.iter().any(|e| e.tf_type == "aws_nat_gateway") {
        return out;
    }
    struct Assoc {
        subnets: Vec<usize>,
        subnet_opaque: bool,
        tables: Hits,
        table_opaque: bool,
    }
    let assocs: Vec<Assoc> = entries
        .iter()
        .filter(|e| e.tf_type == "aws_route_table_association")
        .map(|e| {
            let (subnets, _) = resolve(entries, e, "subnet_id", SUBNET_T);
            let tables = resolve(entries, e, "route_table_id", TABLES);
            Assoc {
                subnet_opaque: subnets.is_empty() && opaque(entries, e, "subnet_id", SUBNET_T),
                table_opaque: tables.0.is_empty() && opaque(entries, e, "route_table_id", TABLES),
                subnets,
                tables,
            }
        })
        .collect();
    // A default `aws_route` whose table cannot be resolved may be on ANY table.
    let orphan_route = entries
        .iter()
        .filter(|e| {
            e.tf_type == "aws_route" && is_default_route(e.values, "destination_cidr_block")
        })
        .find(|e| {
            resolve(entries, e, "route_table_id", TABLES).0.is_empty()
                && opaque(entries, e, "route_table_id", TABLES)
        })
        .map(|e| e.address.to_string());
    let table_nats = |(tables, exact): &Hits| -> RouteEgress {
        if let Some(route) = &orphan_route {
            return RouteEgress::Unknown(format!(
                "egress unknown: the default route {route} names its route table through a \
                 reference Helios cannot follow"
            ));
        }
        default_route_nats(entries, tables, *exact)
    };
    let subnets: Vec<usize> = (0..entries.len())
        .filter(|&i| entries[i].tf_type == "aws_subnet")
        .collect();
    let unresolvable: Vec<&Assoc> = assocs
        .iter()
        .filter(|a| a.subnets.is_empty() && a.subnet_opaque)
        .collect();
    let unassociated = subnets
        .iter()
        .filter(|s| !assocs.iter().any(|a| a.subnets.contains(s)))
        .count();
    for &s in &subnets {
        let named: Vec<&Assoc> = assocs.iter().filter(|a| a.subnets.contains(&s)).collect();
        let egress = if !named.is_empty() {
            if named.iter().any(|a| a.table_opaque) {
                RouteEgress::Unknown(
                    "egress unknown: its route table association names the table through a \
                     reference Helios cannot follow (a local, variable or module output)"
                        .to_string(),
                )
            } else {
                let mut tables = Vec::new();
                let mut exact = true;
                for a in &named {
                    exact &= a.tables.1;
                    tables.extend(a.tables.0.iter().copied());
                }
                table_nats(&(tables, exact))
            }
        } else if !unresolvable.is_empty() {
            let mut candidates: Vec<RouteEgress> = unresolvable
                .iter()
                .map(|a| {
                    if a.table_opaque {
                        RouteEgress::Unknown(String::new())
                    } else {
                        table_nats(&a.tables)
                    }
                })
                .collect();
            if unresolvable.len() < unassociated {
                candidates.push(main_table_nats(entries, s, &table_nats));
            }
            agreed(&candidates).unwrap_or_else(|| {
                RouteEgress::Unknown(format!(
                    "egress unknown: {} route table association(s) name a subnet Helios cannot \
                     resolve (e.g. `subnet_id = each.value.id`), and the route tables they could \
                     put it in do not agree on a NAT gateway",
                    unresolvable.len()
                ))
            })
        } else {
            main_table_nats(entries, s, &table_nats)
        };
        out.insert(s, egress);
    }
    out
}

/// The one NAT set every candidate agrees on, if they are all known and agree.
fn agreed(candidates: &[RouteEgress]) -> Option<RouteEgress> {
    let mut sets = candidates.iter().map(|c| match c {
        RouteEgress::Known(nats, exact) => {
            let mut sorted = nats.clone();
            sorted.sort();
            Some((sorted, *exact))
        }
        RouteEgress::Unknown(_) => None,
    });
    let (first, mut exact) = sets.next()??;
    for set in sets {
        let (nats, e) = set?;
        if nats != first {
            return None;
        }
        exact &= e;
    }
    Some(RouteEgress::Known(first, exact))
}

/// The VPC's main route table's NATs, for a subnet with no association: the table a
/// main-route-table association names, else the VPC's adopted default. A main table Terraform
/// does not manage is invisible: no NAT.
fn main_table_nats(
    entries: &[Entry],
    subnet: usize,
    table_nats: &dyn Fn(&Hits) -> RouteEgress,
) -> RouteEgress {
    let (vpcs, _) = resolve(entries, &entries[subnet], "vpc_id", VPC_T);
    let mains = naming(
        entries,
        "aws_main_route_table_association",
        "vpc_id",
        &vpcs,
        VPC_T,
    );
    let tables = if !mains.0.is_empty() {
        then(entries, mains, "route_table_id", TABLES)
    } else {
        let by_vpc = naming(entries, "aws_default_route_table", "vpc_id", &vpcs, VPC_T);
        if by_vpc.0.is_empty() {
            // A plan: `vpc_id` is unknown, the reference is on this attribute.
            naming(
                entries,
                "aws_default_route_table",
                "default_route_table_id",
                &vpcs,
                VPC_T,
            )
        } else {
            by_vpc
        }
    };
    table_nats(&tables)
}

fn is_default_route(v: &Value, key: &str) -> bool {
    v.get(key).and_then(Value::as_str) == Some("0.0.0.0/0")
}

/// The NAT gateways the default (`0.0.0.0/0`) routes of these route tables go through: inline
/// `route` blocks and separate `aws_route` resources. Other destinations are not egress. Unknown
/// when such a route names its NAT through a reference Helios cannot follow.
fn default_route_nats(entries: &[Entry], tables: &[usize], mut exact: bool) -> RouteEgress {
    let mut out = Vec::new();
    let unknown = |what: &str| {
        RouteEgress::Unknown(format!(
            "egress unknown: {what} names its NAT gateway through a reference Helios cannot follow"
        ))
    };
    for &t in tables {
        let table = entries[t];
        // The table seen with its default routes only. A `route` attribute absent altogether is
        // unknown (a plan), and stays absent so the references decide.
        let view = match table.values.get("route").and_then(Value::as_array) {
            Some(routes) => serde_json::json!({
                "route": routes
                    .iter()
                    .filter(|r| is_default_route(r, "cidr_block"))
                    .collect::<Vec<_>>()
            }),
            None => serde_json::json!({}),
        };
        let view = Entry {
            values: &view,
            ..table
        };
        let (nats, e) = resolve(entries, &view, "route.nat_gateway_id", NAT);
        if nats.is_empty() && opaque(entries, &view, "route.nat_gateway_id", NAT) {
            return unknown(&format!("route table {}", table.address));
        }
        exact &= e;
        out.extend(nats);
    }
    for route in entries.iter().filter(|e| {
        e.tf_type == "aws_route" && is_default_route(e.values, "destination_cidr_block")
    }) {
        let (tables_of_route, e) = resolve(entries, route, "route_table_id", TABLES);
        if tables_of_route.iter().any(|t| tables.contains(t)) {
            let (nats, e2) = resolve(entries, route, "nat_gateway_id", NAT);
            if nats.is_empty() && opaque(entries, route, "nat_gateway_id", NAT) {
                return unknown(&format!("the default route {}", route.address));
            }
            exact &= e && e2;
            out.extend(nats);
        }
    }
    let mut seen = Vec::new();
    out.retain(|i| {
        let new = !seen.contains(i);
        seen.push(*i);
        new
    });
    RouteEgress::Known(out, exact)
}

/// Unknown until apply, set in the configuration, and resolving to nothing Helios can follow
/// (`each.value.id`, `local.table_ids[count.index]`): the value exists, Helios cannot say what.
fn opaque(entries: &[Entry], from: &Entry, path: &str, types: &[&str]) -> bool {
    let segs: Vec<&str> = path.split('.').collect();
    let Some(expressions) = from.expressions else {
        return false;
    };
    if !unknown_at(from.values, &segs) || !resolve(entries, from, path, types).0.is_empty() {
        return false;
    }
    let mut refs = Vec::new();
    references_at(expressions, &segs, &mut refs);
    !refs.is_empty()
}

/// `path` on each of `froms`, e.g. the `subnet_ids` of a subnet group.
fn then(entries: &[Entry], (froms, mut exact): Hits, path: &str, types: &[&str]) -> Hits {
    let mut out = Vec::new();
    for f in froms {
        let (targets, e) = resolve(entries, &entries[f], path, types);
        exact &= e;
        for t in targets {
            if !out.contains(&t) {
                out.push(t);
            }
        }
    }
    (out, exact)
}

/// The entries of `tf_type` whose `path` names one of `targets` (of `types`).
fn naming(entries: &[Entry], tf_type: &str, path: &str, targets: &[usize], types: &[&str]) -> Hits {
    let mut exact = true;
    let mut out = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        if e.tf_type != tf_type {
            continue;
        }
        let (hits, e_exact) = resolve(entries, e, path, types);
        if hits.iter().any(|t| targets.contains(t)) {
            exact &= e_exact;
            out.push(i);
        }
    }
    (out, exact)
}

/// The entries of `target_types` that `from`'s attribute at `path` names, in the order it names
/// them. `path` is dot-separated and walks objects and lists of blocks alike (real state stores
/// `vpc_config`, `network_configuration` and `scaling_config` as one-element lists), and into
/// JSON-encoded strings (`redrive_policy`). A value matches a target's `id`, `arn` or `name`, and
/// ONLY a target of one of the given types: names collide across types (WARDEN's DB subnet group
/// is named exactly like its Aurora cluster).
///
/// When the values name nothing and the document is a plan, the configuration's references at the
/// same path decide instead (see [`resolve_references`]).
fn resolve(entries: &[Entry], from: &Entry, path: &str, target_types: &[&str]) -> Hits {
    let segs: Vec<&str> = path.split('.').collect();
    let out = resolve_values(entries, from, &segs, target_types);
    // Only an UNKNOWN value falls back: a known empty `vpc_config = []` means no VPC, whatever
    // the (shared, per-block) configuration of other instances says.
    let Some(expressions) = from.expressions else {
        return (out, true);
    };
    if !out.is_empty() || !unknown_at(from.values, &segs) {
        return (out, true);
    }
    let mut refs = Vec::new();
    references_at(expressions, &segs, &mut refs);
    let (out, exact) = resolve_references(entries, from, path, &refs, target_types);
    let indirect: Vec<&str> = refs
        .iter()
        .map(String::as_str)
        .filter(|r| is_indirect(r))
        .collect();
    // `var.ha ? [a.id, b.id] : [a.id]`: the resources found are only CANDIDATES -- what the
    // variable picks is unknown -- so the result is not exact (a group on it is worst case).
    let exact = exact && indirect.is_empty();
    // A block that exists with its contents unknown and no expression: a `dynamic` block, which
    // the configuration JSON does not describe.
    let dynamic_block = refs.is_empty()
        && segs.len() > 1
        && from
            .values
            .get(segs[0])
            .and_then(Value::as_array)
            .is_some_and(|blocks| !blocks.is_empty());
    if out.is_empty()
        && (!indirect.is_empty() || dynamic_block)
        && first_time(format!("missing {} {path}", from.address))
    {
        tracing::warn!(
            resource = %from.address,
            attribute = %path,
            via = ?indirect,
            "unknown until apply, and its configuration names no {target_types:?} Helios can \
             follow (references through locals, variables, module outputs and dynamic blocks are \
             not followed): this edge is MISSING from the graph"
        );
    }
    (out, exact)
}

/// [`resolve`] against the attribute values alone.
fn resolve_values(
    entries: &[Entry],
    from: &Entry,
    segs: &[&str],
    target_types: &[&str],
) -> Vec<usize> {
    let mut wanted = Vec::new();
    strings_at(from.values, segs, &mut wanted);
    let mut out = Vec::new();
    // ponytail: linear scan per value, O(n^2) over a plan; index by (type, key) if plans get huge.
    for s in wanted.iter().filter(|s| !s.is_empty()) {
        for (i, e) in entries.iter().enumerate() {
            let hit = target_types.contains(&e.tf_type)
                && ["id", "arn", "name"]
                    .iter()
                    .any(|k| e.values.get(k).and_then(Value::as_str) == Some(s.as_str()));
            if hit && !out.contains(&i) {
                out.push(i);
            }
        }
    }
    out
}

/// Resolve a plan attribute through its configuration `references`. Terraform lists every form of
/// each reference (`aws_subnet.private[0].id`, `aws_subnet.private[0]`, `aws_subnet.private`);
/// they are grouped by the referenced resource block, in `from`'s module, and per block:
///
/// 1. references to specific instances (`aws_subnet.private[0]`, `fn["order-processor"]`) name
///    only those instances;
/// 2. otherwise, if the expression uses `count.index` or `each.key` and `from` is itself an
///    instance, it names the instance with the same index or key (`subnet_id =
///    aws_subnet.private[count.index].id`);
/// 3. otherwise every instance of the block (a splat, `aws_subnet.public[*].id`) — with a warning
///    when the attribute holds a single value, since it cannot name them all.
///
/// The result is NOT exact when rule 2 cannot pair (so every instance is linked), or rule 3 links
/// several instances to a single-valued attribute. More links are worst case for a `Contains`
/// parent but BEST case for a group that survives while any member does, so the caller marks
/// them and the engine evaluates such a group worst case.
fn resolve_references(
    entries: &[Entry],
    from: &Entry,
    path: &str,
    refs: &[String],
    target_types: &[&str],
) -> Hits {
    let prefix = module_prefix(from.address);
    let own_key = instance_key(from.address);
    let paired = refs.iter().any(|r| r == "count.index" || r == "each.key");
    // Every instance of a resource block in `from`'s module.
    let instances = |block: &str| -> Vec<String> {
        entries
            .iter()
            .filter(|e| {
                e.address
                    .strip_prefix(&prefix)
                    .is_some_and(|rest| strip_keys(rest) == block)
            })
            .map(|e| e.address.to_string())
            .collect()
    };
    // (block, specific instance keys), in first-reference order.
    let mut blocks: Vec<(String, Vec<String>)> = Vec::new();
    for r in refs {
        let parts = split_address(r);
        let [tf_type, name, ..] = parts.as_slice() else {
            continue;
        };
        if !target_types.contains(tf_type) {
            continue;
        }
        let block = format!("{tf_type}.{}", strip_keys(name));
        let key = instance_key(name);
        match blocks.iter_mut().find(|(b, _)| *b == block) {
            Some((_, keys)) => keys.extend(key),
            None => blocks.push((block, key.into_iter().collect())),
        }
    }
    let mut out = Vec::new();
    let mut exact = true;
    for (block, keys) in blocks {
        let wanted: Vec<String> = if !keys.is_empty() {
            keys.iter().map(|k| format!("{prefix}{block}{k}")).collect()
        } else if let (true, Some(k)) = (paired, &own_key) {
            let all = instances(&block);
            let pair = format!("{prefix}{block}{k}");
            // The references say `count.index` was USED, not that the index IS `count.index`:
            // `aws_subnet.x[count.index % 2]` references exactly the same things. A key is exact
            // when it exists; a count index only when both blocks have as many instances.
            // Counted in `from`'s module instance, as `instances` counts the target block.
            let own_block = strip_keys(from.address);
            let own_count = entries
                .iter()
                .filter(|e| {
                    module_prefix(e.address) == prefix && strip_keys(e.address) == own_block
                })
                .count();
            let pairs_exactly = all.contains(&pair)
                && (refs.iter().any(|r| r == "each.key") || own_count == all.len());
            if pairs_exactly {
                vec![pair]
            } else {
                if first_time(format!("pairing {} {path} {block}", from.address)) {
                    tracing::warn!(
                        resource = %from.address,
                        attribute = %path,
                        block = %block,
                        "the index into {block} is not the plain `count.index` / `each.key` (the \
                         instance counts differ, or the key is absent -- e.g. `count.index % 2`): \
                         linking every instance; a placement group built on this is evaluated worst \
                         case"
                    );
                }
                exact &= all.len() <= 1;
                all
            }
        } else {
            let all = instances(&block);
            // ponytail: "plural attribute name" stands in for the schema's list type.
            let single_valued = !path.ends_with('s');
            if all.len() > 1 && single_valued {
                if first_time(format!("single {} {path} {block}", from.address)) {
                    tracing::warn!(
                        resource = %from.address,
                        attribute = %path,
                        block = %block,
                        "single-valued attribute references every instance of {block}: linking all \
                         of them (the real value is one of them); a placement group built on this is \
                         evaluated worst case"
                    );
                }
                exact = false;
            }
            all
        };
        for w in wanted {
            if let Some(i) = entries.iter().position(|e| e.address == w) {
                if !out.contains(&i) {
                    out.push(i);
                }
            }
        }
    }
    (out, exact)
}

/// A plan's principal attributes that are unknown until apply, and the roles their configuration
/// references (empty when those cannot be followed). Nothing for a state, or a known value.
fn pending_principals(entries: &[Entry], from: &Entry) -> Vec<PendingPrincipal> {
    let Some(expressions) = from.expressions else {
        return Vec::new();
    };
    PRINCIPAL_ATTRS
        .iter()
        .filter(|attr| from.values.get(**attr).is_none())
        .filter_map(|attr| {
            let mut refs = Vec::new();
            references_at(expressions, &[attr], &mut refs);
            if refs.is_empty() {
                return None; // not configured at all: this resource has no such principal
            }
            let opaque = refs.iter().any(|r| is_indirect(r));
            let roles = resolve_references(entries, from, attr, &refs, &["aws_iam_role"])
                .0
                .into_iter()
                .flat_map(|i| {
                    let name = entries[i].values.get("name").and_then(Value::as_str);
                    std::iter::once(entries[i].address.to_string()).chain(name.map(String::from))
                })
                .collect();
            Some(PendingPrincipal {
                attr: attr.to_string(),
                roles,
                opaque,
            })
        })
        .collect()
}

/// The `references` of the expression at `path`: descends objects and lists of blocks, and stops
/// at the first expression (an object with `references` / `constant_value`) — `route` is one
/// expression for all its routes, `redrive_policy` one for the whole JSON document.
fn references_at(expr: &Value, path: &[&str], out: &mut Vec<String>) {
    match expr {
        Value::Array(items) => items.iter().for_each(|x| references_at(x, path, out)),
        Value::Object(m) if m.contains_key("references") || m.contains_key("constant_value") => {
            if let Some(Value::Array(refs)) = m.get("references") {
                out.extend(refs.iter().filter_map(Value::as_str).map(String::from));
            }
        }
        Value::Object(m) => {
            if let Some((head, rest)) = path.split_first() {
                if let Some(x) = m.get(*head) {
                    references_at(x, rest, out);
                }
            }
        }
        _ => {}
    }
}

/// Is the attribute at `path` absent — in a plan, unknown until apply? An empty list or a null is
/// a KNOWN absence (no `vpc_config` block at all), not an unknown.
fn unknown_at(v: &Value, path: &[&str]) -> bool {
    match (v, path.split_first()) {
        (Value::Array(items), _) => items.iter().any(|x| unknown_at(x, path)),
        (Value::Object(m), Some((head, rest))) => m.get(*head).is_none_or(|x| unknown_at(x, rest)),
        _ => false,
    }
}

/// Split a Terraform address or reference on the dots that are not inside an instance key:
/// `module.m["a.b"].aws_x.y[0].id` -> `module`, `m["a.b"]`, `aws_x`, `y[0]`, `id`.
fn split_address(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut start, mut depth, mut quoted) = (0, 0, false);
    for (i, c) in s.char_indices() {
        match c {
            '"' => quoted = !quoted,
            '[' if !quoted => depth += 1,
            ']' if !quoted => depth -= 1,
            '.' if !quoted && depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

/// The address with every instance key removed: its configuration address.
fn strip_keys(address: &str) -> String {
    let (mut out, mut depth, mut quoted) = (String::new(), 0, false);
    for c in address.chars() {
        match c {
            '"' if depth > 0 => quoted = !quoted,
            '[' if !quoted => depth += 1,
            ']' if !quoted => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

/// The module path of an address, with instance keys: `module.net[0].` for
/// `module.net[0].aws_subnet.a[1]`, `""` at the root.
fn module_prefix(address: &str) -> String {
    let parts = split_address(address);
    let mut prefix = String::new();
    let mut i = 0;
    while i + 1 < parts.len() && parts[i] == "module" {
        prefix.push_str(&format!("module.{}.", parts[i + 1]));
        i += 2;
    }
    prefix
}

/// The instance key an address ends in (`[0]`, `["orders"]`), if any.
fn instance_key(address: &str) -> Option<String> {
    let last = *split_address(address).last()?;
    last.find('[').map(|i| last[i..].to_string())
}

/// A zone that is not known (a plan's zone that is computed at apply, or a hand-written state
/// without one) is not something to guess quietly.
fn warn_if_zone_unknown(kind: ResourceKind, raw: &RawResource) {
    let known = has_zone(&raw.values);
    let multi_az = raw.values.get("multi_az").and_then(Value::as_bool) == Some(true);
    match kind {
        ResourceKind::Subnet | ResourceKind::Instance | ResourceKind::ElasticacheCluster
            if !known =>
        {
            tracing::warn!(
                resource = %raw.address,
                "AVAILABILITY ZONE UNKNOWN: Helios would have to guess it, so a zone outage in \
                 its region is INCONCLUSIVE"
            )
        }
        ResourceKind::DbInstance if !known && !multi_az => tracing::warn!(
            resource = %raw.address,
            "AVAILABILITY ZONE UNKNOWN: Helios would have to guess it, so a zone outage in its \
             region is INCONCLUSIVE"
        ),
        _ => {}
    }
}

/// Every string at `path` under `v`, flattening lists at any level.
fn strings_at(v: &Value, path: &[&str], out: &mut Vec<String>) {
    match (v, path.split_first()) {
        (Value::Array(items), _) => items.iter().for_each(|x| strings_at(x, path, out)),
        (Value::String(s), None) => out.push(s.clone()),
        (Value::String(s), Some(_)) => {
            if let Ok(parsed @ Value::Object(_)) = serde_json::from_str::<Value>(s) {
                strings_at(&parsed, path, out);
            }
        }
        (Value::Object(m), Some((head, rest))) => {
            if let Some(x) = m.get(*head) {
                strings_at(x, rest, out);
            }
        }
        _ => {}
    }
}

/// Failure-propagating edges must form a DAG. The SMT encoding *defines* each resource's `down`
/// from its parents' (`down ⇔ … ∨ parent_down`); around a cycle that definition has two solutions
/// (all up, all down) and the verdict would be the solver's choice, not a fact about the estate.
///
/// A cycle through an edge that only exists because a plan reference was over-connected (see
/// [`resolve_references`]) is an artefact of that guess: those edges are dropped with a warning.
/// A cycle of exact edges is a real configuration and an error.
fn check_acyclic(graph: &mut DiGraph<Resource, Dependency>) -> Result<(), Error> {
    loop {
        let propagating = graph.filter_map(|_, _| Some(()), |_, d| d.propagates().then_some(()));
        let Some(scc) = petgraph::algo::tarjan_scc(&propagating)
            .into_iter()
            .find(|scc| scc.len() > 1 || propagating.contains_edge(scc[0], scc[0]))
        else {
            return Ok(());
        };
        let guessed: Vec<EdgeIndex> = graph
            .edge_indices()
            .filter(|&e| {
                let (a, b) = graph.edge_endpoints(e).expect("edge exists");
                let dep = &graph[e];
                scc.contains(&a)
                    && scc.contains(&b)
                    && dep.propagates()
                    && graph[a].inexact.iter().any(|v| v == dep.via())
            })
            .collect();
        if guessed.is_empty() {
            let mut ids: Vec<String> = scc.iter().map(|i| graph[*i].id.clone()).collect();
            ids.sort();
            return Err(Error::DependencyCycle(ids));
        }
        for &e in guessed.iter().rev() {
            let (a, b) = graph.edge_endpoints(e).expect("edge exists");
            tracing::warn!(
                from = %graph[a].id,
                to = %graph[b].id,
                via = %graph[e].via(),
                "dropping an edge that only an over-connected plan reference produced: it closed a \
                 dependency cycle"
            );
            // Highest index first: `remove_edge` moves the last edge into the freed slot.
            graph.remove_edge(e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_table_round_trips() {
        for (kind, tf_type) in KINDS {
            assert_eq!(ResourceKind::from_tf_type(tf_type), Some(*kind));
            assert_eq!(kind.tf_type(), *tf_type);
        }
    }

    #[test]
    fn addresses_split_on_dots_outside_instance_keys() {
        let a = r#"module.m["a.b"].aws_x.y[0].id"#;
        assert_eq!(
            split_address(a),
            vec!["module", r#"m["a.b"]"#, "aws_x", "y[0]", "id"]
        );
        assert_eq!(strip_keys(a), "module.m.aws_x.y.id");
        assert_eq!(strip_keys(r#"aws_x.y["k]"]"#), "aws_x.y");
        assert_eq!(
            module_prefix(r#"module.m["a.b"].module.n[2].aws_x.y"#),
            r#"module.m["a.b"].module.n[2]."#
        );
        assert_eq!(module_prefix("aws_x.y[0]"), "");
        assert_eq!(instance_key(r#"aws_x.y["k"]"#).as_deref(), Some(r#"["k"]"#));
        assert_eq!(instance_key("module.m[0].aws_x.y"), None);
    }

    #[test]
    fn a_contains_cycle_is_rejected() {
        let mut g = DiGraph::<Resource, Dependency>::new();
        let mk = |id: &str| Resource::new(id, ResourceKind::Subnet, Value::Null);
        let a = g.add_node(mk("aws_subnet.a"));
        let b = g.add_node(mk("aws_subnet.b"));
        g.add_edge(a, b, Dependency::Contains("x"));
        // A topology-only MemberOf edge back is not a cycle...
        g.add_edge(b, a, Dependency::MemberOf("y"));
        assert!(check_acyclic(&mut g).is_ok());
        // ...but an ALB's `subnets` decide its zones, so that one is read and must be acyclic.
        let mut alb = g.clone();
        alb.add_edge(b, a, Dependency::MemberOf("subnets"));
        assert!(check_acyclic(&mut alb).is_err());
        g.add_edge(b, a, Dependency::Contains("y"));
        match check_acyclic(&mut g) {
            Err(Error::DependencyCycle(ids)) => {
                assert_eq!(ids, vec!["aws_subnet.a", "aws_subnet.b"])
            }
            other => panic!("expected DependencyCycle, got {other:?}"),
        }
    }

    #[test]
    fn a_cycle_closed_only_by_an_over_connected_edge_drops_that_edge() {
        let mut g = DiGraph::<Resource, Dependency>::new();
        let subnet = g.add_node(Resource::new(
            "aws_subnet.a",
            ResourceKind::Subnet,
            Value::Null,
        ));
        let nat = g.add_node(Resource::new(
            "aws_nat_gateway.n",
            ResourceKind::NatGateway,
            Value::Null,
        ));
        g.add_edge(nat, subnet, Dependency::Contains("subnet_id"));
        // Egress is never read by the subnet's own `down`, so this is NOT a cycle.
        g.add_edge(subnet, nat, Dependency::Egress("nat_gateway_id"));
        assert!(check_acyclic(&mut g.clone()).is_ok());
        // A propagating edge back IS. Exact: a real (broken) configuration -- an error.
        g.add_edge(subnet, nat, Dependency::Spread("x"));
        assert!(check_acyclic(&mut g.clone()).is_err());
        // Over-connected: that edge goes; the NAT's placement and the Egress edge stay.
        g[subnet].inexact.push("x".into());
        assert!(check_acyclic(&mut g).is_ok());
        assert_eq!(g.edge_count(), 2);
        assert!(g
            .edge_indices()
            .all(|e| !matches!(g[e], Dependency::Spread(_))));
    }
}
