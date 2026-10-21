//! Z3 encoder. Covers all six scenario kinds.
//!
//! Every resource's `down` Boolean is *defined* — `down ⇔ availability-condition ∨ forced ∨
//! (any Contains-parent down)` — and a scenario then pins every AZ, region and `forced`
//! variable it does not name to `false`. The model is therefore unique for a scenario, not a
//! solver default. (v0.1.0 forced a targeted resource down *through* its availability rule, so
//! Z3 satisfied "the subnet is down" by taking its whole AZ down — and nothing pinned the zones
//! a scenario never mentioned. Found by reading the fixture output, fixed in 0.1.1.)

use std::collections::HashMap;

use helios_graph::{Dependency, Resource, ResourceGraph, ResourceKind, PRINCIPAL_ATTRS};
use helios_models::{
    availability_for, infer_region, region_for, spread_rule, zone_is_guessed, AvailabilityModel,
    SpreadRule,
};
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use z3::{ast::Bool, SatResult, Solver};

use crate::report::{FailedResource, FailureChain};

/// Smoke test the Z3 binding compiles and links.
#[doc(hidden)]
pub fn solver_smoke() -> SatResult {
    let solver = Solver::new();
    let a = Bool::new_const("a");
    solver.assert(&a);
    solver.check()
}

/// Extract the region name from an AZ name by stripping the trailing letter.
/// "us-east-1a" → "us-east-1". Handles any AZ suffix char.
pub(crate) fn region_of_az(az: &str) -> String {
    helios_models::region_of_az(az)
}

/// Last-resort region, used only when NOTHING in the graph declares one.
///
/// Until 2026-09-06 this was the region every resource without an explicit `region` attribute got,
/// which silently produced the wrong answer for any estate outside it: a eu-west-2 multi-AZ database
/// survived a eu-west-2 outage and fell with a us-east-1 one. The region is now derived per resource
/// (`helios_models::region_for`) with `infer_region` over the whole graph as the default.
pub(crate) const DEFAULT_REGION: &str = "us-east-1";

/// The region this graph is in: whatever most of its resources agree on, else [`DEFAULT_REGION`].
pub(crate) fn graph_region(graph: &ResourceGraph) -> String {
    infer_region(graph.node_indices().map(|i| &graph[i].attrs))
        .unwrap_or_else(|| DEFAULT_REGION.to_string())
}

/// SMT encoding of a resource graph. One [`Encoder`] per simulation run.
pub struct Encoder {
    /// `Bool` per resource, true ⇔ resource is down.
    pub(crate) resource_down: HashMap<NodeIndex, Bool>,
    /// `Bool` per AZ, true ⇔ that AZ is down.
    pub(crate) az_down: HashMap<String, Bool>,
    /// `Bool` per region, true ⇔ that region is down.
    pub(crate) region_down: HashMap<String, Bool>,
    /// `Bool` per resource, true ⇔ a scenario forces this resource down directly (slow RDS
    /// failover, NAT death, IAM revocation) — independently of its AZ or region.
    pub(crate) forced_down: HashMap<NodeIndex, Bool>,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder {
    pub fn new() -> Self {
        Self {
            resource_down: HashMap::new(),
            az_down: HashMap::new(),
            region_down: HashMap::new(),
            forced_down: HashMap::new(),
        }
    }

    pub(crate) fn az_var(&mut self, az: &str) -> Bool {
        self.az_down
            .entry(az.to_string())
            .or_insert_with(|| Bool::new_const(format!("az_down_{az}")))
            .clone()
    }

    pub(crate) fn region_var(&mut self, region: &str) -> Bool {
        self.region_down
            .entry(region.to_string())
            .or_insert_with(|| Bool::new_const(format!("region_down_{region}")))
            .clone()
    }

    /// For every node in the graph, declare its `resource_down` and `forced_down` Bools and
    /// assert the definition
    /// `down ⇔ availability-condition ∨ forced ∨ (any Contains-parent down) ∨ (any Spread-group term)`,
    /// where a Spread group's term is the conjunction of its members' `down` (`AnySurvivor`), their
    /// disjunction (`FailsIfAnyDown`) or absent (`Ignore`) — the rule read from the attrs NOW, so a
    /// `set_attr` fix re-verifies against it.
    ///
    /// The parent term is part of the *definition*, not a separate implication: with a plain
    /// `parent ⇒ child` on top of a biconditional, forcing a child down could only be satisfied
    /// by making the child's own AZ or region down — which is exactly the v0.1.0 defect.
    pub fn encode_availability(&mut self, graph: &ResourceGraph, solver: &Solver) {
        // Pass 1: declare every resource's variables so parent terms can be referenced.
        for idx in graph.node_indices() {
            let r: &Resource = &graph[idx];
            self.resource_down
                .insert(idx, Bool::new_const(format!("down_{}", r.id)));
            self.forced_down
                .insert(idx, Bool::new_const(format!("forced_{}", r.id)));
        }
        // One inferred region for the whole graph, so the few resources that declare no region
        // signal at all land where everything else is rather than in us-east-1.
        let fallback_region = graph_region(graph);
        // Pass 2: assert the definition.
        for idx in graph.node_indices() {
            let r: &Resource = &graph[idx];
            let model = model_of(graph, idx, &fallback_region);
            let down = self.resource_down[&idx].clone();
            let cond: Bool = match model {
                AvailabilityModel::SingleAz { az } => {
                    let region = region_of_az(&az);
                    let az_v = self.az_var(&az);
                    let region_v = self.region_var(&region);
                    Bool::or(&[az_v, region_v])
                }
                AvailabilityModel::MultiAz { azs, .. } => {
                    let region = azs
                        .first()
                        .map(|a| region_of_az(a))
                        .unwrap_or_else(|| region_for(&r.attrs, &fallback_region));
                    let region_v = self.region_var(&region);
                    let subnets = member_subnets(graph, idx);
                    if azs.is_empty() && !subnets.is_empty() {
                        // Real `aws_lb` state has no `availability_zones`, only `subnets`: its
                        // zones are its subnets', so it is down when every one of them is -- or,
                        // when a plan could not say exactly which subnets, when ANY is (linking
                        // every candidate would otherwise make it look more resilient).
                        let downs: Vec<Bool> = subnets
                            .iter()
                            .map(|s| self.resource_down[s].clone())
                            .collect();
                        let lost = if is_inexact(r, "subnets") {
                            Bool::or(&downs)
                        } else {
                            Bool::and(&downs)
                        };
                        Bool::or(&[lost, region_v])
                    } else if azs.is_empty() {
                        // No AZ information at all. `Bool::and(&[])` is Z3's empty conjunction and
                        // evaluates to TRUE, so encoding "all of its zones are down" here would be
                        // vacuously satisfied and the resource would be reported down in EVERY
                        // scenario -- including one naming a zone nothing lives in. An unknown AZ
                        // set means the AZ term must not contribute; the resource still falls with
                        // its region. Its AZ behaviour is simply not modelled, so say so.
                        tracing::warn!(
                            resource = %r.id,
                            "multi-AZ resource declares no availability_zones: its AZ behaviour is \
                             NOT modelled (it will only fail with its region)"
                        );
                        region_v
                    } else {
                        let az_vars: Vec<Bool> = azs.iter().map(|a| self.az_var(a)).collect();
                        let all_azs_down = Bool::and(&az_vars);
                        Bool::or(&[all_azs_down, region_v])
                    }
                }
                AvailabilityModel::Regional { region } => self.region_var(&region),
                AvailabilityModel::GlobalEdge => Bool::from_bool(false),
            };
            let mut terms: Vec<Bool> = vec![cond, self.forced_down[&idx].clone()];
            let compute = is_compute(r.kind);
            for edge in graph.edges_directed(idx, petgraph::Direction::Outgoing) {
                if matches!(edge.weight(), Dependency::Contains(_)) {
                    terms.push(self.resource_down[&edge.target()].clone());
                    if compute {
                        terms.push(self.egress_lost(graph, edge.target()));
                    }
                }
            }
            for (via, members) in spread_groups(graph, idx) {
                // A compute member subnet is lost for this resource if it is down OR has lost
                // its egress (its default route's NAT is down).
                let downs: Vec<Bool> = members
                    .iter()
                    .map(|&m| {
                        let down = self.resource_down[&m].clone();
                        if compute {
                            Bool::or(&[down, self.egress_lost(graph, m)])
                        } else {
                            down
                        }
                    })
                    .collect();
                match group_rule(r, via) {
                    SpreadRule::AnySurvivor => terms.push(Bool::and(&downs)),
                    SpreadRule::FailsIfAnyDown => terms.push(Bool::or(&downs)),
                    SpreadRule::Ignore => {}
                }
            }
            // An in-VPC Lambda runs in any of its subnets: it is lost when every one of them is
            // down or has lost egress -- or, when a plan could not say exactly which subnets, when
            // any is (linking every candidate would otherwise make it look more resilient).
            if r.kind == ResourceKind::LambdaFunction {
                let lost: Vec<Bool> = member_subnets(graph, idx)
                    .iter()
                    .map(|&s| {
                        Bool::or(&[self.resource_down[&s].clone(), self.egress_lost(graph, s)])
                    })
                    .collect();
                if !lost.is_empty() {
                    terms.push(if is_inexact(r, "subnet_ids") {
                        Bool::or(&lost)
                    } else {
                        Bool::and(&lost)
                    });
                }
            }
            solver.assert(down.eq(Bool::or(&terms)));
        }
    }

    /// True iff any NAT gateway on `subnet`'s default route is down (false when it has none).
    fn egress_lost(&self, graph: &ResourceGraph, subnet: NodeIndex) -> Bool {
        let nats: Vec<Bool> = egress_nats(graph, subnet)
            .iter()
            .map(|n| self.resource_down[n].clone())
            .collect();
        Bool::or(&nats)
    }

    /// Pin every AZ, region and `forced` variable NOT listed to `false`, so the only things
    /// down are the ones the scenario names and what follows from them. Without this the
    /// unnamed variables are free and the result depends on the solver's default assignment.
    fn pin_everything_else(
        &self,
        solver: &Solver,
        azs_named: &[String],
        regions_named: &[String],
        forced_named: &[NodeIndex],
    ) {
        for (az, v) in &self.az_down {
            if !azs_named.contains(az) {
                solver.assert(v.not());
            }
        }
        for (region, v) in &self.region_down {
            if !regions_named.contains(region) {
                solver.assert(v.not());
            }
        }
        for (idx, v) in &self.forced_down {
            if !forced_named.contains(idx) {
                solver.assert(v.not());
            }
        }
    }

    /// For every strong containment edge, assert `parent_down ⇒ child_down`.
    ///
    /// Only [`Dependency::Contains`] edges propagate — they represent hard parent/child
    /// links (subnet→vpc, instance→subnet) where the child cannot survive the parent.
    /// [`Dependency::MemberOf`] edges (alb/lambda into a set of subnets) are loose: the
    /// resource's availability model already captures the per-AZ membership, so adding
    /// an implication here would over-constrain and falsely kill Regional services like
    /// Lambda when a single member subnet fails.
    pub fn encode_dependencies(&self, graph: &ResourceGraph, solver: &Solver) {
        for edge in graph.edge_references() {
            if !matches!(edge.weight(), Dependency::Contains(_)) {
                continue;
            }
            let child_idx = edge.source();
            let parent_idx = edge.target();
            let (Some(child), Some(parent)) = (
                self.resource_down.get(&child_idx),
                self.resource_down.get(&parent_idx),
            ) else {
                continue;
            };
            solver.assert(parent.implies(child));
        }
    }

    /// Apply a [`crate::Scenario`] to the solver by forcing the right Bool(s) true.
    ///
    /// Needs `graph` so targeted-resource kinds (slow-rds-failover,
    /// single-nat-death, iam-revocation) can look up the affected nodes.
    /// Assert the scenario. Returns the target id the scenario named but the graph does not
    /// contain, if any.
    ///
    /// A miss used to be silent: nothing was asserted, nothing was down, and the run printed
    /// "No failures — configuration is resilient" and exited 0. So a typo in `db_id`, or naming one
    /// of the skipped resource kinds, read as a clean bill of health. The fix path already errors on
    /// an unknown id, so the asymmetry ran the wrong way — the safety-critical direction was the
    /// forgiving one. The caller turns this into an error.
    #[must_use]
    pub fn apply_scenario(
        &mut self,
        scenario: &crate::Scenario,
        graph: &ResourceGraph,
        solver: &Solver,
    ) -> Option<String> {
        match &scenario.kind {
            crate::ScenarioKind::AzOutage { az } => {
                let v = self.az_var(az);
                solver.assert(&v);
                // Pin the region UP so we observe the AZ effect in isolation — and every
                // OTHER zone up too, so the other zones' survival is asserted, not defaulted.
                self.pin_everything_else(solver, std::slice::from_ref(az), &[], &[]);
            }
            crate::ScenarioKind::RegionOutage { region } => {
                let v = self.region_var(region);
                solver.assert(&v);
                // A region outage takes its zones with it (semantically, and so the model reads
                // consistently); every other region and zone stays up.
                let azs_in_region: Vec<String> = self
                    .az_down
                    .keys()
                    .filter(|az| &region_of_az(az) == region)
                    .cloned()
                    .collect();
                for az in &azs_in_region {
                    solver.assert(&self.az_down[az]);
                }
                self.pin_everything_else(solver, &azs_in_region, std::slice::from_ref(region), &[]);
            }
            crate::ScenarioKind::SlowRdsFailover { db_id }
            | crate::ScenarioKind::SingleNatDeath { subnet_id: db_id }
            | crate::ScenarioKind::ResourceLoss { resource_id: db_id } => {
                // Force that specific resource down through its `forced` variable — NOT through
                // its availability rule — so its AZ stays up and only Contains-dependents follow.
                let mut named = Vec::new();
                match graph.node_indices().find(|i| &graph[*i].id == db_id) {
                    Some(idx) => {
                        solver.assert(&self.forced_down[&idx]);
                        named.push(idx);
                    }
                    None => {
                        self.pin_everything_else(solver, &[], &[], &named);
                        return Some(db_id.clone());
                    }
                }
                self.pin_everything_else(solver, &[], &[], &named);
            }
            crate::ScenarioKind::IamRevocation { principal_arn } => {
                // String match on the attributes that carry a principal: `iam_role_arn`,
                // `role_arn`, and `role` (the attribute name aws_lambda_function actually uses).
                let mut named = Vec::new();
                for idx in graph.node_indices() {
                    if names_principal(&graph[idx], principal_arn) {
                        solver.assert(&self.forced_down[&idx]);
                        named.push(idx);
                    }
                }
                self.pin_everything_else(solver, &[], &[], &named);
            }
        }
        None
    }

    /// After `solver.check() == Sat`, build the failure chain from the model.
    pub fn extract_failures(
        &self,
        graph: &ResourceGraph,
        scenario: &crate::Scenario,
        solver: &Solver,
    ) -> FailureChain {
        let Some(model) = solver.get_model() else {
            return FailureChain {
                scenario: scenario.name.clone(),
                failures: vec![],
            };
        };
        // Same derivation the encoding used, so a reason string can never disagree with the verdict.
        let fallback_region = graph_region(graph);
        let mut failures = Vec::new();
        for (idx, down_bool) in &self.resource_down {
            let is_down = model
                .eval(down_bool, true)
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !is_down {
                continue;
            }
            let r: &Resource = &graph[*idx];
            let is_down = |n: &NodeIndex| {
                model
                    .eval(&self.resource_down[n], true)
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false)
            };
            let reason = reason_for(r, &model_of(graph, *idx, &fallback_region), scenario)
                .or_else(|| group_reason(graph, *idx, &fallback_region, is_down))
                .or_else(|| egress_reason(graph, *idx, is_down))
                .or_else(|| contains_reason(graph, *idx, is_down))
                .unwrap_or_else(|| "failure propagated from a dependency".to_string());
            failures.push(FailedResource {
                id: r.id.clone(),
                kind: format!("{:?}", r.kind),
                reason,
            });
        }
        failures.sort_by(|a, b| a.id.cmp(&b.id));
        FailureChain {
            scenario: scenario.name.clone(),
            failures,
        }
    }
}

/// Short per-resource explanation for why this scenario takes it down, when the scenario names
/// it or its own zone / region. `None` when it fell through an edge (see [`group_reason`]).
fn reason_for(
    r: &Resource,
    model: &AvailabilityModel,
    scenario: &crate::Scenario,
) -> Option<String> {
    use crate::ScenarioKind as S;
    Some(match (model, &scenario.kind) {
        (AvailabilityModel::SingleAz { az }, S::AzOutage { az: s_az }) if az == s_az => {
            format!("single-AZ in {az}, which is down")
        }
        (AvailabilityModel::SingleAz { az }, S::RegionOutage { region })
            if &region_of_az(az) == region =>
        {
            format!("single-AZ in {az} (region {region} is down)")
        }
        (AvailabilityModel::MultiAz { azs, .. }, S::RegionOutage { region }) if azs.is_empty() => {
            format!("multi-AZ across its subnets — whole region {region} is down")
        }
        (AvailabilityModel::MultiAz { azs, .. }, S::RegionOutage { region })
            if !azs.is_empty() && azs.iter().all(|a| &region_of_az(a) == region) =>
        {
            format!("multi-AZ across {azs:?} — whole region {region} is down")
        }
        (AvailabilityModel::Regional { region }, S::RegionOutage { region: r }) if region == r => {
            format!("regional in {region}, which is down")
        }
        (_, S::SlowRdsFailover { db_id }) if db_id == &r.id => match r.kind {
            ResourceKind::RdsCluster => format!(
                "Aurora cluster {db_id} failover window exceeded SLO — the whole cluster is \
                 unavailable during it"
            ),
            ResourceKind::RdsClusterInstance => format!(
                "Aurora instance {db_id} lost (writer loss) — the cluster must fail over to \
                 another instance"
            ),
            _ => format!("RDS {db_id} failover window exceeded SLO — treated as unavailable"),
        },
        (_, S::SingleNatDeath { subnet_id }) if subnet_id == &r.id => match r.kind {
            ResourceKind::NatGateway => format!("NAT {subnet_id} is dead"),
            _ => format!("NAT in subnet {subnet_id} is dead — subnet loses egress"),
        },
        (_, S::ResourceLoss { resource_id }) if resource_id == &r.id => {
            format!("{resource_id} is lost (resource-loss) — treated as unavailable")
        }
        (_, S::IamRevocation { principal_arn }) if names_principal(r, principal_arn) => {
            format!("principal {principal_arn} was revoked")
        }
        _ => return None,
    })
}

/// The availability model the encoding uses: [`availability_for`], except that an instance whose
/// zone is unknown (a plan: it is computed from the subnet) but whose subnet's is known is
/// Regional here -- its `Contains` edge to the subnet carries the zone, where the model alone
/// would have to guess one.
fn model_of(graph: &ResourceGraph, idx: NodeIndex, fallback_region: &str) -> AvailabilityModel {
    let r = &graph[idx];
    if placed_by_subnet(graph, idx) {
        return AvailabilityModel::Regional {
            region: region_for(&r.attrs, fallback_region),
        };
    }
    availability_for(r.kind.tf_type(), &r.attrs, fallback_region)
}

/// An instance with no zone of its own, in a subnet whose zone is known.
fn placed_by_subnet(graph: &ResourceGraph, idx: NodeIndex) -> bool {
    let r = &graph[idx];
    r.kind == ResourceKind::Instance
        && zone_is_guessed(r.kind.tf_type(), &r.attrs)
        && graph
            .edges_directed(idx, petgraph::Direction::Outgoing)
            .any(|e| {
                let s = &graph[e.target()];
                matches!(e.weight(), Dependency::Contains(_))
                    && s.kind == ResourceKind::Subnet
                    && !zone_is_guessed(s.kind.tf_type(), &s.attrs)
            })
}

/// Why a resource fell through a placement group — a Spread group, or the subnets an ALB with no
/// declared zones spans — given which nodes the model has down. `None` if no group explains it.
fn group_reason(
    graph: &ResourceGraph,
    idx: NodeIndex,
    fallback_region: &str,
    is_down: impl Fn(&NodeIndex) -> bool,
) -> Option<String> {
    let r = &graph[idx];
    const INEXACT: &str = "placement could not be resolved exactly from the plan";
    if let AvailabilityModel::MultiAz { azs, .. } =
        availability_for(r.kind.tf_type(), &r.attrs, fallback_region)
    {
        let subnets = member_subnets(graph, idx);
        let n = subnets.len();
        if azs.is_empty() && n > 0 {
            if is_inexact(r, "subnets") && subnets.iter().any(&is_down) {
                return Some(format!(
                    "{INEXACT} — lost when any of its {n} candidate subnets is lost (worst case)"
                ));
            }
            if subnets.iter().all(&is_down) {
                return Some(format!("every one of its {n} subnets placements is down"));
            }
        }
    }
    let compute = is_compute(r.kind);
    // A member is lost to a compute resource when it is down or has lost its egress.
    let lost =
        |m: &NodeIndex| is_down(m) || (compute && egress_nats(graph, *m).iter().any(&is_down));
    if r.kind == ResourceKind::LambdaFunction {
        let subnets = member_subnets(graph, idx);
        let n = subnets.len();
        if n > 0 {
            if is_inexact(r, "subnet_ids") && subnets.iter().any(&lost) {
                return Some(format!(
                    "{INEXACT} — lost when any of its {n} candidate subnets is lost (worst case)"
                ));
            }
            if subnets.iter().all(&is_down) {
                return Some(format!(
                    "every one of its {n} subnet_ids placements is down"
                ));
            }
        }
    }
    let number = |path: &[&str]| {
        let mut v = &r.attrs;
        for seg in path {
            if let serde_json::Value::Array(items) = v {
                v = items.first().unwrap_or(&serde_json::Value::Null);
            }
            v = v.get(seg).unwrap_or(&serde_json::Value::Null);
        }
        v.as_u64().map_or("unset".to_string(), |n| n.to_string())
    };
    spread_groups(graph, idx)
        .into_iter()
        .find_map(|(via, members)| {
            let n = members.len();
            match group_rule(r, via) {
                SpreadRule::AnySurvivor if members.iter().all(&lost) => {
                    Some(if members.iter().all(&is_down) {
                        format!("every one of its {n} {via} placements is down")
                    } else {
                        format!("every one of its {n} {via} placements is down or has lost egress")
                    })
                }
                SpreadRule::FailsIfAnyDown if members.iter().any(&lost) => {
                    let why = if is_inexact(r, via) {
                        INEXACT.to_string()
                    } else {
                        match r.kind {
                            ResourceKind::RdsClusterInstance => {
                                "its zone is unknown until apply".to_string()
                            }
                            ResourceKind::EcsService => format!(
                                "desired_count {} (where its task runs is unknown)",
                                number(&["desired_count"])
                            ),
                            ResourceKind::EksNodeGroup => format!(
                                "desired_size {} (where its node runs is unknown)",
                                number(&["scaling_config", "desired_size"])
                            ),
                            ResourceKind::ElasticacheReplicationGroup => {
                                "no automatic failover to a replica (its primary's zone is \
                                 unknown)"
                                    .to_string()
                            }
                            _ => "it cannot lose a member".to_string(),
                        }
                    };
                    Some(format!(
                        "{why} — lost when any of its {n} {via} placements is lost (worst case)"
                    ))
                }
                _ => None,
            }
        })
}

/// Why a resource fell with the thing it is inside: names that parent and the attribute that
/// points at it (`its subnet_id aws_subnet.a is down`), not just "a dependency".
fn contains_reason(
    graph: &ResourceGraph,
    idx: NodeIndex,
    is_down: impl Fn(&NodeIndex) -> bool,
) -> Option<String> {
    graph
        .edges_directed(idx, petgraph::Direction::Outgoing)
        .find(|e| matches!(e.weight(), Dependency::Contains(_)) && is_down(&e.target()))
        .map(|e| format!("its {} {} is down", e.weight().via(), graph[e.target()].id))
}

/// Why a compute resource fell because a subnet it runs in lost its egress.
fn egress_reason(
    graph: &ResourceGraph,
    idx: NodeIndex,
    is_down: impl Fn(&NodeIndex) -> bool,
) -> Option<String> {
    // A subnet it is IN that is itself down explains it first: that is the Contains parent
    // ("failure propagated from a dependency"), not the NAT that zone also took.
    let parent_down = graph
        .edges_directed(idx, petgraph::Direction::Outgoing)
        .any(|e| matches!(e.weight(), Dependency::Contains(_)) && is_down(&e.target()));
    if !is_compute(graph[idx].kind) || parent_down {
        return None;
    }
    graph
        .edges_directed(idx, petgraph::Direction::Outgoing)
        .map(|e| e.target())
        .filter(|&s| graph[s].kind == ResourceKind::Subnet)
        .find_map(|s| {
            egress_nats(graph, s)
                .into_iter()
                .find(|n| is_down(n))
                .map(|n| {
                    format!(
                        "egress via NAT {} (the default route of {}), which is down",
                        graph[n].id, graph[s].id
                    )
                })
        })
}

/// The placement rule of one of a resource's groups: its kind's rule, read from the attrs -- or
/// worst case when a plan reference could not say exactly which members it has.
fn group_rule(r: &Resource, via: &str) -> SpreadRule {
    match spread_rule(r.kind.tf_type(), &r.attrs) {
        SpreadRule::AnySurvivor if is_inexact(r, via) => SpreadRule::FailsIfAnyDown,
        rule => rule,
    }
}

fn is_inexact(r: &Resource, via: &str) -> bool {
    r.inexact.iter().any(|v| v == via)
}

/// Kinds that need egress to work: they fail when their subnet's NAT does.
fn is_compute(kind: ResourceKind) -> bool {
    matches!(
        kind,
        ResourceKind::Instance
            | ResourceKind::LambdaFunction
            | ResourceKind::EcsService
            | ResourceKind::EksNodeGroup
    )
}

/// The NAT gateways a subnet's default route goes through.
fn egress_nats(graph: &ResourceGraph, subnet: NodeIndex) -> Vec<NodeIndex> {
    graph
        .edges_directed(subnet, petgraph::Direction::Outgoing)
        .filter(|e| matches!(e.weight(), Dependency::Egress(_)))
        .map(|e| e.target())
        .collect()
}

/// A resource's Spread edges, grouped by `via`: one placement group each.
fn spread_groups(graph: &ResourceGraph, idx: NodeIndex) -> Vec<(&'static str, Vec<NodeIndex>)> {
    let mut groups: Vec<(&'static str, Vec<NodeIndex>)> = Vec::new();
    for e in graph.edges_directed(idx, petgraph::Direction::Outgoing) {
        if let Dependency::Spread(via) = e.weight() {
            match groups.iter_mut().find(|(v, _)| v == via) {
                Some((_, members)) => members.push(e.target()),
                None => groups.push((via, vec![e.target()])),
            }
        }
    }
    groups
}

/// The subnet nodes a resource is a `MemberOf` (an ALB's `subnets`, a Lambda's `subnet_ids`).
fn member_subnets(graph: &ResourceGraph, idx: NodeIndex) -> Vec<NodeIndex> {
    graph
        .edges_directed(idx, petgraph::Direction::Outgoing)
        .filter(|e| matches!(e.weight(), Dependency::MemberOf(_)))
        .map(|e| e.target())
        .filter(|t| graph[*t].kind == ResourceKind::Subnet)
        .collect()
}

/// Does this resource name `principal` in any of its principal-carrying attributes
/// ([`PRINCIPAL_ATTRS`])? A string match on the known value; in a plan, where the ARN is not known
/// yet, a match on the role its configuration references -- by the role's Terraform address, its
/// name, or an ARN ending in that name. Modelling IAM as graph nodes is future work.
pub(crate) fn names_principal(r: &Resource, principal: &str) -> bool {
    let role_name = principal
        .starts_with("arn:")
        .then(|| principal.rsplit('/').next())
        .flatten();
    PRINCIPAL_ATTRS
        .iter()
        .any(|key| r.attrs.get(key).and_then(|v| v.as_str()) == Some(principal))
        || r.pending_principals.iter().any(|p| {
            p.roles
                .iter()
                .any(|id| id == principal || Some(id.as_str()) == role_name)
        })
}

/// Why a NAT's death cannot be evaluated: subnets whose egress (route table, NAT) is unknown, and
/// compute whose subnets are unknown -- it may run in a subnet that routes through that NAT. The
/// second is WARDEN's Wave 4 plan: its Lambdas' `dynamic "vpc_config"` names no subnet, and a NAT
/// death reported the NAT alone, where the applied state loses three Lambdas with it.
pub(crate) fn egress_unknown(graph: &ResourceGraph) -> Vec<String> {
    graph
        .node_indices()
        .map(|i| &graph[i])
        .filter_map(|r| {
            r.unresolved
                .iter()
                .find(|w| {
                    w.starts_with("egress unknown")
                        || (is_compute(r.kind) && w.ends_with("names no subnet Helios can place"))
                })
                .map(|w| format!("{} ({w})", r.id))
        })
        .collect()
}

/// The resources whose principal cannot be compared with `principal` at all: unknown until apply,
/// through references Helios cannot follow. An iam-revocation that leaves any of these out is not
/// a pass -- it is inconclusive.
pub(crate) fn unevaluable_principals(graph: &ResourceGraph, principal: &str) -> Vec<String> {
    graph
        .node_indices()
        .map(|i| &graph[i])
        .filter(|r| !names_principal(r, principal))
        .filter(|r| {
            r.pending_principals
                .iter()
                .any(|p| p.roles.is_empty() || p.opaque)
        })
        .map(|r| r.id.clone())
        .collect()
}

/// No region: `region_for` returns this when a resource carries no region signal of its own.
const NO_REGION: &str = "\0none";

/// Every region the modelled resources THEMSELVES say they are in (never a fallback).
pub(crate) fn estate_regions(graph: &ResourceGraph) -> std::collections::BTreeSet<String> {
    graph
        .node_indices()
        .map(|i| region_for(&graph[i].attrs, NO_REGION))
        .filter(|r| r != NO_REGION)
        .collect()
}

/// The resources with no region signal of their own (they fall back to the majority region).
pub(crate) fn without_region(graph: &ResourceGraph) -> Vec<String> {
    graph
        .node_indices()
        .filter(|&i| region_for(&graph[i].attrs, NO_REGION) == NO_REGION)
        .map(|i| graph[i].id.clone())
        .collect()
}

/// Every zone a modelled resource declares (`availability_zone`, `availability_zones`).
pub(crate) fn estate_zones(graph: &ResourceGraph) -> std::collections::BTreeSet<String> {
    let mut zones = std::collections::BTreeSet::new();
    for i in graph.node_indices() {
        let attrs = &graph[i].attrs;
        if let Some(z) = attrs.get("availability_zone").and_then(|v| v.as_str()) {
            zones.insert(z.to_string());
        }
        if let Some(zs) = attrs.get("availability_zones").and_then(|v| v.as_array()) {
            zones.extend(zs.iter().filter_map(|z| z.as_str()).map(String::from));
        }
    }
    zones.retain(|z| !z.is_empty());
    zones
}

pub(crate) use helios_models::{well_formed_region, well_formed_zone};

/// The resources in `az`'s region whose zone cannot be modelled -- a guessed zone, or a
/// zone-deciding attribute that names nothing Helios can place -- each with why. An outage of
/// `az` says nothing trustworthy about them. A resource with no region signal of its own counts
/// as in `az`'s region unless the graph as a whole says where it is: when NOTHING declares a
/// region, a guess (us-east-1) must not decide that it is elsewhere.
pub(crate) fn unplaceable_in(graph: &ResourceGraph, az: &str) -> Vec<String> {
    let region = region_of_az(az);
    let fallback = graph_region(graph);
    let region_known = infer_region(graph.node_indices().map(|i| &graph[i].attrs)).is_some();
    graph
        .node_indices()
        .filter(|&i| match region_for(&graph[i].attrs, NO_REGION) {
            own if own == NO_REGION => !region_known || fallback == region,
            own => own == region,
        })
        .filter_map(|i| {
            let r = &graph[i];
            if !r.unresolved.is_empty() {
                Some(format!("{} ({})", r.id, r.unresolved.join("; ")))
            } else if zone_is_guessed(r.kind.tf_type(), &r.attrs) && !placed_by_subnet(graph, i) {
                Some(format!("{} (no availability_zone)", r.id))
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn z3_links_and_solves_trivial() {
        assert_eq!(solver_smoke(), SatResult::Sat);
    }
}

#[cfg(test)]
mod region_tests {
    use super::region_of_az;

    #[test]
    fn strips_az_suffix() {
        assert_eq!(region_of_az("us-east-1a"), "us-east-1");
        assert_eq!(region_of_az("eu-west-2c"), "eu-west-2");
    }

    #[test]
    fn leaves_region_only_alone() {
        assert_eq!(region_of_az("us-east-1"), "us-east-1");
    }
}

#[cfg(test)]
mod encode_tests {
    use super::*;
    use crate::{Scenario, ScenarioKind};
    use helios_graph::from_json;

    const FIXTURE: &str = include_str!("../../../fixtures/three-tier-webapp/terraform-show.json");

    fn build_graph() -> ResourceGraph {
        from_json(FIXTURE).expect("fixture parses")
    }

    #[test]
    fn single_az_ec2_is_down_when_its_az_is_down() {
        let graph = build_graph();
        let solver = Solver::new();
        let mut enc = Encoder::new();
        enc.encode_availability(&graph, &solver);

        let ec2_idx = graph
            .node_indices()
            .find(|i| graph[*i].id == "aws_instance.web")
            .expect("fixture contains aws_instance.web");
        let ec2_down = enc.resource_down[&ec2_idx].clone();

        solver.assert(enc.az_var("us-east-1a"));
        solver.assert(enc.region_var("us-east-1").not());
        enc.pin_everything_else(&solver, &["us-east-1a".into()], &[], &[]);

        assert_eq!(solver.check(), SatResult::Sat);
        let model = solver.get_model().unwrap();
        let ec2_val = model.eval(&ec2_down, true).unwrap().as_bool().unwrap();
        assert!(ec2_val, "EC2 in us-east-1a must be down when 1a is down");
    }

    #[test]
    fn subnet_down_propagates_to_ec2() {
        let graph = build_graph();
        let solver = Solver::new();
        let mut enc = Encoder::new();
        enc.encode_availability(&graph, &solver);
        enc.encode_dependencies(&graph, &solver);

        let ec2_idx = graph
            .node_indices()
            .find(|i| graph[*i].id == "aws_instance.web")
            .unwrap();
        let subnet_idx = graph
            .node_indices()
            .find(|i| graph[*i].id == "aws_subnet.public_a")
            .unwrap();

        let ec2_down = enc.resource_down[&ec2_idx].clone();
        let subnet_down = enc.resource_down[&subnet_idx].clone();

        solver.assert(&subnet_down);
        solver.assert(enc.region_var("us-east-1").not());

        assert_eq!(solver.check(), SatResult::Sat);
        let model = solver.get_model().unwrap();
        let ec2_val = model.eval(&ec2_down, true).unwrap().as_bool().unwrap();
        assert!(ec2_val, "EC2 must be down when its subnet is down");
    }

    #[test]
    fn regional_s3_unaffected_by_az_outage() {
        let graph = build_graph();
        let solver = Solver::new();
        let mut enc = Encoder::new();
        enc.encode_availability(&graph, &solver);

        let s3_idx = graph
            .node_indices()
            .find(|i| matches!(graph[*i].kind, helios_graph::ResourceKind::S3Bucket))
            .expect("fixture contains an S3 bucket");
        let s3_down = enc.resource_down[&s3_idx].clone();

        solver.assert(enc.az_var("us-east-1a"));
        solver.assert(enc.region_var("us-east-1").not());
        enc.pin_everything_else(&solver, &["us-east-1a".into()], &[], &[]);

        assert_eq!(solver.check(), SatResult::Sat);
        let model = solver.get_model().unwrap();
        let s3_val = model.eval(&s3_down, true).unwrap().as_bool().unwrap();
        assert!(!s3_val, "S3 must not be down from an AZ outage alone");
    }

    #[test]
    fn az_outage_takes_single_az_resources_down() {
        let graph = build_graph();
        let solver = Solver::new();
        let mut enc = Encoder::new();
        enc.encode_availability(&graph, &solver);
        enc.encode_dependencies(&graph, &solver);

        let scenario = Scenario {
            name: "lose-1a".into(),
            kind: ScenarioKind::AzOutage {
                az: "us-east-1a".into(),
            },
        };
        assert!(
            enc.apply_scenario(&scenario, &graph, &solver).is_none(),
            "scenario target must exist"
        );

        assert_eq!(solver.check(), SatResult::Sat);
        let chain = enc.extract_failures(&graph, &scenario, &solver);

        let ids: Vec<&str> = chain.failures.iter().map(|f| f.id.as_str()).collect();
        assert!(
            ids.contains(&"aws_subnet.public_a"),
            "subnet in 1a must fail"
        );
        assert!(ids.contains(&"aws_instance.web"), "ec2 in 1a must fail");
        assert!(
            !ids.contains(&"aws_subnet.public_b"),
            "subnet in 1b must survive"
        );
    }

    #[test]
    fn slow_rds_failover_forces_the_db_down() {
        let graph = build_graph();
        let solver = Solver::new();
        let mut enc = Encoder::new();
        enc.encode_availability(&graph, &solver);
        enc.encode_dependencies(&graph, &solver);

        let scenario = Scenario {
            name: "rds-slow".into(),
            kind: ScenarioKind::SlowRdsFailover {
                db_id: "aws_db_instance.primary".into(),
            },
        };
        assert!(
            enc.apply_scenario(&scenario, &graph, &solver).is_none(),
            "scenario target must exist"
        );

        assert_eq!(solver.check(), SatResult::Sat);
        let chain = enc.extract_failures(&graph, &scenario, &solver);
        assert!(
            chain
                .failures
                .iter()
                .any(|f| f.id == "aws_db_instance.primary"),
            "rds must be down; got {:?}",
            chain.failures
        );
    }

    #[test]
    fn single_nat_death_takes_subnet_and_children_down() {
        let graph = build_graph();
        let solver = Solver::new();
        let mut enc = Encoder::new();
        enc.encode_availability(&graph, &solver);
        enc.encode_dependencies(&graph, &solver);

        let scenario = Scenario {
            name: "nat-1a-dead".into(),
            kind: ScenarioKind::SingleNatDeath {
                subnet_id: "aws_subnet.public_a".into(),
            },
        };
        assert!(
            enc.apply_scenario(&scenario, &graph, &solver).is_none(),
            "scenario target must exist"
        );

        assert_eq!(solver.check(), SatResult::Sat);
        let chain = enc.extract_failures(&graph, &scenario, &solver);
        let ids: Vec<&str> = chain.failures.iter().map(|f| f.id.as_str()).collect();
        assert!(ids.contains(&"aws_subnet.public_a"));
        assert!(
            ids.contains(&"aws_instance.web"),
            "web depends on public_a; must fall; got {ids:?}"
        );
    }

    #[test]
    fn iam_revocation_hits_resources_with_matching_role_arn() {
        // Build a fixture graph, then inject an iam_role_arn into one node
        // to prove the string-match path. We roll a mini in-memory graph so
        // we don't need to touch the shipped fixture.
        let mut graph = build_graph();
        let role_arn = "arn:aws:iam::123:role/web";
        let web_idx = graph
            .node_indices()
            .find(|i| graph[*i].id == "aws_instance.web")
            .unwrap();
        graph[web_idx]
            .attrs
            .as_object_mut()
            .unwrap()
            .insert("iam_role_arn".into(), serde_json::json!(role_arn));

        let solver = Solver::new();
        let mut enc = Encoder::new();
        enc.encode_availability(&graph, &solver);
        enc.encode_dependencies(&graph, &solver);

        let scenario = Scenario {
            name: "revoke-web".into(),
            kind: ScenarioKind::IamRevocation {
                principal_arn: role_arn.into(),
            },
        };
        assert!(
            enc.apply_scenario(&scenario, &graph, &solver).is_none(),
            "scenario target must exist"
        );

        assert_eq!(solver.check(), SatResult::Sat);
        let chain = enc.extract_failures(&graph, &scenario, &solver);
        let ids: Vec<&str> = chain.failures.iter().map(|f| f.id.as_str()).collect();
        assert!(
            ids.contains(&"aws_instance.web"),
            "web should fail after its role is revoked; got {ids:?}"
        );
    }

    #[test]
    fn a_scenario_naming_a_resource_that_does_not_exist_is_not_a_silent_pass() {
        // This used to assert nothing and report "No failures — configuration is resilient", exit 0.
        // So a typo in `db_id`, or naming a resource kind Helios skips, read as a clean bill of
        // health. The fix path already errored on an unknown id; the scenario path did not, and that
        // asymmetry ran the wrong way.
        let graph = build_graph();
        let solver = Solver::new();
        let mut enc = Encoder::new();
        enc.encode_availability(&graph, &solver);
        enc.encode_dependencies(&graph, &solver);

        let missing = enc.apply_scenario(
            &Scenario {
                name: "typo".into(),
                kind: ScenarioKind::SlowRdsFailover {
                    db_id: "aws_db_instance.does_not_exist".into(),
                },
            },
            &graph,
            &solver,
        );
        assert_eq!(
            missing.as_deref(),
            Some("aws_db_instance.does_not_exist"),
            "an unknown scenario target must be reported, not silently ignored"
        );
    }

    #[test]
    fn a_non_default_region_estate_is_not_placed_in_us_east_1() {
        // Until 2026-09-06 every resource without an explicit `region` attribute was placed in the
        // hard-coded us-east-1, so a eu-west-2 estate SURVIVED a eu-west-2 outage and FELL with a
        // us-east-1 one. Both directions are wrong answers, and nothing warned.
        //
        // The three resources below cover the three ways a region has to be found: from an ARN,
        // from a declared zone, and — the Lambda — from nothing at all, which only the graph-wide
        // inference can resolve.
        const EU: &str = r#"{
          "format_version": "1.0",
          "terraform_version": "1.9.0",
          "values": { "root_module": { "resources": [
            { "address": "aws_db_instance.eu", "type": "aws_db_instance", "mode": "managed",
              "name": "eu",
              "values": { "id": "db-eu", "multi_az": true,
                          "arn": "arn:aws:rds:eu-west-2:123456789012:db:eu" } },
            { "address": "aws_subnet.eu_a", "type": "aws_subnet", "mode": "managed", "name": "eu_a",
              "values": { "id": "sn-eu-a", "availability_zone": "eu-west-2a" } },
            { "address": "aws_lambda_function.eu", "type": "aws_lambda_function",
              "mode": "managed", "name": "eu", "values": { "id": "fn-eu" } }
          ] } }
        }"#;

        let graph = from_json(EU).expect("fixture parses");

        // Losing eu-west-2 must take all three down.
        let solver = Solver::new();
        let mut enc = Encoder::new();
        enc.encode_availability(&graph, &solver);
        enc.encode_dependencies(&graph, &solver);
        let eu = Scenario {
            name: "lose-eu-west-2".into(),
            kind: ScenarioKind::RegionOutage {
                region: "eu-west-2".into(),
            },
        };
        assert!(
            enc.apply_scenario(&eu, &graph, &solver).is_none(),
            "scenario target must exist"
        );
        assert_eq!(solver.check(), SatResult::Sat);
        let ids: Vec<String> = enc
            .extract_failures(&graph, &eu, &solver)
            .failures
            .iter()
            .map(|f| f.id.clone())
            .collect();
        assert_eq!(
            ids.len(),
            3,
            "a eu-west-2 outage must take the whole eu-west-2 estate down; got {ids:?}"
        );

        // And losing us-east-1 must take NOTHING down.
        let solver2 = Solver::new();
        let mut enc2 = Encoder::new();
        enc2.encode_availability(&graph, &solver2);
        enc2.encode_dependencies(&graph, &solver2);
        let us = Scenario {
            name: "lose-us-east-1".into(),
            kind: ScenarioKind::RegionOutage {
                region: "us-east-1".into(),
            },
        };
        assert!(
            enc2.apply_scenario(&us, &graph, &solver2).is_none(),
            "scenario target must exist"
        );
        assert_eq!(solver2.check(), SatResult::Sat);
        let untouched = enc2.extract_failures(&graph, &us, &solver2).failures;
        assert!(
            untouched.is_empty(),
            "a us-east-1 outage must not touch a eu-west-2 estate; got {:?}",
            untouched.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_multi_az_resource_with_no_zones_is_not_vacuously_down() {
        // `Bool::and(&[])` is Z3's empty conjunction and evaluates to TRUE, so a multi-AZ resource
        // whose `availability_zones` attribute is absent used to encode "all of its zones are
        // down" as a tautology -- reported down in EVERY scenario, including one naming a zone
        // nothing lives in. An unknown AZ set must contribute nothing; the resource still falls
        // with its region.
        const NO_ZONES: &str = r#"{
          "format_version": "1.0",
          "terraform_version": "1.9.0",
          "values": { "root_module": { "resources": [
            { "address": "aws_lb.naked", "type": "aws_lb", "mode": "managed", "name": "naked",
              "values": { "id": "lb-1" } },
            { "address": "aws_subnet.real", "type": "aws_subnet", "mode": "managed", "name": "real",
              "values": { "id": "subnet-real", "availability_zone": "us-east-1a" } }
          ] } }
        }"#;

        let graph = from_json(NO_ZONES).expect("fixture parses");
        let solver = Solver::new();
        let mut enc = Encoder::new();
        enc.encode_availability(&graph, &solver);
        enc.encode_dependencies(&graph, &solver);

        let scenario = Scenario {
            name: "lose-us-east-1a".into(),
            kind: ScenarioKind::AzOutage {
                az: "us-east-1a".into(),
            },
        };
        assert!(
            enc.apply_scenario(&scenario, &graph, &solver).is_none(),
            "scenario target must exist"
        );

        assert_eq!(solver.check(), SatResult::Sat);
        let chain = enc.extract_failures(&graph, &scenario, &solver);
        let ids: Vec<&str> = chain.failures.iter().map(|f| f.id.as_str()).collect();
        assert!(
            !ids.contains(&"aws_lb.naked"),
            "an ALB with no declared zones must not fail an AZ outage; got {ids:?}"
        );
        assert!(
            ids.contains(&"aws_subnet.real"),
            "the subnet actually in the dead zone must still fail; got {ids:?}"
        );
    }

    #[test]
    fn a_data_source_is_not_infrastructure_that_can_fail() {
        // A data source describes infrastructure Terraform does not own, so it cannot fail.
        // `RawResource` did not read `mode`, so `data.aws_subnet.selected` was ingested as a
        // subnet and reported as a failed service -- a false positive.
        const WITH_DATA_SOURCE: &str = r#"{
          "format_version": "1.0",
          "terraform_version": "1.9.0",
          "values": { "root_module": { "resources": [
            { "address": "data.aws_subnet.selected", "type": "aws_subnet", "mode": "data",
              "name": "selected",
              "values": { "id": "subnet-data", "availability_zone": "us-east-1a" } },
            { "address": "aws_subnet.real", "type": "aws_subnet", "mode": "managed", "name": "real",
              "values": { "id": "subnet-real", "availability_zone": "us-east-1a" } }
          ] } }
        }"#;

        let graph = from_json(WITH_DATA_SOURCE).expect("fixture parses");
        let ids: Vec<&str> = graph.node_indices().map(|i| graph[i].id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["aws_subnet.real"],
            "only the managed subnet belongs in the graph; got {ids:?}"
        );
    }

    #[test]
    fn az_outage_pins_the_other_zone_up_not_by_default() {
        // v0.1.0 never constrained az_down_us-east-1b; the other zone's survival was Z3's
        // default assignment for a free Boolean, not a property of the encoding.
        let graph = build_graph();
        let solver = Solver::new();
        let mut enc = Encoder::new();
        enc.encode_availability(&graph, &solver);
        enc.encode_dependencies(&graph, &solver);
        assert!(
            enc.apply_scenario(
                &Scenario {
                    name: "lose-1a".into(),
                    kind: ScenarioKind::AzOutage {
                        az: "us-east-1a".into(),
                    },
                },
                &graph,
                &solver,
            )
            .is_none(),
            "scenario target must exist"
        );
        assert_eq!(solver.check(), SatResult::Sat);
        let model = solver.get_model().unwrap();
        let b_down = model
            .eval(&enc.az_down["us-east-1b"], true)
            .unwrap()
            .as_bool()
            .unwrap();
        assert!(!b_down, "us-east-1b must be pinned UP by the encoding");
        // And the solver cannot choose otherwise: asserting it down must be UNSAT.
        solver.assert(&enc.az_down["us-east-1b"]);
        assert_eq!(solver.check(), SatResult::Unsat);
    }

    #[test]
    fn single_nat_death_does_not_take_the_zone_down() {
        // v0.1.0 forced the subnet down THROUGH its availability rule, so Z3 took the whole
        // AZ down and the unrelated cache (no edge to the subnet) fell with it.
        let graph = build_graph();
        let solver = Solver::new();
        let mut enc = Encoder::new();
        enc.encode_availability(&graph, &solver);
        enc.encode_dependencies(&graph, &solver);
        let scenario = Scenario {
            name: "nat-1a-dead".into(),
            kind: ScenarioKind::SingleNatDeath {
                subnet_id: "aws_subnet.public_a".into(),
            },
        };
        assert!(
            enc.apply_scenario(&scenario, &graph, &solver).is_none(),
            "scenario target must exist"
        );
        assert_eq!(solver.check(), SatResult::Sat);
        let chain = enc.extract_failures(&graph, &scenario, &solver);
        let ids: Vec<&str> = chain.failures.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(
            ids,
            vec!["aws_instance.web", "aws_subnet.public_a"],
            "only the subnet and what it CONTAINS may fall; got {ids:?}"
        );
    }

    #[test]
    fn slow_rds_failover_fails_only_the_database() {
        // v0.1.0 forced the multi-AZ DB down through `(a ∧ b) ∨ region`, so Z3 took BOTH zones
        // down and the ALB and both subnets fell — six failures for one slow failover.
        let graph = build_graph();
        let solver = Solver::new();
        let mut enc = Encoder::new();
        enc.encode_availability(&graph, &solver);
        enc.encode_dependencies(&graph, &solver);
        let scenario = Scenario {
            name: "rds-slow".into(),
            kind: ScenarioKind::SlowRdsFailover {
                db_id: "aws_db_instance.primary".into(),
            },
        };
        assert!(
            enc.apply_scenario(&scenario, &graph, &solver).is_none(),
            "scenario target must exist"
        );
        assert_eq!(solver.check(), SatResult::Sat);
        let chain = enc.extract_failures(&graph, &scenario, &solver);
        let ids: Vec<&str> = chain.failures.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, vec!["aws_db_instance.primary"], "got {ids:?}");
    }

    #[test]
    fn iam_revocation_reads_the_lambda_role_attribute() {
        // The shipped fixture's Lambda carries its principal under `role`, which v0.1.0 never
        // read — so the bundled iam-revocation scenario reported "resilient" for the wrong reason.
        let graph = build_graph();
        let solver = Solver::new();
        let mut enc = Encoder::new();
        enc.encode_availability(&graph, &solver);
        enc.encode_dependencies(&graph, &solver);
        let scenario = Scenario {
            name: "revoke-lambda-role".into(),
            kind: ScenarioKind::IamRevocation {
                principal_arn: "arn:aws:iam::123456789012:role/lambda-worker".into(),
            },
        };
        assert!(
            enc.apply_scenario(&scenario, &graph, &solver).is_none(),
            "scenario target must exist"
        );
        assert_eq!(solver.check(), SatResult::Sat);
        let chain = enc.extract_failures(&graph, &scenario, &solver);
        let ids: Vec<&str> = chain.failures.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, vec!["aws_lambda_function.worker"], "got {ids:?}");
        assert!(chain.failures[0].reason.contains("was revoked"));
    }

    #[test]
    fn region_outage_takes_everything_down_except_global() {
        let graph = build_graph();
        let solver = Solver::new();
        let mut enc = Encoder::new();
        enc.encode_availability(&graph, &solver);
        enc.encode_dependencies(&graph, &solver);

        let scenario = Scenario {
            name: "lose-useast1".into(),
            kind: ScenarioKind::RegionOutage {
                region: "us-east-1".into(),
            },
        };
        assert!(
            enc.apply_scenario(&scenario, &graph, &solver).is_none(),
            "scenario target must exist"
        );

        assert_eq!(solver.check(), SatResult::Sat);
        let chain = enc.extract_failures(&graph, &scenario, &solver);

        assert!(
            chain.failures.len() >= graph.node_count() - 1,
            "at least all non-edge resources must fail"
        );
    }
}
