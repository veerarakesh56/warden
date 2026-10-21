//! Top-level entry point the CLI uses.

use helios_graph::ResourceGraph;
use thiserror::Error;
use z3::{SatResult, Solver};

use crate::report::FailureChain;
use crate::scenario::Scenario;
use crate::smt::Encoder;

#[derive(Debug, Error)]
pub enum SimulateError {
    #[error("solver returned unsat — this should not happen for a well-formed scenario")]
    Unsat,
    #[error("solver returned unknown — Z3 timed out or hit a resource limit")]
    Unknown,
    /// The scenario named a resource the graph does not contain. Silently ignoring this used to
    /// report "no failures", i.e. a typo read as a clean bill of health.
    #[error(
        "scenario names '{0}', which is not in the graph — check the id, or it may be a resource kind Helios does not model (those are skipped with a warning)"
    )]
    UnknownTarget(String),
    /// The scenario cannot be evaluated against this graph. NOT a pass: reporting "no failures"
    /// here would be the same silent pass as an unknown target.
    #[error("INCONCLUSIVE (not a pass): {0}")]
    Inconclusive(String),
    /// An iam-revocation whose principal no resource uses. Revoking it touches nothing, which is
    /// far more likely a typo than a finding -- and "no failures" would read as a pass.
    #[error(
        "no resource in the graph uses principal '{0}' (checked iam_role_arn, role_arn, role, node_role_arn) — check the ARN; a revocation that touches nothing is not a pass"
    )]
    UnknownPrincipal(String),
    /// A zone or region outage aimed where nothing modelled lives: "no failures" would be a pass
    /// for an estate the scenario never touched (a us-east-1 scenario against an ap-south-2 plan).
    #[error("scenario targets region {region}; the modelled estate is in {estate} — check the zone or region name")]
    UnknownRegion { region: String, estate: String },
    /// A zone name that is not `<region><letter>` (`eu-west-2a`), or a region name that is not
    /// `<area>-<name>-<number>`.
    #[error("'{0}' is not a well-formed {1} name (a zone is `<region><letter>`, e.g. eu-west-2a; a region is e.g. eu-west-2)")]
    Malformed(String, &'static str),
}

/// A zone or region outage must name a region the estate is in. `Ok(false)`: nothing declares a
/// region at all, so whether `region` is the estate's cannot be told.
fn check_region(graph: &ResourceGraph, region: &str) -> Result<bool, SimulateError> {
    let estate = crate::smt::estate_regions(graph);
    if estate.is_empty() {
        tracing::warn!(
            "NO RESOURCE DECLARES A REGION (no zone, no ARN, no `region`): Helios cannot tell \
             whether {region} is where this estate is; resources it cannot place make the \
             result inconclusive"
        );
        return Ok(false);
    }
    if !estate.contains(region) {
        return Err(SimulateError::UnknownRegion {
            region: region.to_string(),
            estate: estate.into_iter().collect::<Vec<_>>().join(", "),
        });
    }
    Ok(true)
}

/// Run one scenario against one graph. Returns the failure chain.
pub fn simulate(graph: &ResourceGraph, scenario: &Scenario) -> Result<FailureChain, SimulateError> {
    if let crate::ScenarioKind::IamRevocation { principal_arn } = &scenario.kind {
        let unknown = crate::smt::unevaluable_principals(graph, principal_arn);
        if !unknown.is_empty() {
            return Err(SimulateError::Inconclusive(format!(
                "cannot tell whether these resources use {principal_arn}: {} -- their \
                 principal is unknown until apply and their configuration references something \
                 Helios cannot follow (a variable, local, module output or data source). Simulate \
                 the applied state instead.",
                unknown.join(", ")
            )));
        }
        if !graph
            .node_indices()
            .any(|i| crate::smt::names_principal(&graph[i], principal_arn))
        {
            return Err(SimulateError::UnknownPrincipal(principal_arn.clone()));
        }
    }
    if let crate::ScenarioKind::RegionOutage { region } = &scenario.kind {
        if !crate::smt::well_formed_region(region) {
            return Err(SimulateError::Malformed(region.clone(), "region"));
        }
        let unplaced = crate::smt::without_region(graph);
        if crate::smt::estate_regions(graph).len() > 1 && !unplaced.is_empty() {
            return Err(SimulateError::Inconclusive(format!(
                "this estate spans several regions, and nothing says which one {} is in",
                unplaced.join(", ")
            )));
        }
        if !check_region(graph, region)? {
            return Err(SimulateError::Inconclusive(format!(
                "no resource declares a region (no zone, ARN or `region` attribute), so whether \
                 {region} is this estate's region cannot be told"
            )));
        }
    }
    // Forcing down a NAT, or a subnet a NAT lives in, takes the egress of whatever routes through
    // that NAT -- which cannot be told while some compute subnet's route table is unknown.
    let forced = match &scenario.kind {
        crate::ScenarioKind::SingleNatDeath { subnet_id: id }
        | crate::ScenarioKind::ResourceLoss { resource_id: id }
        | crate::ScenarioKind::SlowRdsFailover { db_id: id } => Some(id),
        _ => None,
    };
    if let Some(id) = forced {
        use helios_graph::ResourceKind::{NatGateway, Subnet};
        let hosts_nat = graph.node_indices().any(|i| {
            &graph[i].id == id
                && (graph[i].kind == NatGateway
                    || (graph[i].kind == Subnet
                        && graph
                            .neighbors_directed(i, petgraph::Direction::Incoming)
                            .any(|n| graph[n].kind == NatGateway)))
        });
        let unknown = crate::smt::egress_unknown(graph);
        if hosts_nat && !unknown.is_empty() {
            return Err(SimulateError::Inconclusive(format!(
                "cannot tell what would lose egress with {id}: {}",
                unknown.join(", ")
            )));
        }
    }
    if let crate::ScenarioKind::AzOutage { az } = &scenario.kind {
        if !crate::smt::well_formed_zone(az) {
            return Err(SimulateError::Malformed(az.clone(), "zone"));
        }
        check_region(graph, &crate::smt::region_of_az(az))?;
        let zones = crate::smt::estate_zones(graph);
        if !zones.contains(az) {
            tracing::warn!(
                "nothing Helios models declares zone {az} (zones in the estate: {}): a zone \
                 with nothing in it is resilient by definition -- check the name",
                zones.into_iter().collect::<Vec<_>>().join(", ")
            );
        }
        let unsure = crate::smt::unplaceable_in(graph, az);
        if !unsure.is_empty() {
            return Err(SimulateError::Inconclusive(format!(
                "cannot tell what losing {az} takes down: the zone of {} cannot be modelled. \
                 Declare it, or simulate the applied state.",
                unsure.join(", ")
            )));
        }
    }
    let solver = Solver::new();
    let mut enc = Encoder::new();
    enc.encode_availability(graph, &solver);
    enc.encode_dependencies(graph, &solver);
    if let Some(missing) = enc.apply_scenario(scenario, graph, &solver) {
        return Err(SimulateError::UnknownTarget(missing));
    }

    match solver.check() {
        SatResult::Sat => Ok(enc.extract_failures(graph, scenario, &solver)),
        SatResult::Unsat => Err(SimulateError::Unsat),
        SatResult::Unknown => Err(SimulateError::Unknown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Scenario, ScenarioKind};
    use helios_graph::from_json;

    const FIXTURE: &str = include_str!("../../../fixtures/three-tier-webapp/terraform-show.json");

    #[test]
    fn simulate_az_outage_returns_failure_chain() {
        let graph = from_json(FIXTURE).unwrap();
        let scenario = Scenario {
            name: "lose-us-east-1a".into(),
            kind: ScenarioKind::AzOutage {
                az: "us-east-1a".into(),
            },
        };
        let chain = simulate(&graph, &scenario).unwrap();
        assert!(!chain.is_safe());
        assert_eq!(chain.scenario, "lose-us-east-1a");
    }
}
