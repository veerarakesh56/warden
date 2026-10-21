//! `verify` applies a fix to a clone of the graph and re-runs [`crate::simulate()`] for EVERY
//! scenario: the ones the caller supplies, plus the standard set derived from the graph
//! ([`standard_scenarios`]: every zone, every region, every NAT gateway). A fix that clears its
//! own scenario by moving the damage into another zone is a regression, not a resolution.
//! Used by the `helios verify` CLI command.

use std::collections::BTreeSet;

use helios_graph::ResourceGraph;
use serde::Serialize;
use thiserror::Error;

use crate::{
    apply_fix, simulate, FailureChain, FixError, FixProposal, Scenario, ScenarioKind, SimulateError,
};

/// One scenario simulated before and after the fix.
#[derive(Debug, Clone, Serialize)]
pub struct ScenarioDiff {
    pub scenario: String,
    /// The scenario the fix names (`FixProposal::scenario_name`).
    pub target: bool,
    /// `None` when the scenario is inconclusive on that side (see `inconclusive`).
    pub pre_fix: Option<FailureChain>,
    pub post_fix: Option<FailureChain>,
    /// Why the before/after cannot be compared: Helios cannot evaluate the scenario. Not a pass.
    pub inconclusive: Option<String>,
    /// Resource ids that failed pre-fix but survive post-fix.
    pub resolved: Vec<String>,
    /// Resource ids that the fix newly broke.
    pub new_failures: Vec<String>,
    /// Resource ids that still fail after the fix.
    pub remaining: Vec<String>,
}

/// What [`verify`] reports: one [`ScenarioDiff`] per scenario, the target first.
#[derive(Debug, Clone, Serialize)]
pub struct VerifyReport {
    pub scenarios: Vec<ScenarioDiff>,
}

/// The overall outcome, worst first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Some scenario fails somewhere it did not before.
    NewFailures,
    /// The target scenario still has failures.
    StillFailing,
    /// Some scenario could not be evaluated: the fix cannot be shown not to break it.
    Inconclusive,
    /// The target is clean, nothing new fails anywhere, every scenario was evaluated.
    Resolved,
}

impl VerifyReport {
    /// The scenario the fix names.
    pub fn target(&self) -> &ScenarioDiff {
        &self.scenarios[0]
    }

    pub fn verdict(&self) -> Verdict {
        if self.scenarios.iter().any(|s| !s.new_failures.is_empty()) {
            Verdict::NewFailures
        } else if !self.target().remaining.is_empty() {
            Verdict::StillFailing
        } else if self.scenarios.iter().any(|s| s.inconclusive.is_some()) {
            Verdict::Inconclusive
        } else {
            Verdict::Resolved
        }
    }

    /// `true` iff the target is clean and no scenario got worse or went unevaluated.
    pub fn is_safe(&self) -> bool {
        self.verdict() == Verdict::Resolved
    }
}

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("apply fix: {0}")]
    Apply(#[from] FixError),
    #[error("simulate: {0}")]
    Simulate(#[from] SimulateError),
    /// A fix is for one scenario. Verifying it against another would "resolve" a chain it was
    /// never written for.
    #[error(
        "the fix is for scenario {fix:?}, but the scenarios given are named {given:?} -- pass the \
         scenario the fix was proposed for"
    )]
    ScenarioMismatch { fix: String, given: Vec<String> },
    /// Two supplied scenarios with one name: which one the fix is for cannot be told, and the
    /// report would show two scenarios under one label.
    #[error("two scenarios given are both named {0:?} -- scenario names must be unique")]
    DuplicateScenario(String),
}

/// The scenarios every fix is checked against, from what the graphs (before and after the fix)
/// declare: an `az-outage` per zone, a `region-outage` per region, a `single-nat-death` per NAT
/// gateway. Names are `<kind> <target>`.
pub fn standard_scenarios(graphs: &[&ResourceGraph]) -> Vec<Scenario> {
    let mut zones = BTreeSet::new();
    let mut regions = BTreeSet::new();
    let mut nats = BTreeSet::new();
    for g in graphs {
        zones.extend(crate::smt::estate_zones(g));
        regions.extend(crate::smt::estate_regions(g));
        nats.extend(
            g.node_indices()
                .filter(|&i| g[i].kind == helios_graph::ResourceKind::NatGateway)
                .map(|i| g[i].id.clone()),
        );
    }
    let zones = zones
        .into_iter()
        .filter(|z| crate::smt::well_formed_zone(z))
        .map(|az| ("az-outage", az.clone(), ScenarioKind::AzOutage { az }));
    let regions = regions
        .into_iter()
        .filter(|r| crate::smt::well_formed_region(r))
        .map(|region| {
            let kind = ScenarioKind::RegionOutage {
                region: region.clone(),
            };
            ("region-outage", region, kind)
        });
    let nats = nats.into_iter().map(|id| {
        let kind = ScenarioKind::SingleNatDeath {
            subnet_id: id.clone(),
        };
        ("single-nat-death", id, kind)
    });
    zones
        .chain(regions)
        .chain(nats)
        .map(|(label, what, kind)| Scenario {
            name: format!("{label} {what}"),
            kind,
        })
        .collect()
}

/// An inconclusive side is recorded, not fatal (the target's is: the caller asked about it).
fn run(graph: &ResourceGraph, s: &Scenario) -> Result<Result<FailureChain, String>, SimulateError> {
    match simulate(graph, s) {
        Ok(chain) => Ok(Ok(chain)),
        Err(SimulateError::Inconclusive(why)) => Ok(Err(why)),
        Err(e) => Err(e),
    }
}

fn ids(chain: &FailureChain) -> BTreeSet<String> {
    chain.failures.iter().map(|f| f.id.clone()).collect()
}

/// Apply `fix` to a clone of `graph`, then simulate every scenario in `scenarios` plus
/// [`standard_scenarios`] (one of the same kind as a given scenario is not run twice) before and
/// after, and diff each. The fix's `scenario_name` must name one of `scenarios`: that is the
/// target, and it is first in the report. An inconclusive target is an error
/// ([`SimulateError::Inconclusive`]); any other inconclusive scenario is recorded in its diff.
pub fn verify(
    graph: &ResourceGraph,
    scenarios: &[Scenario],
    fix: &FixProposal,
) -> Result<VerifyReport, VerifyError> {
    let mut names = BTreeSet::new();
    if let Some(dup) = scenarios.iter().find(|s| !names.insert(s.name.as_str())) {
        return Err(VerifyError::DuplicateScenario(dup.name.clone()));
    }
    let Some(target) = scenarios.iter().find(|s| s.name == fix.scenario_name) else {
        return Err(VerifyError::ScenarioMismatch {
            fix: fix.scenario_name.clone(),
            given: scenarios.iter().map(|s| s.name.clone()).collect(),
        });
    };
    let patched = apply_fix(graph, fix)?;

    let mut all: Vec<Scenario> = vec![target.clone()];
    for s in scenarios
        .iter()
        .cloned()
        .chain(standard_scenarios(&[graph, &patched]))
    {
        if !all.iter().any(|a| a.kind == s.kind) {
            all.push(s);
        }
    }

    let mut out = Vec::with_capacity(all.len());
    for (i, s) in all.iter().enumerate() {
        let is_target = i == 0;
        let (pre, post) = if is_target {
            (Ok(simulate(graph, s)?), Ok(simulate(&patched, s)?))
        } else {
            (run(graph, s)?, run(&patched, s)?)
        };
        let mut diff = ScenarioDiff {
            scenario: s.name.clone(),
            target: is_target,
            pre_fix: None,
            post_fix: None,
            inconclusive: None,
            resolved: vec![],
            new_failures: vec![],
            remaining: vec![],
        };
        match (pre, post) {
            (Ok(pre), Ok(post)) => {
                let (a, b) = (ids(&pre), ids(&post));
                diff.resolved = a.difference(&b).cloned().collect();
                diff.new_failures = b.difference(&a).cloned().collect();
                diff.remaining = a.intersection(&b).cloned().collect();
                diff.pre_fix = Some(pre);
                diff.post_fix = Some(post);
            }
            (pre, post) => {
                let side = |r: &Result<FailureChain, String>, when: &str| {
                    r.as_ref().err().map(|why| format!("{when} the fix: {why}"))
                };
                diff.inconclusive = side(&pre, "before")
                    .into_iter()
                    .chain(side(&post, "after"))
                    .reduce(|a, b| format!("{a}; {b}"));
                diff.pre_fix = pre.ok();
                diff.post_fix = post.ok();
            }
        }
        out.push(diff);
    }
    Ok(VerifyReport { scenarios: out })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FixEdit, FixProposal, ScenarioKind};
    use helios_graph::from_json;

    const FIXTURE: &str = include_str!("../../../fixtures/three-tier-webapp/terraform-show.json");

    fn az_1a_scenario() -> Scenario {
        Scenario {
            name: "lose-us-east-1a".into(),
            kind: ScenarioKind::AzOutage {
                az: "us-east-1a".into(),
            },
        }
    }

    fn set_az(id: &str, az: &str) -> FixEdit {
        FixEdit::SetAttr {
            resource_id: id.into(),
            key: "availability_zone".into(),
            value: serde_json::json!(az),
        }
    }

    fn diff<'a>(report: &'a VerifyReport, name: &str) -> &'a ScenarioDiff {
        report
            .scenarios
            .iter()
            .find(|s| s.scenario == name)
            .unwrap_or_else(|| panic!("{name} not checked: {report:?}"))
    }

    #[test]
    fn verify_moves_elasticache_out_of_failing_az() {
        // Pre-fix: az-outage 1a kills subnet.public_a, instance.web, elasticache.cache.
        // Fix: move elasticache to 1b. Post-fix: elasticache is resolved; subnet+instance remain.
        // It now dies with 1b instead, and verify says so.
        let graph = from_json(FIXTURE).unwrap();
        let scenario = az_1a_scenario();
        let fix = FixProposal {
            scenario_name: scenario.name.clone(),
            explanation: "move cache to 1b".into(),
            edits: vec![set_az("aws_elasticache_cluster.cache", "us-east-1b")],
        };

        let report = verify(&graph, &[scenario], &fix).unwrap();
        let t = report.target();
        assert!(t.target && t.scenario == "lose-us-east-1a");
        assert_eq!(t.resolved, vec!["aws_elasticache_cluster.cache"]);
        assert!(t.new_failures.is_empty(), "{t:?}");
        assert!(t.remaining.contains(&"aws_subnet.public_a".to_string()));
        assert_eq!(
            diff(&report, "az-outage us-east-1b").new_failures,
            vec!["aws_elasticache_cluster.cache"]
        );
        assert_eq!(report.verdict(), Verdict::NewFailures);
    }

    /// The shipped `fixes/az-outage.json` moves every 1a resource to 1b. Against its own scenario
    /// it "resolves" all three; under a 1b outage it takes five resources down instead of one.
    #[test]
    fn the_shipped_az_outage_fix_is_a_regression_in_the_other_zone() {
        let graph = from_json(FIXTURE).unwrap();
        let fix: FixProposal =
            serde_json::from_str(include_str!("../../../fixes/az-outage.json")).unwrap();
        let report = verify(&graph, &[az_1a_scenario()], &fix).unwrap();

        let t = report.target();
        assert_eq!(t.resolved.len(), 3, "{t:?}");
        assert!(t.post_fix.as_ref().unwrap().is_safe());
        let b = diff(&report, "az-outage us-east-1b");
        assert_eq!(b.pre_fix.as_ref().unwrap().failures.len(), 1);
        assert_eq!(b.post_fix.as_ref().unwrap().failures.len(), 5);
        assert_eq!(b.new_failures.len(), 4, "{b:?}");
        diff(&report, "region-outage us-east-1");
        assert_eq!(report.verdict(), Verdict::NewFailures);
        assert!(!report.is_safe());
    }

    #[test]
    fn a_fix_for_another_scenario_is_rejected() {
        let graph = from_json(FIXTURE).unwrap();
        let fix = FixProposal {
            scenario_name: "something-else".into(),
            explanation: "x".into(),
            edits: vec![set_az("aws_elasticache_cluster.cache", "us-east-1b")],
        };
        match verify(&graph, &[az_1a_scenario()], &fix) {
            Err(VerifyError::ScenarioMismatch { fix, given }) => {
                assert_eq!(fix, "something-else");
                assert_eq!(given, vec!["lose-us-east-1a"]);
            }
            other => panic!("expected ScenarioMismatch, got {other:?}"),
        }
    }

    #[test]
    fn two_scenarios_with_one_name_are_rejected() {
        let graph = from_json(FIXTURE).unwrap();
        let other_kind = Scenario {
            name: "lose-us-east-1a".into(),
            kind: ScenarioKind::RegionOutage {
                region: "us-east-1".into(),
            },
        };
        let fix = FixProposal {
            scenario_name: "lose-us-east-1a".into(),
            explanation: "x".into(),
            edits: vec![set_az("aws_elasticache_cluster.cache", "us-east-1b")],
        };
        match verify(&graph, &[az_1a_scenario(), other_kind], &fix) {
            Err(VerifyError::DuplicateScenario(name)) => assert_eq!(name, "lose-us-east-1a"),
            other => panic!("expected DuplicateScenario, got {other:?}"),
        }
    }

    #[test]
    fn standard_scenarios_cover_every_zone_and_region_once() {
        let graph = from_json(FIXTURE).unwrap();
        let names: Vec<String> = standard_scenarios(&[&graph, &graph])
            .into_iter()
            .map(|s| s.name)
            .collect();
        assert_eq!(
            names,
            [
                "az-outage us-east-1a",
                "az-outage us-east-1b",
                "region-outage us-east-1"
            ]
        );
    }

    #[test]
    fn verify_noop_fix_preserves_failures() {
        // Setting an irrelevant attr doesn't change the simulation outcome anywhere.
        let graph = from_json(FIXTURE).unwrap();
        let scenario = az_1a_scenario();
        let fix = FixProposal {
            scenario_name: scenario.name.clone(),
            explanation: "cosmetic".into(),
            edits: vec![FixEdit::SetAttr {
                resource_id: "aws_s3_bucket.assets".into(),
                key: "versioning_enabled".into(),
                value: serde_json::json!(true),
            }],
        };

        let report = verify(&graph, &[scenario], &fix).unwrap();
        for s in &report.scenarios {
            assert_eq!(s.resolved, Vec::<String>::new(), "{}", s.scenario);
            assert_eq!(s.new_failures, Vec::<String>::new(), "{}", s.scenario);
        }
        assert_eq!(report.verdict(), Verdict::StillFailing);
    }

    #[test]
    fn verify_propagates_unknown_resource_error_from_apply() {
        let graph = from_json(FIXTURE).unwrap();
        let scenario = az_1a_scenario();
        let fix = FixProposal {
            scenario_name: scenario.name.clone(),
            explanation: "bad".into(),
            edits: vec![FixEdit::SetAttr {
                resource_id: "aws_nope.ghost".into(),
                key: "foo".into(),
                value: serde_json::json!(1),
            }],
        };
        assert!(matches!(
            verify(&graph, &[scenario], &fix),
            Err(VerifyError::Apply(FixError::UnknownResource(_)))
        ));
    }
}
