//! End-to-end: load the real fixture + real scenario files from disk, run simulate().

use helios_engine::{scenario, simulate, ScenarioKind};
use helios_graph::load as load_graph;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn three_tier_webapp_az_outage_e2e() {
    let root = repo_root();
    let graph = load_graph(root.join("fixtures/three-tier-webapp")).unwrap();
    let sc = scenario::load(&root.join("fixtures/scenarios/az-outage.yaml")).unwrap();
    assert!(matches!(sc.kind, ScenarioKind::AzOutage { .. }));

    let chain = simulate(&graph, &sc).unwrap();
    assert!(
        !chain.is_safe(),
        "AZ-1a outage must fail at least one resource"
    );

    let ids: Vec<&str> = chain.failures.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"aws_subnet.public_a"));
    assert!(ids.contains(&"aws_instance.web"));
    assert!(!ids.contains(&"aws_subnet.public_b"));
}

#[test]
fn three_tier_webapp_region_outage_e2e() {
    let root = repo_root();
    let graph = load_graph(root.join("fixtures/three-tier-webapp")).unwrap();
    let sc = scenario::load(&root.join("fixtures/scenarios/region-outage.yaml")).unwrap();

    let chain = simulate(&graph, &sc).unwrap();
    assert!(chain.failures.len() >= graph.node_count() - 1);
}
