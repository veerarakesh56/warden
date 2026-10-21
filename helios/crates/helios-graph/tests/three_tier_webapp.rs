//! End-to-end fixture test: load the three-tier webapp terraform-show.json
//! and verify the exact graph shape helios-graph v0.1 produces.

use std::collections::HashSet;

use helios_graph::{Dependency, ResourceKind};

const FIXTURE: &str = include_str!("../../../fixtures/three-tier-webapp/terraform-show.json");

#[test]
fn loads_eight_resource_kinds() {
    let graph = helios_graph::from_json(FIXTURE).expect("fixture parses");
    assert_eq!(
        graph.node_count(),
        9,
        "expected 9 resources (vpc, 2 subnets, ec2, alb, rds, elasticache, lambda, s3)"
    );

    let kinds: HashSet<ResourceKind> = graph.node_indices().map(|i| graph[i].kind).collect();
    let expected: HashSet<ResourceKind> = [
        ResourceKind::Vpc,
        ResourceKind::Subnet,
        ResourceKind::Instance,
        ResourceKind::Lb,
        ResourceKind::DbInstance,
        ResourceKind::ElasticacheCluster,
        ResourceKind::LambdaFunction,
        ResourceKind::S3Bucket,
    ]
    .into_iter()
    .collect();
    assert_eq!(kinds, expected);
}

#[test]
fn derives_structural_edges() {
    let graph = helios_graph::from_json(FIXTURE).expect("fixture parses");

    // 2 subnet→vpc + 1 instance→subnet_a + 2 alb→subnet + 2 lambda→subnet = 7
    assert_eq!(graph.edge_count(), 7);

    let edges: HashSet<(String, String)> = graph
        .raw_edges()
        .iter()
        .map(|e| (graph[e.source()].id.clone(), graph[e.target()].id.clone()))
        .collect();

    for expected in [
        ("aws_subnet.public_a", "aws_vpc.main"),
        ("aws_subnet.public_b", "aws_vpc.main"),
        ("aws_instance.web", "aws_subnet.public_a"),
        ("aws_lb.app", "aws_subnet.public_a"),
        ("aws_lb.app", "aws_subnet.public_b"),
        ("aws_lambda_function.worker", "aws_subnet.public_a"),
        ("aws_lambda_function.worker", "aws_subnet.public_b"),
    ] {
        assert!(
            edges.contains(&(expected.0.to_string(), expected.1.to_string())),
            "missing edge {} -> {}",
            expected.0,
            expected.1
        );
    }
}

#[test]
fn alb_edge_is_member_of() {
    let graph = helios_graph::from_json(FIXTURE).expect("fixture parses");
    let (alb_idx, _) = graph
        .node_indices()
        .map(|i| (i, &graph[i]))
        .find(|(_, r)| r.kind == ResourceKind::Lb)
        .expect("alb present");
    let kinds: Vec<&Dependency> = graph.edges(alb_idx).map(|e| e.weight()).collect();
    assert!(kinds.iter().all(|d| matches!(d, Dependency::MemberOf(_))));
    assert_eq!(kinds.len(), 2);
}
