//! WARDEN's Wave 4 stack as it really ran on AWS (ap-south-2, 2026-09-26), scrubbed with
//! `scripts/scrub_tfjson.py`: `terraform show -json` of the applied state, and of a plan of the
//! same configuration against an empty state (what Helios sees before the first apply).
//!
//! The applied sets were cross-checked against the live account: subnets 0 are in 2a and 1 in
//! 2b, the single NAT is in public-0 (2a), the one EKS node ran in 2a, the two ECS tasks in 2a
//! and 2b, the Redis members in 2a and 2b, and both interface endpoints have one subnet (2a).
//! The Aurora cluster is not here: it is created outside Terraform (express configuration), so
//! Helios cannot see it -- a limit, not a pass.

use std::collections::BTreeSet;

use helios_engine::{scenario, simulate, FailureChain, SimulateError};
use helios_graph::from_json;

fn root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/wave4-fullstack")
}

fn run(input: &str, name: &str) -> Result<FailureChain, SimulateError> {
    let g =
        from_json(&std::fs::read_to_string(root().join(input)).expect("fixture")).expect("parses");
    let s = scenario::load(&root().join(format!("scenarios/{name}.yaml"))).expect("scenario");
    simulate(&g, &s)
}

fn down(input: &str, name: &str) -> BTreeSet<String> {
    let chain = run(input, name).unwrap_or_else(|e| panic!("{name} on {input}: {e:?}"));
    chain.failures.into_iter().map(|f| f.id).collect()
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| s.to_string()).collect()
}

const STATE: &str = "terraform-show.json";
const PLAN: &str = "plan.json";
const VPC_LAMBDAS: [&str; 3] = [
    r#"aws_lambda_function.fn["ops"]"#,
    r#"aws_lambda_function.fn["order-processor"]"#,
    r#"aws_lambda_function.fn["reconciler"]"#,
];

#[test]
fn losing_2a_takes_the_nat_the_vpc_lambdas_the_node_group_and_both_endpoints() {
    let mut want = set(&[
        "aws_eks_node_group.this", // one node, placement unknown: worst case (it WAS in 2a)
        "aws_nat_gateway.this",
        "aws_subnet.private[0]",
        "aws_subnet.public[0]",
        r#"aws_vpc_endpoint.interface["secretsmanager"]"#,
        r#"aws_vpc_endpoint.interface["sqs"]"#,
    ]);
    want.extend(set(&VPC_LAMBDAS));
    assert_eq!(down(STATE, "az-2a"), want);
}

#[test]
fn losing_2b_takes_its_subnets_and_the_single_node_group_worst_case() {
    assert_eq!(
        down(STATE, "az-2b"),
        set(&[
            "aws_eks_node_group.this",
            "aws_subnet.private[1]",
            "aws_subnet.public[1]",
        ])
    );
}

#[test]
fn nothing_terraform_manages_is_in_2c() {
    assert_eq!(down(STATE, "az-2c"), set(&[]));
}

#[test]
fn the_nat_takes_exactly_the_three_in_vpc_lambdas() {
    let mut want = set(&["aws_nat_gateway.this"]);
    want.extend(set(&VPC_LAMBDAS));
    assert_eq!(down(STATE, "nat-death"), want);
}

#[test]
fn losing_a_resource_or_a_role_takes_only_what_names_it() {
    for (name, want) in [
        ("redis-loss", "aws_elasticache_replication_group.redis"),
        ("nodegroup-loss", "aws_eks_node_group.this"),
        ("orders-queue-loss", r#"aws_sqs_queue.main["orders"]"#), // consumers: MemberOf
        ("iam-lambda-role", r#"aws_lambda_function.fn["checkout"]"#),
        ("iam-node-role", "aws_eks_node_group.this"),
    ] {
        assert_eq!(down(STATE, name), set(&[want]), "{name} on the state");
        assert_eq!(down(PLAN, name), set(&[want]), "{name} on the plan");
    }
}

#[test]
fn the_region_takes_all_26_modelled_resources_on_both() {
    assert_eq!(down(STATE, "region").len(), 26);
    assert_eq!(down(PLAN, "region"), down(STATE, "region"));
}

#[test]
fn before_apply_a_zone_outage_is_inconclusive_because_the_lambdas_cannot_be_placed() {
    for name in ["az-2a", "az-2b", "az-2c"] {
        match run(PLAN, name) {
            Err(SimulateError::Inconclusive(msg)) => {
                for l in VPC_LAMBDAS {
                    assert!(msg.contains(l), "{name}: {msg}");
                }
            }
            other => panic!("{name} on the plan: expected Inconclusive, got {other:?}"),
        }
    }
}

#[test]
fn before_apply_a_nat_death_is_inconclusive_not_the_nat_alone() {
    // It used to report the NAT alone -- a verdict that missed the three Lambdas the applied
    // state loses with it -- because their subnets come from a `dynamic "vpc_config"` block.
    match run(PLAN, "nat-death") {
        Err(SimulateError::Inconclusive(msg)) => {
            for l in VPC_LAMBDAS {
                assert!(msg.contains(l), "{msg}");
            }
        }
        other => panic!("expected Inconclusive, got {other:?}"),
    }
}

fn fix(edits: serde_json::Value) -> helios_engine::FixProposal {
    serde_json::from_value(serde_json::json!({
        "scenario_name": "lose-ap-south-2a", "explanation": "t", "edits": edits
    }))
    .expect("fix")
}

fn verify_2a(
    edits: serde_json::Value,
) -> Result<helios_engine::VerifyReport, helios_engine::VerifyError> {
    let g =
        from_json(&std::fs::read_to_string(root().join(STATE)).expect("fixture")).expect("parses");
    let s = scenario::load(&root().join("scenarios/az-2a.yaml")).expect("scenario");
    helios_engine::verify(&g, &[s], &fix(edits))
}

#[test]
fn a_capacity_fix_written_as_a_dotted_path_verifies() {
    // What Claude actually proposed on this stack (2026-09-26): `scaling_config.desired_size`.
    // It used to be stored as a literal top-level key named "scaling_config.desired_size" -- read
    // by nothing, so the node group stayed "failed" and the fix looked wrong.
    for key in [
        "scaling_config.desired_size",
        "scaling_config[0].desired_size",
    ] {
        let r = verify_2a(serde_json::json!([{
            "op": "set_attr", "resource_id": "aws_eks_node_group.this", "key": key, "value": 2
        }]))
        .unwrap_or_else(|e| panic!("{key}: {e}"));
        assert_eq!(
            r.target().resolved,
            vec!["aws_eks_node_group.this".to_string()],
            "{key}"
        );
        for s in &r.scenarios {
            assert!(s.new_failures.is_empty(), "{key}: {s:?}");
        }
    }
}

#[test]
fn moving_a_resource_is_refused_not_verified_as_a_fix_that_changed_nothing() {
    // Claude's other edits on this stack: move the NAT to 2b, add a 2b subnet to the endpoints.
    for (id, key) in [
        ("aws_nat_gateway.this", "subnet_id"),
        (r#"aws_vpc_endpoint.interface["sqs"]"#, "subnet_ids"),
        (
            "aws_ecs_service.orders_api",
            "network_configuration.subnets",
        ),
    ] {
        let r = verify_2a(serde_json::json!([{
            "op": "set_attr", "resource_id": id, "key": key, "value": "subnet-00000000000000002"
        }]));
        match r {
            Err(helios_engine::VerifyError::Apply(helios_engine::FixError::PlacementKey {
                key: k,
                ..
            })) => {
                assert_eq!(k, key)
            }
            other => panic!("{id} {key}: expected PlacementKey, got {other:?}"),
        }
    }
}

#[test]
fn a_path_into_nothing_is_an_error_not_a_new_key() {
    let r = verify_2a(serde_json::json!([{
        "op": "set_attr", "resource_id": "aws_eks_node_group.this", "key": "no_such_block.size", "value": 2
    }]));
    assert!(
        matches!(
            r,
            Err(helios_engine::VerifyError::Apply(
                helios_engine::FixError::Path { .. }
            ))
        ),
        "{r:?}"
    );
}

#[test]
fn every_attribute_an_edge_is_built_from_is_a_placement_key() {
    let src = include_str!("../../helios-graph/src/resource.rs");
    let mut roots = BTreeSet::new();
    for kind in [
        "Contains(\"",
        "MemberOf(\"",
        "Spread(\"",
        "Egress(\"",
        "direct(\"",
    ] {
        for chunk in src.split(kind).skip(1) {
            let attr = chunk.split('"').next().unwrap_or_default();
            if attr.len() > 1 {
                roots.insert(attr.split('.').next().unwrap_or_default().to_string());
            }
        }
    }
    let missing: Vec<_> = roots
        .iter()
        .filter(|r| !helios_engine::fix::PLACEMENT_KEYS.contains(&r.as_str()))
        .collect();
    assert!(roots.len() >= 12, "{roots:?}");
    assert!(
        missing.is_empty(),
        "edges are built from {missing:?}, which a fix could silently set"
    );
}
