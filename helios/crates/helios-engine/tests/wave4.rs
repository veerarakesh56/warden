//! Exact failure sets for a synthetic copy of WARDEN's Wave 4 stack (ap-south-2, two zones):
//! Aurora (writer 2a, reader 2b), a two-node Redis with automatic failover, an ALB and an ECS
//! service over the public subnets, EKS with a one-node group, in-VPC Lambdas, SQS with DLQs,
//! and interface endpoints in ONE private subnet.

use std::collections::BTreeSet;

use helios_engine::{
    apply_fix, simulate, verify, FixEdit, FixProposal, Scenario, ScenarioKind, SimulateError,
};
use helios_graph::ResourceGraph;
use serde_json::json;

const FIXTURE: &str = include_str!("../../../fixtures/wave4-synthetic/terraform-show.json");

const AURORA_1: &str = "aws_rds_cluster_instance.aurora_1";
const AURORA_2: &str = "aws_rds_cluster_instance.aurora_2";
const CLUSTER: &str = "aws_rds_cluster.aurora";
const ECS: &str = "aws_ecs_service.orders_api";
const NODES: &str = "aws_eks_node_group.this";
const REDIS: &str = "aws_elasticache_replication_group.redis";

fn graph() -> ResourceGraph {
    helios_graph::from_json(FIXTURE).expect("fixture parses")
}

fn scenario(kind: ScenarioKind) -> Scenario {
    Scenario {
        name: "t".into(),
        kind,
    }
}

fn az(zone: &str) -> Scenario {
    scenario(ScenarioKind::AzOutage { az: zone.into() })
}

fn down(g: &ResourceGraph, s: &Scenario) -> BTreeSet<String> {
    simulate(g, s)
        .expect("simulates")
        .failures
        .into_iter()
        .map(|f| f.id)
        .collect()
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| s.to_string()).collect()
}

fn patched(g: &ResourceGraph, id: &str, key: &str, value: serde_json::Value) -> ResourceGraph {
    apply_fix(g, &fix(id, key, value)).expect("fix applies")
}

fn fix(id: &str, key: &str, value: serde_json::Value) -> FixProposal {
    FixProposal {
        scenario_name: "t".into(),
        explanation: "t".into(),
        edits: vec![FixEdit::SetAttr {
            resource_id: id.into(),
            key: key.into(),
            value,
        }],
    }
}

#[test]
fn losing_2a_kills_its_subnets_the_2a_writer_the_node_group_and_the_single_subnet_endpoints() {
    assert_eq!(
        down(&graph(), &az("ap-south-2a")),
        set(&[
            NODES,
            AURORA_1,
            "aws_subnet.private[0]",
            "aws_subnet.public[0]",
            "aws_vpc_endpoint.interface[\"secretsmanager\"]",
            "aws_vpc_endpoint.interface[\"sqs\"]",
        ])
    );
}

#[test]
fn losing_2b_kills_the_reader_and_the_node_group_worst_case() {
    assert_eq!(
        down(&graph(), &az("ap-south-2b")),
        set(&[
            NODES,
            AURORA_2,
            "aws_subnet.private[1]",
            "aws_subnet.public[1]"
        ])
    );
}

#[test]
fn losing_2c_kills_nothing() {
    assert!(down(&graph(), &az("ap-south-2c")).is_empty());
}

#[test]
fn losing_the_region_kills_every_node_and_another_region_kills_none() {
    let g = graph();
    let all: BTreeSet<String> = g.node_indices().map(|i| g[i].id.clone()).collect();
    let region = |r: &str| scenario(ScenarioKind::RegionOutage { region: r.into() });
    assert_eq!(down(&g, &region("ap-south-2")), all);
    assert!(matches!(
        simulate(&g, &region("us-east-1")),
        Err(SimulateError::UnknownRegion { .. })
    ));
}

#[test]
fn writer_loss_takes_only_that_instance() {
    let s = scenario(ScenarioKind::SlowRdsFailover {
        db_id: AURORA_1.into(),
    });
    let chain = simulate(&graph(), &s).unwrap();
    assert_eq!(
        chain
            .failures
            .iter()
            .map(|f| f.id.as_str())
            .collect::<Vec<_>>(),
        vec![AURORA_1]
    );
    assert!(chain.failures[0].reason.contains("writer loss"));
}

#[test]
fn a_slow_cluster_failover_takes_only_the_cluster() {
    let s = scenario(ScenarioKind::SlowRdsFailover {
        db_id: CLUSTER.into(),
    });
    assert_eq!(down(&graph(), &s), set(&[CLUSTER]));
}

#[test]
fn the_cluster_falls_when_both_instances_do() {
    // Put the reader in 2a too: one zone now holds every instance.
    let g = patched(
        &graph(),
        AURORA_2,
        "availability_zone",
        json!("ap-south-2a"),
    );
    let chain = simulate(&g, &az("ap-south-2a")).unwrap();
    let cluster = chain
        .failures
        .iter()
        .find(|f| f.id == CLUSTER)
        .expect("cluster down");
    assert_eq!(
        cluster.reason,
        "every one of its 2 cluster_identifier placements is down"
    );
}

#[test]
fn resource_loss_takes_only_that_resource() {
    let s = scenario(ScenarioKind::ResourceLoss {
        resource_id: REDIS.into(),
    });
    let chain = simulate(&graph(), &s).unwrap();
    assert_eq!(chain.failures.len(), 1);
    assert_eq!(chain.failures[0].id, REDIS);
    assert!(chain.failures[0].reason.contains("resource-loss"));
}

/// A capacity-1 resource dies in either zone, and a `set_attr` raising the capacity verifies —
/// the spread rule is read at solve time, not frozen at graph build.
fn capacity_fix_verifies(id: &str, key: &str, one: serde_json::Value, two: serde_json::Value) {
    let g = patched(&graph(), id, key, one);
    for zone in ["ap-south-2a", "ap-south-2b"] {
        assert!(down(&g, &az(zone)).contains(id), "{id} survives {zone}");
    }
    let report = verify(&g, &[az("ap-south-2a")], &fix(id, key, two)).unwrap();
    assert!(
        report.target().resolved.contains(&id.to_string()),
        "{report:?}"
    );
    for s in &report.scenarios {
        assert!(s.new_failures.is_empty(), "{s:?}");
    }
}

#[test]
fn ecs_desired_count_one_dies_and_two_verifies() {
    capacity_fix_verifies(ECS, "desired_count", json!(1), json!(2));
}

#[test]
fn eks_desired_size_two_verifies() {
    let size = |n: u32| json!([{"desired_size": n, "min_size": n, "max_size": n}]);
    capacity_fix_verifies(NODES, "scaling_config", size(1), size(2));
}

#[test]
fn redis_automatic_failover_verifies() {
    capacity_fix_verifies(
        REDIS,
        "automatic_failover_enabled",
        json!(false),
        json!(true),
    );
}

#[test]
fn revoking_the_eks_cluster_role_takes_the_node_group_with_it() {
    let s = scenario(ScenarioKind::IamRevocation {
        principal_arn: "arn:aws:iam::123456789012:role/warden-pg-fs-eks-cluster".into(),
    });
    assert_eq!(down(&graph(), &s), set(&["aws_eks_cluster.this", NODES]));
}

#[test]
fn revoking_the_node_role_takes_only_the_node_group() {
    let s = scenario(ScenarioKind::IamRevocation {
        principal_arn: "arn:aws:iam::123456789012:role/warden-pg-fs-eks-node".into(),
    });
    assert_eq!(down(&graph(), &s), set(&[NODES]));
}

#[test]
fn an_alb_with_no_declared_zones_falls_when_all_its_subnets_do() {
    // Real `aws_lb` state has `subnets` but no `availability_zones`. Before 0.2 such an ALB only
    // ever failed with its region; its zones are its subnets'.
    let g = patched(
        &graph(),
        "aws_subnet.public[1]",
        "availability_zone",
        json!("ap-south-2a"),
    );
    let chain = simulate(&g, &az("ap-south-2a")).unwrap();
    let alb = chain
        .failures
        .iter()
        .find(|f| f.id == "aws_lb.orders")
        .expect("ALB down");
    assert_eq!(alb.reason, "every one of its 2 subnets placements is down");
    assert!(chain.failures.iter().any(|f| f.id == ECS));
}

// ---- the same stack as a saved PLAN, before the first apply ------------------------------------

const PLAN: &str = include_str!("../../../fixtures/wave4-synthetic/plan.json");

/// The plan as `terraform show -json` renders WARDEN's config: the Lambdas' `dynamic
/// "vpc_config"` has no references, so before apply nothing says which subnets they use.
fn plan_as_rendered() -> ResourceGraph {
    helios_graph::from_json(PLAN).expect("plan parses")
}

/// The same plan had `vpc_config` been a static block (`subnet_ids = aws_subnet.private[*].id`):
/// what the rest of the plan's verdicts are, once the Lambdas can be placed.
fn plan() -> ResourceGraph {
    let mut doc: serde_json::Value = serde_json::from_str(PLAN).unwrap();
    let blocks = doc["configuration"]["root_module"]["resources"]
        .as_array_mut()
        .unwrap();
    let fns = blocks
        .iter_mut()
        .find(|b| b["address"] == "aws_lambda_function.fn")
        .unwrap();
    fns["expressions"]["vpc_config"] =
        json!([{"subnet_ids": {"references": ["aws_subnet.private"]}}]);
    helios_graph::from_json(&doc.to_string()).expect("plan parses")
}

#[test]
fn before_apply_a_zone_outage_is_inconclusive_while_the_lambdas_subnets_are_unknown() {
    for zone in ["ap-south-2a", "ap-south-2b", "ap-south-2c"] {
        match simulate(&plan_as_rendered(), &az(zone)) {
            Err(SimulateError::Inconclusive(msg)) => {
                for f in ["ops", "order-processor", "reconciler"] {
                    assert!(msg.contains(&format!("fn[\"{f}\"]")), "{zone}: {msg}");
                }
                assert!(!msg.contains("fn[\"checkout\"]"), "not in a VPC: {msg}");
            }
            other => panic!("{zone}: expected Inconclusive, got {other:?}"),
        }
    }
    // A region outage does not depend on zones.
    let all = plan_as_rendered().node_count();
    assert_eq!(
        down(
            &plan_as_rendered(),
            &scenario(ScenarioKind::RegionOutage {
                region: "ap-south-2".into()
            })
        )
        .len(),
        all
    );
}

#[test]
fn before_apply_2a_also_takes_the_other_aurora_instance_and_the_cluster() {
    // No Aurora instance has a zone until apply, so each is lost with ANY subnet of its subnet
    // group (worst case) -- and with both gone, the cluster is too. The honest headline.
    let mut want = down(&graph(), &az("ap-south-2a"));
    want.extend(set(&[AURORA_2, CLUSTER]));
    assert_eq!(down(&plan(), &az("ap-south-2a")), want);
    let mut want = down(&graph(), &az("ap-south-2b"));
    want.extend(set(&[AURORA_1, CLUSTER]));
    assert_eq!(down(&plan(), &az("ap-south-2b")), want);
    assert!(down(&plan(), &az("ap-south-2c")).is_empty());
}

#[test]
fn a_plan_with_no_arns_and_no_region_attributes_is_placed_by_its_zones() {
    // Nothing in the plan carries an ARN or a `region`: only the subnets' zones (read from a data
    // source at plan time) say ap-south-2.
    let g = plan();
    let all: BTreeSet<String> = g.node_indices().map(|i| g[i].id.clone()).collect();
    let region = |r: &str| scenario(ScenarioKind::RegionOutage { region: r.into() });
    assert_eq!(down(&g, &region("ap-south-2")), all);
    assert!(matches!(
        simulate(&g, &region("us-east-1")),
        Err(SimulateError::UnknownRegion { .. })
    ));
}

#[test]
fn before_apply_a_revoked_role_is_matched_through_the_configuration() {
    // No role ARN is known before apply; the resources' role attributes REFERENCE the roles, whose
    // names are known. The ARN's name, or the role's Terraform address, finds them.
    let revoke = |p: &str| {
        scenario(ScenarioKind::IamRevocation {
            principal_arn: p.into(),
        })
    };
    assert_eq!(
        down(
            &plan(),
            &revoke("arn:aws:iam::123456789012:role/warden-pg-fs-eks-cluster")
        ),
        set(&["aws_eks_cluster.this", NODES])
    );
    assert_eq!(
        down(&plan(), &revoke("aws_iam_role.lambda[\"reconciler\"]")),
        set(&["aws_lambda_function.fn[\"reconciler\"]"])
    );
}

#[test]
fn before_apply_a_role_behind_a_variable_is_inconclusive_not_a_pass() {
    // `role = var.opaque_role_arn`: nothing can say whether it is the revoked role. This used to
    // report "no failures" -- a silent pass, the defect 0.1.4 removed for unknown targets.
    let g = helios_graph::from_json(include_str!("../../../fixtures/iam-inconclusive/plan.json"))
        .unwrap();
    let s = scenario(ScenarioKind::IamRevocation {
        principal_arn: "arn:aws:iam::123456789012:role/worker".into(),
    });
    match simulate(&g, &s) {
        Err(SimulateError::Inconclusive(msg)) => {
            assert!(msg.contains("aws_lambda_function.opaque"), "{msg}");
            assert!(!msg.contains("aws_lambda_function.known"), "{msg}");
        }
        other => panic!("expected Inconclusive, got {other:?}"),
    }
}

#[test]
fn a_group_that_cannot_lose_a_member_says_why() {
    let reason = |g: &ResourceGraph, id: &str| {
        simulate(g, &az("ap-south-2a"))
            .unwrap()
            .failures
            .into_iter()
            .find(|f| f.id == id)
            .unwrap_or_else(|| panic!("{id} not down"))
            .reason
    };
    assert!(reason(&plan(), AURORA_2).starts_with("its zone is unknown until apply — lost when"));
    let g = patched(&graph(), REDIS, "automatic_failover_enabled", json!(false));
    assert!(reason(&g, REDIS).starts_with("no automatic failover to a replica"));
    let g = patched(&graph(), ECS, "desired_count", json!(1));
    assert!(reason(&g, ECS).starts_with("desired_count 1 (where its task runs is unknown)"));
    assert!(reason(&graph(), NODES).starts_with("desired_size 1 (where its node runs is unknown)"));
}
