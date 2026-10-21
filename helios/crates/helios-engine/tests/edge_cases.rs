//! Second-review repros (`fixtures/edge-cases/`): each used to read as "resilient" or to abort.

use std::collections::BTreeSet;

use helios_engine::{simulate, FailureChain, Scenario, ScenarioKind, SimulateError};
use helios_graph::from_json;

fn fixture(name: &str) -> String {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    std::fs::read_to_string(root.join(name)).expect("fixture")
}

fn run(name: &str, kind: ScenarioKind) -> Result<FailureChain, SimulateError> {
    let g = from_json(&fixture(name)).expect("parses");
    simulate(
        &g,
        &Scenario {
            name: "t".into(),
            kind,
        },
    )
}

fn az(zone: &str) -> ScenarioKind {
    ScenarioKind::AzOutage { az: zone.into() }
}

fn region(r: &str) -> ScenarioKind {
    ScenarioKind::RegionOutage { region: r.into() }
}

fn nat_death(nat: &str) -> ScenarioKind {
    ScenarioKind::SingleNatDeath {
        subnet_id: nat.into(),
    }
}

fn ids(chain: &FailureChain) -> BTreeSet<String> {
    chain.failures.iter().map(|f| f.id.clone()).collect()
}

fn inconclusive(r: Result<FailureChain, SimulateError>) -> String {
    match r {
        Err(SimulateError::Inconclusive(msg)) => msg,
        other => panic!("expected Inconclusive, got {other:?}"),
    }
}

const THREE_TIER: &str = "three-tier-webapp/terraform-show.json";
const WAVE4: &str = "wave4-synthetic/terraform-show.json";

#[test]
fn an_outage_aimed_at_a_region_the_estate_is_not_in_is_an_error() {
    // The default us-east-1a scenario against an ap-south-2 estate used to say "resilient".
    match run(WAVE4, az("us-east-1a")) {
        Err(SimulateError::UnknownRegion { region, estate }) => {
            assert_eq!(
                (region.as_str(), estate.as_str()),
                ("us-east-1", "ap-south-2")
            )
        }
        other => panic!("expected UnknownRegion, got {other:?}"),
    }
    assert!(matches!(
        run(THREE_TIER, region("eu-west-2")),
        Err(SimulateError::UnknownRegion { .. })
    ));
}

#[test]
fn a_malformed_zone_or_region_name_is_an_error() {
    for (kind, what) in [
        (region("us-east1"), "us-east1"),
        (az("us-east-1"), "us-east-1"),
        (az("useast1a"), "useast1a"),
    ] {
        match run(THREE_TIER, kind) {
            Err(SimulateError::Malformed(name, _)) => assert_eq!(name, what),
            other => panic!("{what}: expected Malformed, got {other:?}"),
        }
    }
}

#[test]
fn an_empty_zone_in_the_estates_own_region_is_genuinely_resilient() {
    // ap-south-2c exists and nothing lives in it: a real, correct pass.
    assert!(run(WAVE4, az("ap-south-2c")).unwrap().is_safe());
}

#[test]
fn with_no_region_signal_at_all_nothing_is_assumed_to_be_elsewhere() {
    // p5: an ECS service (capacity 1) in subnets from `data.aws_subnets`, and no ARN, zone or
    // `region` anywhere. The us-east-1 fallback must not decide it is not in eu-west-2.
    let msg = inconclusive(run("edge-cases/p5.json", az("eu-west-2a")));
    assert!(msg.contains("aws_ecs_service.s"), "{msg}");
    let msg = inconclusive(run("edge-cases/p5.json", region("eu-west-2")));
    assert!(msg.contains("no resource declares a region"), "{msg}");
}

#[test]
fn an_in_vpc_lambda_in_unplaceable_subnets_is_inconclusive() {
    let msg = inconclusive(run("edge-cases/s1.json", az("us-east-1a")));
    assert!(msg.contains("vpc_config.subnet_ids"), "{msg}");
}

#[test]
fn an_in_vpc_lambda_falls_when_all_its_subnets_do() {
    // s1b: one subnet, in 1a (its NAT in 1b). Losing 1a loses the Lambda.
    let chain = run("edge-cases/s1b.json", az("us-east-1a")).unwrap();
    assert!(ids(&chain).contains("aws_lambda_function.f"), "{chain:?}");
}

#[test]
fn an_unresolvable_route_table_association_makes_egress_unknown_not_a_cycle() {
    // p1: `for_each = aws_subnet.public`, `subnet_id = each.value.id`. p1a also has a managed
    // default route table through the NAT: falling back to it gave the NAT's own public subnet an
    // Egress edge to that NAT -- DependencyCycle, every command failed. p1b (no default table):
    // the private subnets silently had no egress and `aws_instance.app` survived its NAT's zone.
    for plan in ["edge-cases/p1a.json", "edge-cases/p1b.json"] {
        let msg = inconclusive(run(plan, az("us-east-1a")));
        assert!(msg.contains("egress unknown"), "{plan}: {msg}");
        let msg = inconclusive(run(plan, nat_death("aws_nat_gateway.n")));
        assert!(msg.contains("aws_nat_gateway.n"), "{plan}: {msg}");
    }
}

#[test]
fn a_conditional_on_a_variable_links_candidates_not_an_exact_set() {
    // p2: `subnets = var.ha ? [a, b] : [a]` for an ECS service with desired_count 2 and a Lambda.
    let chain = run("edge-cases/p2.json", az("us-east-1a")).unwrap();
    for id in ["aws_ecs_service.s", "aws_lambda_function.l"] {
        let f = chain.failures.iter().find(|f| f.id == id).expect(id);
        assert!(
            f.reason
                .starts_with("placement could not be resolved exactly"),
            "{id}: {}",
            f.reason
        );
    }
}

#[test]
fn an_inexact_lambda_subnet_set_is_evaluated_worst_case() {
    // p3: Lambda[0] with `subnet_ids = [aws_subnet.private[count.index].id]` but TWO private
    // subnets, each with its own NAT: the pairing is a guess, so losing either NAT loses it.
    let chain = run("edge-cases/p3.json", nat_death("aws_nat_gateway.n[0]")).unwrap();
    assert!(
        ids(&chain).contains("aws_lambda_function.l[0]"),
        "{chain:?}"
    );
}

fn resource_loss(id: &str) -> ScenarioKind {
    ScenarioKind::ResourceLoss {
        resource_id: id.into(),
    }
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| s.to_string()).collect()
}

#[test]
fn unresolvable_associations_whose_tables_agree_still_answer() {
    // vpc-plan-mixed: the PUBLIC associations are `for_each` with `subnet_id = each.value.id` --
    // all to the internet-gateway table -- and only the ALB and the NATs (not compute) sit in the
    // public subnets. Every candidate table has the same NAT set (none): fully determined.
    let chain = run("edge-cases/vpc-plan-mixed.json", az("us-east-1a")).unwrap();
    assert_eq!(
        ids(&chain),
        set(&[
            "aws_nat_gateway.this[0]",
            "aws_subnet.private[0]",
            "aws_subnet.public[0]"
        ])
    );
    let chain = run(
        "edge-cases/vpc-plan-mixed.json",
        nat_death("aws_nat_gateway.this[1]"),
    )
    .unwrap();
    assert_eq!(
        ids(&chain),
        set(&["aws_instance.worker", "aws_nat_gateway.this[1]"])
    );
}

#[test]
fn every_scenario_that_forces_a_nat_or_its_subnet_down_checks_egress() {
    // vpc-plan-foreach: every association is `for_each` over subnets, so compute subnets' route
    // tables are unknown. Losing a NAT -- or the subnet it lives in -- by ANY forcing scenario
    // cannot be evaluated.
    let plan = "edge-cases/vpc-plan-foreach.json";
    for kind in [
        nat_death("aws_nat_gateway.this[1]"),
        resource_loss("aws_nat_gateway.this[1]"),
        nat_death("aws_subnet.public[1]"),
        resource_loss("aws_subnet.public[1]"),
        ScenarioKind::SlowRdsFailover {
            db_id: "aws_subnet.public[1]".into(),
        },
    ] {
        let msg = inconclusive(run(plan, kind.clone()));
        assert!(msg.contains("lose egress"), "{kind:?}: {msg}");
    }
    // A target with no NAT in it is answered.
    assert!(run(plan, resource_loss("aws_db_instance.pg")).is_ok());
}

#[test]
fn a_route_table_named_through_a_local_makes_egress_unknown() {
    // vpc-plan-local-rt: `route_table_id = local.private_route_table_ids[count.index]`.
    let plan = "edge-cases/vpc-plan-local-rt.json";
    let msg = inconclusive(run(plan, nat_death("aws_nat_gateway.this[0]")));
    assert!(msg.contains("aws_subnet.private"), "{msg}");
    let msg = inconclusive(run(plan, az("us-east-1a")));
    assert!(msg.contains("egress unknown"), "{msg}");
}

#[test]
fn a_multi_region_plan_places_resources_by_their_provider() {
    // mr: an `aws.west` provider (us-west-2) for a DR bucket and queue, the default `aws`
    // (us-east-1) for the rest. Before: the DR pair followed the us-east-1 majority.
    let west = run("edge-cases/mr.json", region("us-west-2")).unwrap();
    assert_eq!(
        ids(&west),
        set(&["aws_s3_bucket.dr", "aws_sqs_queue.dr", "aws_subnet.w1"])
    );
    let east = run("edge-cases/mr.json", region("us-east-1")).unwrap();
    assert!(!ids(&east).contains("aws_s3_bucket.dr"), "{east:?}");

    // Without the provider key, the queue's region is unknown in a two-region estate.
    let mut doc: serde_json::Value = serde_json::from_str(&fixture("edge-cases/mr.json")).unwrap();
    for r in doc["configuration"]["root_module"]["resources"]
        .as_array_mut()
        .unwrap()
    {
        if r["address"] == "aws_sqs_queue.dr" {
            r.as_object_mut().unwrap().remove("provider_config_key");
        }
    }
    let g = from_json(&doc.to_string()).unwrap();
    let r = simulate(
        &g,
        &Scenario {
            name: "t".into(),
            kind: region("us-west-2"),
        },
    );
    assert!(inconclusive(r).contains("aws_sqs_queue.dr"));
}

#[test]
fn local_and_wavelength_zones_belong_to_their_parent_region() {
    let json = r#"{"format_version":"1.0","values":{"root_module":{"resources":[
      {"address":"aws_subnet.a","type":"aws_subnet","values":{"id":"s-a","availability_zone":"us-west-2a"}},
      {"address":"aws_subnet.lax","type":"aws_subnet","values":{"id":"s-lax","availability_zone":"us-west-2-lax-1a"}},
      {"address":"aws_subnet.wl","type":"aws_subnet","values":{"id":"s-wl","availability_zone":"us-west-2-wl1-las-wlz-1"}}]}}}"#;
    let g = from_json(json).unwrap();
    let go = |kind| {
        simulate(
            &g,
            &Scenario {
                name: "t".into(),
                kind,
            },
        )
    };
    assert_eq!(
        ids(&go(region("us-west-2")).unwrap()),
        set(&["aws_subnet.a", "aws_subnet.lax", "aws_subnet.wl"])
    );
    assert_eq!(
        ids(&go(az("us-west-2-lax-1a")).unwrap()),
        set(&["aws_subnet.lax"])
    );
    assert_eq!(
        ids(&go(az("us-west-2-wl1-las-wlz-1")).unwrap()),
        set(&["aws_subnet.wl"])
    );
}

/// vpc-plan-mixed with one `aws_route.private_nat_gateway` expression replaced.
fn mixed_with_route(attr: &str, refs: serde_json::Value) -> helios_graph::ResourceGraph {
    let mut doc: serde_json::Value =
        serde_json::from_str(&fixture("edge-cases/vpc-plan-mixed.json")).unwrap();
    for r in doc["configuration"]["root_module"]["resources"]
        .as_array_mut()
        .unwrap()
    {
        if r["address"] == "aws_route.private_nat_gateway" {
            r["expressions"][attr] = serde_json::json!({ "references": refs });
        }
    }
    from_json(&doc.to_string()).unwrap()
}

#[test]
fn a_default_route_whose_nat_or_table_is_indirect_makes_egress_unknown() {
    for (attr, refs) in [
        (
            "nat_gateway_id",
            serde_json::json!(["local.nat_ids", "count.index"]),
        ),
        (
            "route_table_id",
            serde_json::json!(["local.table_ids", "count.index"]),
        ),
    ] {
        let g = mixed_with_route(attr, refs);
        let r = simulate(
            &g,
            &Scenario {
                name: "t".into(),
                kind: nat_death("aws_nat_gateway.this[1]"),
            },
        );
        assert!(inconclusive(r).contains("lose egress"), "{attr}");
    }
}

#[test]
fn compute_in_a_subnet_whose_candidate_tables_agree_gets_that_egress() {
    // vpc-plan-mixed plus a bastion in public[0]: its association is unresolvable, but every
    // table it could be in has the same NAT set (none), so a NAT's death does not touch it.
    let mut doc: serde_json::Value =
        serde_json::from_str(&fixture("edge-cases/vpc-plan-mixed.json")).unwrap();
    doc["planned_values"]["root_module"]["resources"]
        .as_array_mut()
        .unwrap()
        .push(
            serde_json::json!({"address": "aws_instance.bastion", "mode": "managed",
            "type": "aws_instance", "name": "bastion", "values": {}}),
        );
    doc["configuration"]["root_module"]["resources"]
        .as_array_mut()
        .unwrap()
        .push(
            serde_json::json!({"address": "aws_instance.bastion", "expressions": {
            "subnet_id": {"references": ["aws_subnet.public[0].id", "aws_subnet.public[0]",
                                         "aws_subnet.public"]}}}),
        );
    let g = from_json(&doc.to_string()).unwrap();
    let chain = simulate(
        &g,
        &Scenario {
            name: "t".into(),
            kind: nat_death("aws_nat_gateway.this[0]"),
        },
    )
    .expect("determined, not inconclusive");
    assert!(!ids(&chain).contains("aws_instance.bastion"), "{chain:?}");
}
