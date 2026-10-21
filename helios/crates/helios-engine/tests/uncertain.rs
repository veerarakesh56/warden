//! What Helios cannot know must not read as a pass: unplaceable zones, guessed zones, over-connected
//! plan references, principals it cannot evaluate or that nothing uses.

use std::collections::BTreeSet;

use helios_engine::{simulate, FailureChain, Scenario, ScenarioKind, SimulateError};
use helios_graph::from_json;

fn run(json: &str, kind: ScenarioKind) -> Result<FailureChain, SimulateError> {
    let g = from_json(json).expect("parses");
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

fn ids(chain: &FailureChain) -> BTreeSet<String> {
    chain.failures.iter().map(|f| f.id.clone()).collect()
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| s.to_string()).collect()
}

fn inconclusive(r: Result<FailureChain, SimulateError>) -> String {
    match r {
        Err(SimulateError::Inconclusive(msg)) => msg,
        other => panic!("expected Inconclusive, got {other:?}"),
    }
}

/// A capacity-1 ECS service in a subnet that is a DATA SOURCE (not in the graph). It used to get
/// no placement at all, be Regional, and survive every zone outage: exit 0, "resilient".
const EXTERNAL_SUBNET: &str = r#"{"format_version":"1.0","values":{"root_module":{"resources":[
 {"address":"data.aws_subnet.a","mode":"data","type":"aws_subnet","values":{"id":"subnet-ext","availability_zone":"us-east-1a"}},
 {"address":"aws_ecs_cluster.c","mode":"managed","type":"aws_ecs_cluster","values":{"id":"arn:aws:ecs:us-east-1:1:cluster/c","arn":"arn:aws:ecs:us-east-1:1:cluster/c","name":"c"}},
 {"address":"aws_ecs_service.s","mode":"managed","type":"aws_ecs_service","values":{"id":"arn:aws:ecs:us-east-1:1:service/c/s","cluster":"arn:aws:ecs:us-east-1:1:cluster/c","desired_count":1,"network_configuration":[{"subnets":["subnet-ext"]}]}}
]}}}"#;

#[test]
fn a_service_in_a_subnet_helios_cannot_see_is_inconclusive_for_its_region() {
    let msg = inconclusive(run(EXTERNAL_SUBNET, az("us-east-1a")));
    assert!(
        msg.contains("aws_ecs_service.s") && msg.contains("network_configuration.subnets"),
        "{msg}"
    );
    // A region outage is still answerable; another region's zone is not this estate's at all.
    assert!(matches!(
        run(EXTERNAL_SUBNET, az("eu-west-1a")),
        Err(SimulateError::UnknownRegion { .. })
    ));
    let region = ScenarioKind::RegionOutage {
        region: "us-east-1".into(),
    };
    assert!(run(EXTERNAL_SUBNET, region).unwrap().failures.len() == 2);
}

#[test]
fn an_aurora_instance_with_no_zone_and_no_subnet_group_is_inconclusive() {
    // The cluster has no db_subnet_group_name (the default group, outside Terraform): nothing
    // places the instance, whose zone is unknown until apply.
    let json = r#"{"format_version":"1.0","values":{"root_module":{"resources":[
      {"address":"aws_rds_cluster.c","type":"aws_rds_cluster","values":{"id":"c","cluster_identifier":"c","arn":"arn:aws:rds:us-east-1:1:cluster:c"}},
      {"address":"aws_rds_cluster_instance.i","type":"aws_rds_cluster_instance","values":{"id":"i","cluster_identifier":"c","arn":"arn:aws:rds:us-east-1:1:db:i"}}]}}}"#;
    let msg = inconclusive(run(json, az("us-east-1b")));
    assert!(msg.contains("aws_rds_cluster_instance.i"), "{msg}");
}

#[test]
fn a_guessed_zone_makes_an_outage_in_its_region_inconclusive() {
    // A plan whose subnet has only `availability_zone_id`: Helios would have to guess `...a`.
    let json = r#"{"format_version":"1.2","planned_values":{"root_module":{"resources":[
      {"address":"aws_subnet.s","mode":"managed","type":"aws_subnet","name":"s",
       "values":{"availability_zone_id":"use1-az4","region":"us-east-1"}}]}}}"#;
    let msg = inconclusive(run(json, az("us-east-1b")));
    assert!(msg.contains("aws_subnet.s (no availability_zone)"), "{msg}");
    assert!(matches!(
        run(json, az("eu-west-1a")),
        Err(SimulateError::UnknownRegion { .. })
    ));
}

/// Two subnets, an ECS service with `desired_count = 2` (it would survive one zone) and an ALB,
/// both counted (`count = 1`) and indexing the THREE subnets with `count.index`: the counts differ,
/// so the pairing is a guess and every subnet is linked. Linking more members must not make a
/// "survives while any is up" group look safer: both are evaluated worst case.
const INEXACT_PLAN: &str = r#"{
  "format_version": "1.2",
  "planned_values": {"root_module": {"resources": [
    {"address": "aws_subnet.p[0]", "mode": "managed", "type": "aws_subnet", "name": "p", "index": 0, "values": {"availability_zone": "us-east-1a"}},
    {"address": "aws_subnet.p[1]", "mode": "managed", "type": "aws_subnet", "name": "p", "index": 1, "values": {"availability_zone": "us-east-1b"}},
    {"address": "aws_subnet.p[2]", "mode": "managed", "type": "aws_subnet", "name": "p", "index": 2, "values": {"availability_zone": "us-east-1c"}},
    {"address": "aws_ecs_service.s[0]", "mode": "managed", "type": "aws_ecs_service", "name": "s", "index": 0,
     "values": {"desired_count": 2, "network_configuration": [{}]}},
    {"address": "aws_lb.a[0]", "mode": "managed", "type": "aws_lb", "name": "a", "index": 0, "values": {}}
  ]}},
  "configuration": {"root_module": {"resources": [
    {"address": "aws_ecs_service.s", "mode": "managed", "type": "aws_ecs_service", "name": "s",
     "expressions": {"network_configuration": [{"subnets": {"references": ["aws_subnet.p", "count.index"]}}]}},
    {"address": "aws_lb.a", "mode": "managed", "type": "aws_lb", "name": "a",
     "expressions": {"subnets": {"references": ["aws_subnet.p", "count.index"]}}}
  ]}}
}"#;

#[test]
fn an_over_connected_placement_group_is_evaluated_worst_case() {
    let chain = run(INEXACT_PLAN, az("us-east-1c")).unwrap();
    assert_eq!(
        ids(&chain),
        set(&["aws_ecs_service.s[0]", "aws_lb.a[0]", "aws_subnet.p[2]"])
    );
    for f in chain.failures.iter().filter(|f| f.id != "aws_subnet.p[2]") {
        assert!(
            f.reason
                .starts_with("placement could not be resolved exactly from the plan"),
            "{}: {}",
            f.id,
            f.reason
        );
    }
}

#[test]
fn count_index_pairing_inside_a_counted_module_stays_in_the_module_instance() {
    // Two instances of module m, each with two subnets and two instances paired by count.index.
    // Counting the referencing block across BOTH module instances (4) against one instance's
    // subnets (2) broke the pairing and put i[1] (1b) in 1a as well.
    let module = |key: &str| {
        let r = |name: &str, i: u32, az: &str| {
            format!(
                r#"{{"address":"module.m[\"{key}\"].aws_{name}[{i}]","mode":"managed","type":"aws_{t}","name":"{n}","index":{i},"values":{{"availability_zone":"us-east-1{az}"}}}}"#,
                t = name.split('.').next().unwrap(),
                n = name.split('.').nth(1).unwrap()
            )
        };
        format!(
            r#"{{"address":"module.m[\"{key}\"]","resources":[{},{},{},{}]}}"#,
            r("subnet.s", 0, "a"),
            r("subnet.s", 1, "b"),
            r("instance.i", 0, "a"),
            r("instance.i", 1, "b")
        )
    };
    let json = format!(
        r#"{{"format_version":"1.2","planned_values":{{"root_module":{{"resources":[],"child_modules":[{},{}]}}}},
        "configuration":{{"root_module":{{"module_calls":{{"m":{{"module":{{"resources":[
          {{"address":"aws_subnet.s","expressions":{{}}}},
          {{"address":"aws_instance.i","expressions":{{"subnet_id":{{"references":["aws_subnet.s","count.index"]}}}}}}]}}}}}}}}}}}}"#,
        module("x"),
        module("y")
    );
    let chain = run(&json, az("us-east-1a")).unwrap();
    assert!(
        !ids(&chain).contains("module.m[\"x\"].aws_instance.i[1]"),
        "{:?}",
        ids(&chain)
    );
}

/// A Lambda whose role is `var.role_override != null ? var.role_override : aws_iam_role.l.arn`:
/// it references the role AND a variable. Revoking the role matches it; revoking any OTHER role
/// cannot be answered for it.
const PARTIAL_ROLE_PLAN: &str = r#"{
  "format_version": "1.2",
  "planned_values": {"root_module": {"resources": [
    {"address": "aws_lambda_function.f", "mode": "managed", "type": "aws_lambda_function", "name": "f", "values": {"function_name": "f", "region": "us-east-1"}},
    {"address": "aws_lambda_function.g", "mode": "managed", "type": "aws_lambda_function", "name": "g", "values": {"function_name": "g", "region": "us-east-1"}},
    {"address": "aws_iam_role.l", "mode": "managed", "type": "aws_iam_role", "name": "l", "values": {"name": "l"}},
    {"address": "aws_iam_role.other", "mode": "managed", "type": "aws_iam_role", "name": "other", "values": {"name": "other"}}
  ]}},
  "configuration": {"root_module": {"resources": [
    {"address": "aws_lambda_function.f", "mode": "managed", "type": "aws_lambda_function", "name": "f",
     "expressions": {"role": {"references": ["var.role_override", "aws_iam_role.l.arn", "aws_iam_role.l"]}}},
    {"address": "aws_lambda_function.g", "mode": "managed", "type": "aws_lambda_function", "name": "g",
     "expressions": {"role": {"references": ["aws_iam_role.other.arn", "aws_iam_role.other"]}}}
  ]}}
}"#;

#[test]
fn a_role_behind_a_conditional_on_a_variable_is_inconclusive_unless_matched() {
    let revoke = |p: &str| ScenarioKind::IamRevocation {
        principal_arn: p.into(),
    };
    let chain = run(PARTIAL_ROLE_PLAN, revoke("aws_iam_role.l")).unwrap();
    assert_eq!(ids(&chain), set(&["aws_lambda_function.f"]));
    let msg = inconclusive(run(
        PARTIAL_ROLE_PLAN,
        revoke("arn:aws:iam::123456789012:role/other"),
    ));
    assert!(msg.contains("aws_lambda_function.f"), "{msg}");
}

#[test]
fn revoking_a_principal_nothing_uses_is_an_error_not_a_pass() {
    let json = include_str!("../../../fixtures/three-tier-webapp/terraform-show.json");
    match run(
        json,
        ScenarioKind::IamRevocation {
            principal_arn: "arn:aws:iam::123456789012:role/no-such-role".into(),
        },
    ) {
        Err(SimulateError::UnknownPrincipal(p)) => {
            assert_eq!(p, "arn:aws:iam::123456789012:role/no-such-role")
        }
        other => panic!("expected UnknownPrincipal, got {other:?}"),
    }
}
