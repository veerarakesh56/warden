//! NAT gateways: a subnet's egress is its route table's default route. Losing the NAT loses the
//! EGRESS of compute in the subnet (instances, Lambdas, ECS services, EKS node groups); the subnet,
//! and a database or cache in it, do not fail.

use std::collections::BTreeSet;

use helios_engine::{simulate, Scenario, ScenarioKind};
use helios_graph::{from_json, ResourceGraph};

fn res(address: &str, tf_type: &str, values: &str) -> String {
    format!(r#"{{"address":"{address}","mode":"managed","type":"{tf_type}","values":{values}}}"#)
}

fn state(resources: &[String]) -> String {
    format!(
        r#"{{"format_version":"1.0","values":{{"root_module":{{"resources":[{}]}}}}}}"#,
        resources.join(",")
    )
}

fn subnet(name: &str, az: &str) -> String {
    res(
        &format!("aws_subnet.{name}"),
        "aws_subnet",
        &format!(
            r#"{{"id":"subnet-{name}","vpc_id":"vpc-1","availability_zone":"us-east-1{az}"}}"#
        ),
    )
}

fn assoc(name: &str, table: &str) -> String {
    res(
        &format!("aws_route_table_association.{name}"),
        "aws_route_table_association",
        &format!(
            r#"{{"id":"rtbassoc-{name}","subnet_id":"subnet-{name}","route_table_id":"rtb-{table}"}}"#
        ),
    )
}

fn instance(name: &str, subnet: &str, az: &str) -> String {
    res(
        &format!("aws_instance.{name}"),
        "aws_instance",
        &format!(
            r#"{{"id":"i-{name}","subnet_id":"subnet-{subnet}","availability_zone":"us-east-1{az}"}}"#
        ),
    )
}

/// One NAT in public_a (1a) for both private subnets; the default route is a separate `aws_route`.
/// The PUBLIC table also sends 10.99.0.0/16 through the NAT: not a default route, so no edge (an
/// edge would even be a cycle: public_a -> NAT -> public_a). In private_b: an instance (compute),
/// a cache and an interface endpoint (not compute); a Lambda spans both private subnets.
fn single_nat() -> ResourceGraph {
    from_json(&state(&[
        res("aws_vpc.main", "aws_vpc", r#"{"id":"vpc-1"}"#),
        subnet("public_a", "a"),
        subnet("public_b", "b"),
        subnet("private_a", "a"),
        subnet("private_b", "b"),
        res(
            "aws_nat_gateway.main",
            "aws_nat_gateway",
            r#"{"id":"nat-1","subnet_id":"subnet-public_a"}"#,
        ),
        res(
            "aws_route_table.public",
            "aws_route_table",
            r#"{"id":"rtb-public","route":[
                {"cidr_block":"0.0.0.0/0","gateway_id":"igw-1","nat_gateway_id":""},
                {"cidr_block":"10.99.0.0/16","gateway_id":"","nat_gateway_id":"nat-1"}]}"#,
        ),
        res(
            "aws_route_table.private",
            "aws_route_table",
            r#"{"id":"rtb-private","route":[]}"#,
        ),
        res(
            "aws_route.private_default",
            "aws_route",
            r#"{"id":"r-1","route_table_id":"rtb-private","destination_cidr_block":"0.0.0.0/0","nat_gateway_id":"nat-1"}"#,
        ),
        assoc("public_a", "public"),
        assoc("public_b", "public"),
        assoc("private_a", "private"),
        assoc("private_b", "private"),
        instance("app_b", "private_b", "b"),
        res(
            "aws_vpc_endpoint.ssm",
            "aws_vpc_endpoint",
            r#"{"id":"vpce-1","vpc_endpoint_type":"Interface","subnet_ids":["subnet-private_b"]}"#,
        ),
        res(
            "aws_elasticache_cluster.cache_b",
            "aws_elasticache_cluster",
            r#"{"id":"cache-b","availability_zone":"us-east-1b"}"#,
        ),
        res(
            "aws_lambda_function.worker",
            "aws_lambda_function",
            r#"{"id":"worker","function_name":"worker","arn":"arn:aws:lambda:us-east-1:123456789012:function:worker",
                "vpc_config":[{"subnet_ids":["subnet-private_a","subnet-private_b"]}]}"#,
        ),
    ]))
    .expect("parses")
}

fn run(g: &ResourceGraph, kind: ScenarioKind) -> Vec<(String, String)> {
    let s = Scenario {
        name: "t".into(),
        kind,
    };
    simulate(g, &s)
        .expect("simulates")
        .failures
        .into_iter()
        .map(|f| (f.id, f.reason))
        .collect()
}

fn down(g: &ResourceGraph, kind: ScenarioKind) -> BTreeSet<String> {
    run(g, kind).into_iter().map(|(id, _)| id).collect()
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| s.to_string()).collect()
}

fn az(zone: &str) -> ScenarioKind {
    ScenarioKind::AzOutage { az: zone.into() }
}

fn nat_death(nat: &str) -> ScenarioKind {
    ScenarioKind::SingleNatDeath {
        subnet_id: nat.into(),
    }
}

#[test]
fn losing_the_nat_zone_takes_the_egress_of_compute_in_the_other_zone() {
    // app_b (1b) loses egress; the Lambda has lost it in both its subnets; the cache in the same
    // subnet as app_b, and the subnet itself, are fine.
    assert_eq!(
        down(&single_nat(), az("us-east-1a")),
        set(&[
            "aws_instance.app_b",
            "aws_lambda_function.worker",
            "aws_nat_gateway.main",
            "aws_subnet.private_a",
            "aws_subnet.public_a",
        ])
    );
    // The other way round the NAT survives, so only zone b is lost (the Lambda keeps private_a).
    assert_eq!(
        down(&single_nat(), az("us-east-1b")),
        set(&[
            "aws_elasticache_cluster.cache_b",
            "aws_instance.app_b",
            "aws_subnet.private_b",
            "aws_subnet.public_b",
            "aws_vpc_endpoint.ssm"
        ])
    );
}

#[test]
fn single_nat_death_can_name_the_nat_and_spares_non_compute() {
    let reasons = run(&single_nat(), nat_death("aws_nat_gateway.main"));
    let want = |id: &str, why: &str| (id.to_string(), why.to_string());
    assert_eq!(
        reasons,
        vec![
            want(
                "aws_instance.app_b",
                "egress via NAT aws_nat_gateway.main (the default route of aws_subnet.private_b), \
                 which is down"
            ),
            want(
                "aws_lambda_function.worker",
                "egress via NAT aws_nat_gateway.main (the default route of aws_subnet.private_b), \
                 which is down"
            ),
            want("aws_nat_gateway.main", "NAT aws_nat_gateway.main is dead"),
        ]
    );
}

#[test]
fn a_nat_inside_the_subnet_it_serves_is_a_broken_network_not_an_error() {
    // subnet --Egress--> NAT --Contains--> subnet looks like a cycle, but a subnet's `down` never
    // reads its Egress edge (only compute in it does), so the encoding stays unique: the NAT dying
    // takes the instance's egress, not the subnet.
    let g = from_json(&state(&[
        subnet("private_a", "a"),
        res(
            "aws_nat_gateway.loop",
            "aws_nat_gateway",
            r#"{"id":"nat-1","subnet_id":"subnet-private_a"}"#,
        ),
        res(
            "aws_route_table.private",
            "aws_route_table",
            r#"{"id":"rtb-private","route":[{"cidr_block":"0.0.0.0/0","nat_gateway_id":"nat-1"}]}"#,
        ),
        assoc("private_a", "private"),
        instance("app_a", "private_a", "a"),
    ]))
    .expect("not a dependency cycle");
    assert_eq!(
        down(&g, nat_death("aws_nat_gateway.loop")),
        set(&["aws_instance.app_a", "aws_nat_gateway.loop"])
    );
}

/// A NAT per zone, as a PLAN: every id is unknown, and each private route table's default route
/// names `aws_nat_gateway.this[count.index]` -- rule 2 pairs table [i] with NAT [i]. Table [1]'s
/// whole `route` attribute is unknown, so only its references say where it goes. The instances'
/// zones are unknown too: their subnet places them.
const PER_AZ_PLAN: &str = r#"{
  "format_version": "1.2",
  "planned_values": {"root_module": {"resources": [
    {"address": "aws_vpc.main", "mode": "managed", "type": "aws_vpc", "name": "main", "values": {}},
    {"address": "aws_subnet.public[0]", "mode": "managed", "type": "aws_subnet", "name": "public",
     "index": 0, "values": {"availability_zone": "us-east-1a"}},
    {"address": "aws_subnet.public[1]", "mode": "managed", "type": "aws_subnet", "name": "public",
     "index": 1, "values": {"availability_zone": "us-east-1b"}},
    {"address": "aws_subnet.private[0]", "mode": "managed", "type": "aws_subnet", "name": "private",
     "index": 0, "values": {"availability_zone": "us-east-1a"}},
    {"address": "aws_subnet.private[1]", "mode": "managed", "type": "aws_subnet", "name": "private",
     "index": 1, "values": {"availability_zone": "us-east-1b"}},
    {"address": "aws_nat_gateway.this[0]", "mode": "managed", "type": "aws_nat_gateway",
     "name": "this", "index": 0, "values": {}},
    {"address": "aws_nat_gateway.this[1]", "mode": "managed", "type": "aws_nat_gateway",
     "name": "this", "index": 1, "values": {}},
    {"address": "aws_route_table.private[0]", "mode": "managed", "type": "aws_route_table",
     "name": "private", "index": 0, "values": {"route": [{"cidr_block": "0.0.0.0/0"}]}},
    {"address": "aws_route_table.private[1]", "mode": "managed", "type": "aws_route_table",
     "name": "private", "index": 1, "values": {}},
    {"address": "aws_route_table_association.private[0]", "mode": "managed",
     "type": "aws_route_table_association", "name": "private", "index": 0, "values": {}},
    {"address": "aws_route_table_association.private[1]", "mode": "managed",
     "type": "aws_route_table_association", "name": "private", "index": 1, "values": {}},
    {"address": "aws_instance.app[0]", "mode": "managed", "type": "aws_instance", "name": "app",
     "index": 0, "values": {}},
    {"address": "aws_instance.app[1]", "mode": "managed", "type": "aws_instance", "name": "app",
     "index": 1, "values": {}}
  ]}},
  "configuration": {"root_module": {"resources": [
    {"address": "aws_vpc.main", "mode": "managed", "type": "aws_vpc", "name": "main"},
    {"address": "aws_subnet.public", "mode": "managed", "type": "aws_subnet", "name": "public",
     "expressions": {"vpc_id": {"references": ["aws_vpc.main.id", "aws_vpc.main"]}}},
    {"address": "aws_subnet.private", "mode": "managed", "type": "aws_subnet", "name": "private",
     "expressions": {"vpc_id": {"references": ["aws_vpc.main.id", "aws_vpc.main"]}}},
    {"address": "aws_nat_gateway.this", "mode": "managed", "type": "aws_nat_gateway",
     "name": "this", "expressions": {"subnet_id": {"references": ["aws_subnet.public", "count.index"]}}},
    {"address": "aws_route_table.private", "mode": "managed", "type": "aws_route_table",
     "name": "private", "expressions": {"route": {"references": ["aws_nat_gateway.this", "count.index"]}}},
    {"address": "aws_route_table_association.private", "mode": "managed",
     "type": "aws_route_table_association", "name": "private", "expressions": {
       "subnet_id": {"references": ["aws_subnet.private", "count.index"]},
       "route_table_id": {"references": ["aws_route_table.private", "count.index"]}}},
    {"address": "aws_instance.app", "mode": "managed", "type": "aws_instance", "name": "app",
     "expressions": {"subnet_id": {"references": ["aws_subnet.private", "count.index"]}}}
  ]}}
}"#;

#[test]
fn per_zone_nats_keep_the_other_zone_up_even_in_a_plan() {
    let g = from_json(PER_AZ_PLAN).expect("parses");
    assert_eq!(
        down(&g, az("us-east-1a")),
        set(&[
            "aws_instance.app[0]",
            "aws_nat_gateway.this[0]",
            "aws_subnet.private[0]",
            "aws_subnet.public[0]"
        ])
    );
    assert_eq!(
        down(&g, nat_death("aws_nat_gateway.this[1]")),
        set(&["aws_instance.app[1]", "aws_nat_gateway.this[1]"])
    );
}

/// Private subnet with NO explicit association, in a VPC whose main route table (set by an
/// `aws_main_route_table_association`, or the adopted `aws_default_route_table`) goes through the
/// NAT in 1a. `extra` is appended.
fn main_table(table: &str, extra: &[String]) -> ResourceGraph {
    let mut resources = vec![
        res("aws_vpc.main", "aws_vpc", r#"{"id":"vpc-1"}"#),
        subnet("public_a", "a"),
        subnet("private_b", "b"),
        res(
            "aws_nat_gateway.main",
            "aws_nat_gateway",
            r#"{"id":"nat-1","subnet_id":"subnet-public_a"}"#,
        ),
        res(
            "aws_route_table.public",
            "aws_route_table",
            r#"{"id":"rtb-public","route":[{"cidr_block":"0.0.0.0/0","gateway_id":"igw-1","nat_gateway_id":""}]}"#,
        ),
        assoc("public_a", "public"),
        instance("app_b", "private_b", "b"),
    ];
    let nat_route = r#"[{"cidr_block":"0.0.0.0/0","nat_gateway_id":"nat-1"}]"#;
    if table == "main" {
        resources.push(res(
            "aws_route_table.main",
            "aws_route_table",
            &format!(r#"{{"id":"rtb-main","vpc_id":"vpc-1","route":{nat_route}}}"#),
        ));
        resources.push(res(
            "aws_main_route_table_association.main",
            "aws_main_route_table_association",
            r#"{"id":"rtbassoc-main","vpc_id":"vpc-1","route_table_id":"rtb-main"}"#,
        ));
    } else {
        resources.push(res(
            "aws_default_route_table.main",
            "aws_default_route_table",
            &format!(
                r#"{{"id":"rtb-default","vpc_id":"vpc-1","default_route_table_id":"rtb-default","route":{nat_route}}}"#
            ),
        ));
    }
    resources.extend_from_slice(extra);
    from_json(&state(&resources)).expect("parses")
}

#[test]
fn an_unassociated_subnet_uses_the_vpc_main_route_table() {
    for table in ["main", "default"] {
        assert_eq!(
            down(&main_table(table, &[]), az("us-east-1a")),
            set(&[
                "aws_instance.app_b",
                "aws_nat_gateway.main",
                "aws_subnet.public_a"
            ]),
            "{table}"
        );
    }
}

#[test]
fn an_association_to_a_table_helios_cannot_see_does_not_fall_back_to_the_main_table() {
    // private_b IS associated -- with a table outside this document. Its egress is unknown, not
    // the main table's NAT.
    let g = main_table("main", &[assoc("private_b", "external")]);
    assert_eq!(
        down(&g, az("us-east-1a")),
        set(&["aws_nat_gateway.main", "aws_subnet.public_a"])
    );
}

#[test]
fn in_a_plan_the_default_route_table_is_found_through_its_reference() {
    // `vpc_id` of an aws_default_route_table is unknown before apply; its configuration's
    // `default_route_table_id = aws_vpc.main.default_route_table_id` says which VPC it is.
    let plan = r#"{
      "format_version": "1.2",
      "planned_values": {"root_module": {"resources": [
        {"address": "aws_vpc.main", "mode": "managed", "type": "aws_vpc", "name": "main", "values": {}},
        {"address": "aws_subnet.private_b", "mode": "managed", "type": "aws_subnet",
         "name": "private_b", "values": {"availability_zone": "us-east-1b"}},
        {"address": "aws_subnet.public_a", "mode": "managed", "type": "aws_subnet",
         "name": "public_a", "values": {"availability_zone": "us-east-1a"}},
        {"address": "aws_nat_gateway.main", "mode": "managed", "type": "aws_nat_gateway",
         "name": "main", "values": {}},
        {"address": "aws_default_route_table.main", "mode": "managed",
         "type": "aws_default_route_table", "name": "main",
         "values": {"route": [{"cidr_block": "0.0.0.0/0"}]}},
        {"address": "aws_instance.app_b", "mode": "managed", "type": "aws_instance",
         "name": "app_b", "values": {}}
      ]}},
      "configuration": {"root_module": {"resources": [
        {"address": "aws_subnet.private_b", "mode": "managed", "type": "aws_subnet",
         "name": "private_b", "expressions": {"vpc_id": {"references": ["aws_vpc.main.id", "aws_vpc.main"]}}},
        {"address": "aws_nat_gateway.main", "mode": "managed", "type": "aws_nat_gateway",
         "name": "main", "expressions": {"subnet_id": {"references": ["aws_subnet.public_a.id", "aws_subnet.public_a"]}}},
        {"address": "aws_default_route_table.main", "mode": "managed",
         "type": "aws_default_route_table", "name": "main", "expressions": {
           "default_route_table_id": {"references": ["aws_vpc.main.default_route_table_id", "aws_vpc.main"]},
           "route": {"references": ["aws_nat_gateway.main.id", "aws_nat_gateway.main"]}}},
        {"address": "aws_instance.app_b", "mode": "managed", "type": "aws_instance",
         "name": "app_b", "expressions": {"subnet_id": {"references": ["aws_subnet.private_b.id", "aws_subnet.private_b"]}}}
      ]}}
    }"#;
    let g = from_json(plan).expect("parses");
    assert_eq!(
        down(&g, az("us-east-1a")),
        set(&[
            "aws_instance.app_b",
            "aws_nat_gateway.main",
            "aws_subnet.public_a"
        ])
    );
}

#[test]
fn a_cycle_only_an_over_connected_association_closes_is_dropped_not_fatal() {
    // One association (no count) whose `subnet_id` references the whole `aws_subnet.all` block:
    // rule 3 links it to BOTH subnets, including all[0] where the NAT lives -- a cycle that exists
    // only because of the guess. It is dropped with a warning; all[1] keeps its egress edge.
    let plan = r#"{
      "format_version": "1.2",
      "planned_values": {"root_module": {"resources": [
        {"address": "aws_subnet.all[0]", "mode": "managed", "type": "aws_subnet", "name": "all",
         "index": 0, "values": {"availability_zone": "us-east-1a"}},
        {"address": "aws_subnet.all[1]", "mode": "managed", "type": "aws_subnet", "name": "all",
         "index": 1, "values": {"availability_zone": "us-east-1b"}},
        {"address": "aws_nat_gateway.n", "mode": "managed", "type": "aws_nat_gateway",
         "name": "n", "values": {}},
        {"address": "aws_route_table.r", "mode": "managed", "type": "aws_route_table", "name": "r",
         "values": {"route": [{"cidr_block": "0.0.0.0/0"}]}},
        {"address": "aws_route_table_association.x", "mode": "managed",
         "type": "aws_route_table_association", "name": "x", "values": {}},
        {"address": "aws_instance.app", "mode": "managed", "type": "aws_instance", "name": "app",
         "values": {"availability_zone": "us-east-1b"}}
      ]}},
      "configuration": {"root_module": {"resources": [
        {"address": "aws_nat_gateway.n", "mode": "managed", "type": "aws_nat_gateway", "name": "n",
         "expressions": {"subnet_id": {"references": ["aws_subnet.all[0].id", "aws_subnet.all[0]", "aws_subnet.all"]}}},
        {"address": "aws_route_table.r", "mode": "managed", "type": "aws_route_table", "name": "r",
         "expressions": {"route": {"references": ["aws_nat_gateway.n.id", "aws_nat_gateway.n"]}}},
        {"address": "aws_route_table_association.x", "mode": "managed",
         "type": "aws_route_table_association", "name": "x", "expressions": {
           "subnet_id": {"references": ["aws_subnet.all"]},
           "route_table_id": {"references": ["aws_route_table.r.id", "aws_route_table.r"]}}},
        {"address": "aws_instance.app", "mode": "managed", "type": "aws_instance", "name": "app",
         "expressions": {"subnet_id": {"references": ["aws_subnet.all[1].id", "aws_subnet.all[1]", "aws_subnet.all"]}}}
      ]}}
    }"#;
    let g = from_json(plan).expect("an over-connected cycle must not abort");
    assert_eq!(
        down(&g, az("us-east-1a")),
        set(&["aws_instance.app", "aws_nat_gateway.n", "aws_subnet.all[0]"])
    );
}

#[test]
fn an_instance_in_a_subnet_that_is_itself_down_is_explained_by_the_subnet_first() {
    // app[0] has no zone of its own; its subnet private[0] is in 1a, and so is its NAT. The
    // subnet being down is the reason, not the NAT.
    let g = from_json(PER_AZ_PLAN).expect("parses");
    let reasons = run(&g, az("us-east-1a"));
    let (_, why) = reasons
        .iter()
        .find(|(id, _)| id == "aws_instance.app[0]")
        .expect("app[0] down");
    assert_eq!(why, "its subnet_id aws_subnet.private[0] is down");
}
