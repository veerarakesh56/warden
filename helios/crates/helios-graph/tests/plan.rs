//! `terraform show -json <planfile>`: planned values with unknowns absent, edges from references.

use std::collections::BTreeSet;

use helios_graph::{from_json, from_json_with_source, Error, ResourceGraph, Source};

const STATE: &str = include_str!("../../../fixtures/wave4-synthetic/terraform-show.json");
const PLAN: &str = include_str!("../../../fixtures/wave4-synthetic/plan.json");

fn edges(g: &ResourceGraph) -> BTreeSet<(String, String, String)> {
    g.raw_edges()
        .iter()
        .map(|e| {
            (
                g[e.source()].id.clone(),
                g[e.target()].id.clone(),
                format!("{:?}", e.weight),
            )
        })
        .collect()
}

fn targets(g: &ResourceGraph, from: &str) -> BTreeSet<String> {
    edges(g)
        .into_iter()
        .filter(|(f, _, _)| f == from)
        .map(|(_, t, _)| t)
        .collect()
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| s.to_string()).collect()
}

#[test]
fn the_source_is_detected() {
    assert_eq!(from_json_with_source(STATE).unwrap().1, Source::State);
    assert_eq!(from_json_with_source(PLAN).unwrap().1, Source::Plan);
}

#[test]
fn a_document_with_neither_values_nor_planned_values_is_rejected() {
    let err = from_json(r#"{"format_version":"1.0"}"#).unwrap_err();
    assert!(matches!(err, Error::NotTerraformJson), "{err:?}");
    let msg = err.to_string();
    assert!(msg.contains("terraform show -json <planfile>") && msg.contains("on a state"));
}

#[test]
fn the_plan_graph_has_the_same_shape_as_the_state_graph_but_the_dynamic_blocks() {
    // No id and no ARN is known before the first apply; every edge below comes from the
    // configuration's references. The one difference is real: WARDEN's Lambdas declare
    // `dynamic "vpc_config"`, which the configuration JSON omits, so before apply nothing says
    // which subnets the in-VPC Lambdas use (a warning says so).
    let (state, plan) = (from_json(STATE).unwrap(), from_json(PLAN).unwrap());
    let ids = |g: &ResourceGraph| -> BTreeSet<String> {
        g.node_indices().map(|i| g[i].id.clone()).collect()
    };
    assert_eq!(ids(&plan), ids(&state));
    let mut want = edges(&state);
    want.retain(|(from, _, dep)| {
        !(from.starts_with("aws_lambda_function.") && dep == "MemberOf(\"subnet_ids\")")
    });
    assert_eq!(
        edges(&state).len() - want.len(),
        6,
        "three in-VPC Lambdas x two subnets"
    );
    assert_eq!(edges(&plan), want);
}

#[test]
fn rule_1_a_specific_instance_reference_names_only_that_instance() {
    // subnet_ids = [aws_subnet.private[0].id]: references also list `aws_subnet.private`.
    let g = from_json(PLAN).unwrap();
    assert_eq!(
        targets(&g, "aws_vpc_endpoint.interface[\"sqs\"]"),
        set(&["aws_subnet.private[0]"])
    );
}

#[test]
fn rule_2_each_key_pairs_the_same_key() {
    // redrive_policy = jsonencode({deadLetterTargetArn = aws_sqs_queue.dlq[each.key].arn})
    let g = from_json(PLAN).unwrap();
    assert_eq!(
        targets(&g, "aws_sqs_queue.main[\"orders\"]"),
        set(&["aws_sqs_queue.dlq[\"orders\"]"])
    );
}

#[test]
fn rule_3_a_splat_names_every_instance() {
    // subnets = aws_subnet.public[*].id
    let g = from_json(PLAN).unwrap();
    assert_eq!(
        targets(&g, "aws_lb.orders"),
        set(&["aws_subnet.public[0]", "aws_subnet.public[1]"])
    );
}

#[test]
fn a_known_empty_block_does_not_fall_back_to_the_shared_configuration() {
    // One `aws_lambda_function.fn` block, two instances: `out`'s planned `vpc_config` is [] (NOT
    // in the VPC, whatever the block's shared expressions say); `in`'s is unknown.
    let plan = r#"{
      "format_version": "1.2",
      "planned_values": {"root_module": {"resources": [
        {"address": "aws_subnet.s", "mode": "managed", "type": "aws_subnet", "name": "s",
         "values": {"availability_zone": "eu-west-1a"}},
        {"address": "aws_lambda_function.fn[\"out\"]", "mode": "managed",
         "type": "aws_lambda_function", "name": "fn", "index": "out", "values": {"vpc_config": []}},
        {"address": "aws_lambda_function.fn[\"in\"]", "mode": "managed",
         "type": "aws_lambda_function", "name": "fn", "index": "in", "values": {"vpc_config": [{}]}}
      ]}},
      "configuration": {"root_module": {"resources": [
        {"address": "aws_lambda_function.fn", "mode": "managed", "type": "aws_lambda_function",
         "name": "fn", "expressions": {"vpc_config": [{"subnet_ids": {"references": ["aws_subnet.s.id", "aws_subnet.s"]}}]}}
      ]}}
    }"#;
    let g = from_json(plan).unwrap();
    assert!(targets(&g, "aws_lambda_function.fn[\"out\"]").is_empty());
    assert_eq!(
        targets(&g, "aws_lambda_function.fn[\"in\"]"),
        set(&["aws_subnet.s"])
    );
}

#[test]
fn references_inside_a_module_instance_resolve_within_it() {
    let plan = r#"{
      "format_version": "1.2",
      "planned_values": {"root_module": {"child_modules": [{
        "address": "module.net[0]",
        "resources": [
          {"address": "module.net[0].aws_subnet.a[0]", "mode": "managed", "type": "aws_subnet",
           "name": "a", "index": 0, "values": {"availability_zone": "eu-west-1a"}},
          {"address": "module.net[0].aws_subnet.a[1]", "mode": "managed", "type": "aws_subnet",
           "name": "a", "index": 1, "values": {"availability_zone": "eu-west-1b"}},
          {"address": "module.net[0].aws_instance.web", "mode": "managed", "type": "aws_instance",
           "name": "web", "values": {"availability_zone": "eu-west-1b"}}
        ]}]}},
      "configuration": {"root_module": {"module_calls": {"net": {"module": {"resources": [
        {"address": "aws_subnet.a", "mode": "managed", "type": "aws_subnet", "name": "a",
         "expressions": {}},
        {"address": "aws_instance.web", "mode": "managed", "type": "aws_instance", "name": "web",
         "expressions": {"subnet_id": {"references": ["aws_subnet.a[1].id", "aws_subnet.a[1]",
                                                      "aws_subnet.a"]}}}
      ]}}}}}
    }"#;
    let g = from_json(plan).unwrap();
    assert_eq!(
        targets(&g, "module.net[0].aws_instance.web"),
        set(&["module.net[0].aws_subnet.a[1]"])
    );
}

#[test]
fn an_index_that_is_not_plain_count_index_links_every_instance() {
    // Four instances over two subnets: `subnet_id = aws_subnet.a[count.index % 2].id`. Terraform
    // records the same references as for `[count.index]`, so pairing [1] with a[1] -- and [3]
    // with a subnet that does not exist -- would be a guess. The counts differ: link all (worst
    // case). With equal counts the pairing stands.
    let instance = |i: u32| {
        format!(
            r#"{{"address":"aws_instance.web[{i}]","mode":"managed","type":"aws_instance",
                "name":"web","index":{i},"values":{{"availability_zone":"eu-west-1a"}}}}"#
        )
    };
    let subnet = |i: u32| {
        format!(
            r#"{{"address":"aws_subnet.a[{i}]","mode":"managed","type":"aws_subnet",
                "name":"a","index":{i},"values":{{"availability_zone":"eu-west-1a"}}}}"#
        )
    };
    let doc = |instances: u32| {
        let resources: Vec<String> = (0..2)
            .map(subnet)
            .chain((0..instances).map(instance))
            .collect();
        format!(
            r#"{{"format_version":"1.2",
                "planned_values":{{"root_module":{{"resources":[{}]}}}},
                "configuration":{{"root_module":{{"resources":[
                  {{"address":"aws_subnet.a","mode":"managed","type":"aws_subnet","name":"a"}},
                  {{"address":"aws_instance.web","mode":"managed","type":"aws_instance",
                    "name":"web","expressions":{{"subnet_id":{{"references":
                      ["aws_subnet.a","count.index"]}}}}}}]}}}}}}"#,
            resources.join(",")
        )
    };
    let g = from_json(&doc(4)).unwrap();
    for i in [1, 3] {
        assert_eq!(
            targets(&g, &format!("aws_instance.web[{i}]")),
            set(&["aws_subnet.a[0]", "aws_subnet.a[1]"])
        );
    }
    let g = from_json(&doc(2)).unwrap();
    assert_eq!(
        targets(&g, "aws_instance.web[1]"),
        set(&["aws_subnet.a[1]"])
    );
}

#[test]
fn a_role_through_each_value_is_opaque() {
    // `role = each.value.role_arn` next to a real role: `each.value` is whatever the for_each map
    // holds -- not followable, so the principal may be something else.
    let plan = r#"{
      "format_version": "1.2",
      "planned_values": {"root_module": {"resources": [
        {"address": "aws_lambda_function.f[\"x\"]", "mode": "managed", "type": "aws_lambda_function",
         "name": "f", "index": "x", "values": {"function_name": "x"}},
        {"address": "aws_iam_role.l", "mode": "managed", "type": "aws_iam_role", "name": "l",
         "values": {"name": "l"}}
      ]}},
      "configuration": {"root_module": {"resources": [
        {"address": "aws_lambda_function.f", "mode": "managed", "type": "aws_lambda_function",
         "name": "f", "expressions": {"role": {"references":
           ["each.value.role_arn", "each.value", "aws_iam_role.l.arn", "aws_iam_role.l"]}}}
      ]}}
    }"#;
    let g = from_json(plan).unwrap();
    let f = g
        .node_indices()
        .find(|&i| g[i].id == "aws_lambda_function.f[\"x\"]")
        .unwrap();
    let pending = &g[f].pending_principals;
    assert_eq!(pending.len(), 1);
    assert!(pending[0].opaque, "{pending:?}");
    assert!(pending[0].roles.contains(&"aws_iam_role.l".to_string()));
}

#[test]
fn an_unknown_egress_is_recorded_only_where_compute_runs() {
    // vpc-plan-foreach: every association is unresolvable and the candidate tables disagree, but
    // only the private subnets hold compute (the ECS service, the Lambda, the worker); the public
    // ones hold the ALB and the NATs. Only the private subnets' egress matters.
    let g = from_json(include_str!(
        "../../../fixtures/edge-cases/vpc-plan-foreach.json"
    ))
    .unwrap();
    for i in g
        .node_indices()
        .filter(|&i| g[i].id.starts_with("aws_subnet."))
    {
        let unknown = g[i]
            .unresolved
            .iter()
            .any(|w| w.starts_with("egress unknown"));
        assert_eq!(
            unknown,
            g[i].id.starts_with("aws_subnet.private"),
            "{}: {:?}",
            g[i].id,
            g[i].unresolved
        );
    }
}

#[test]
fn a_file_written_by_windows_powershell_loads_like_the_plain_one() {
    // `terraform show -json > x.json` in Windows PowerShell 5.1 writes UTF-16LE with a BOM;
    // `Out-File -Encoding utf8` writes UTF-8 with one. Both used to fail as "not UTF-8" / "not JSON".
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let plain = root.join("three-tier-webapp/terraform-show.json");
    let text = std::fs::read_to_string(&plain).expect("fixture");
    let dir = std::env::temp_dir().join(format!("helios-bom-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let utf16: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain(text.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    let utf8_bom: Vec<u8> = "\u{feff}".bytes().chain(text.bytes()).collect();
    let want = edges(&helios_graph::load(&plain).expect("plain"));
    for (name, bytes) in [("utf16.json", utf16), ("utf8bom.json", utf8_bom)] {
        let p = dir.join(name);
        std::fs::write(&p, bytes).expect("write");
        let got = helios_graph::load(&p).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(edges(&got), want, "{name}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
