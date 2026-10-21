//! The attribute resolver: list-shaped blocks, type-checked matching.

use helios_graph::{from_json, Dependency};

fn state(resources: &str) -> String {
    format!(
        r#"{{"format_version":"1.0","values":{{"root_module":{{"resources":[{resources}]}}}}}}"#
    )
}

fn edges(json: &str) -> Vec<(String, String, String)> {
    let g = from_json(json).expect("parses");
    g.raw_edges()
        .iter()
        .map(|e| {
            let dep = match &e.weight {
                Dependency::Contains(v) => format!("Contains({v})"),
                other => format!("{other:?}"),
            };
            (g[e.source()].id.clone(), g[e.target()].id.clone(), dep)
        })
        .collect()
}

#[test]
fn list_form_vpc_config_yields_member_of_edges() {
    // Real state stores `vpc_config` as a one-element list; v0.1 read it as an object and the
    // Lambda had no edges at all.
    let json = state(
        r#"
        {"address":"aws_subnet.a","type":"aws_subnet","values":{"id":"subnet-a","availability_zone":"us-east-1a"}},
        {"address":"aws_subnet.b","type":"aws_subnet","values":{"id":"subnet-b","availability_zone":"us-east-1b"}},
        {"address":"aws_lambda_function.fn","type":"aws_lambda_function",
         "values":{"id":"fn","vpc_config":[{"subnet_ids":["subnet-a","subnet-b"]}]}}"#,
    );
    assert_eq!(
        edges(&json),
        vec![
            (
                "aws_lambda_function.fn".into(),
                "aws_subnet.a".into(),
                "MemberOf(\"subnet_ids\")".into()
            ),
            (
                "aws_lambda_function.fn".into(),
                "aws_subnet.b".into(),
                "MemberOf(\"subnet_ids\")".into()
            ),
        ]
    );
}

#[test]
fn a_value_shared_across_types_resolves_by_type() {
    // The VPC's id equals the subnet's id and comes LATER, so the v0.1 id-only map pointed the
    // instance at the VPC. Only an aws_subnet may satisfy `subnet_id`.
    let json = state(
        r#"
        {"address":"aws_subnet.a","type":"aws_subnet","values":{"id":"shared","availability_zone":"us-east-1a"}},
        {"address":"aws_vpc.v","type":"aws_vpc","values":{"id":"shared"}},
        {"address":"aws_instance.i","type":"aws_instance","values":{"id":"i-1","subnet_id":"shared","availability_zone":"us-east-1a"}}"#,
    );
    assert_eq!(
        edges(&json),
        vec![(
            "aws_instance.i".into(),
            "aws_subnet.a".into(),
            "Contains(subnet_id)".into()
        )]
    );
}
