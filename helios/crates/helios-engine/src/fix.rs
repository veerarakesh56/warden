//! Fix proposals. Claude produces these via structured outputs;
//! the engine's [`apply_fix`] applies them to a graph clone and
//! [`crate::verify()`] re-runs simulate to confirm they resolve the chain.
//!
//! Only the `set_attr` op exists; adding or removing a resource is not implemented, and an edit
//! that would move one is refused ([`PLACEMENT_KEYS`]).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// A single edit inside a [`FixProposal`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum FixEdit {
    /// Set or overwrite a scalar/array attribute on an existing resource.
    SetAttr {
        resource_id: String,
        key: String,
        value: serde_json::Value,
    },
}

/// Typed mirror of `helios_ai.models.FixProposal` (Pydantic v2).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FixProposal {
    pub scenario_name: String,
    pub explanation: String,
    pub edits: Vec<FixEdit>,
}

#[derive(Debug, Error)]
pub enum FixError {
    #[error("read fix file {path:?}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("parse fix JSON: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("fix references unknown resource {0:?}")]
    UnknownResource(String),
    #[error("resource {0:?} has non-object attrs; cannot set key")]
    AttrsNotObject(String),
    /// Edges are derived once, from the input: an edit that moves a resource (its subnets, cluster,
    /// VPC, NAT, queue links) would change an attribute nothing reads again. Refused rather than
    /// "verified" as a fix that changed nothing.
    #[error(
        "{resource:?}: `{key}` places the resource (Helios builds its graph from it once, so the \
         edit would not move anything). Change the Terraform and re-run instead"
    )]
    PlacementKey { resource: String, key: String },
    #[error("{resource:?}: cannot set `{key}`: {why}")]
    Path {
        resource: String,
        key: String,
        why: String,
    },
}

/// The attributes the graph's edges are read from (`crates/helios-graph/src/resource.rs`), by
/// their first path segment. A test checks this against that file.
pub const PLACEMENT_KEYS: &[&str] = &[
    "cluster",
    "cluster_identifier",
    "cluster_name",
    "db_subnet_group_name",
    "event_source_arn",
    "nat_gateway_id",
    "network_configuration",
    "redrive_policy",
    "subnet_group_name",
    "subnet_id",
    "subnet_ids",
    "subnets",
    "vpc_config",
    "vpc_id",
];

/// One path segment: `name` or `name[3]`.
fn segment(s: &str) -> (&str, Option<usize>) {
    match s.strip_suffix(']').and_then(|s| s.split_once('[')) {
        Some((name, i)) => (name, i.parse().ok()),
        None => (s, None),
    }
}

/// Set `value` at a dotted path (`scaling_config.desired_size`, `scaling_config[0].desired_size`).
/// Stepping through a list with no index takes its first element: Terraform renders a block as a
/// one-element list, which is how the models read it (`helios_models::number_at`).
fn set_path(
    attrs: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: serde_json::Value,
) -> Result<(), String> {
    let parts: Vec<&str> = key.split('.').collect();
    let (last, parents) = parts.split_last().expect("split yields one part");
    let mut obj = attrs;
    for part in parents {
        let (name, index) = segment(part);
        let mut v = obj
            .get_mut(name)
            .ok_or_else(|| format!("`{name}` does not exist"))?;
        if let serde_json::Value::Array(items) = v {
            v = items
                .get_mut(index.unwrap_or(0))
                .ok_or_else(|| format!("`{part}` has no such element"))?;
        }
        obj = v
            .as_object_mut()
            .ok_or_else(|| format!("`{part}` is not a block"))?;
    }
    let (name, index) = segment(last);
    match index {
        None => {
            obj.insert(name.to_string(), value);
        }
        Some(i) => {
            let slot = obj
                .get_mut(name)
                .and_then(|v| v.as_array_mut())
                .and_then(|a| a.get_mut(i))
                .ok_or_else(|| format!("`{last}` has no such element"))?;
            *slot = value;
        }
    }
    Ok(())
}

/// Load a [`FixProposal`] from a JSON file on disk.
pub fn load(path: &Path) -> Result<FixProposal, FixError> {
    let raw = std::fs::read_to_string(path).map_err(|source| FixError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(serde_json::from_str(raw.trim_start_matches('\u{feff}'))?)
}

/// Apply a [`FixProposal`] to a clone of `graph` and return the patched graph.
///
/// The original graph is untouched. Only `set_attr` edits are supported in
/// here; unknown resources and non-object attrs surface as [`FixError`].
pub fn apply_fix(
    graph: &helios_graph::ResourceGraph,
    fix: &FixProposal,
) -> Result<helios_graph::ResourceGraph, FixError> {
    let mut patched = graph.clone();
    for edit in &fix.edits {
        match edit {
            FixEdit::SetAttr {
                resource_id,
                key,
                value,
            } => {
                let idx = patched
                    .node_indices()
                    .find(|i| &patched[*i].id == resource_id)
                    .ok_or_else(|| FixError::UnknownResource(resource_id.clone()))?;
                let root = segment(key.split('.').next().unwrap_or_default()).0;
                if PLACEMENT_KEYS.contains(&root) {
                    return Err(FixError::PlacementKey {
                        resource: resource_id.clone(),
                        key: key.clone(),
                    });
                }
                let obj = patched[idx]
                    .attrs
                    .as_object_mut()
                    .ok_or_else(|| FixError::AttrsNotObject(resource_id.clone()))?;
                set_path(obj, key, value.clone()).map_err(|why| FixError::Path {
                    resource: resource_id.clone(),
                    key: key.clone(),
                    why,
                })?;
            }
        }
    }
    Ok(patched)
}

#[cfg(test)]
mod tests {
    use super::*;
    use helios_graph::from_json;

    const FIXTURE: &str = include_str!("../../../fixtures/three-tier-webapp/terraform-show.json");

    #[test]
    fn fix_proposal_roundtrips_json() {
        let fix = FixProposal {
            scenario_name: "lose-us-east-1a".into(),
            explanation: "enable multi-az on rds".into(),
            edits: vec![FixEdit::SetAttr {
                resource_id: "aws_db_instance.main".into(),
                key: "multi_az".into(),
                value: serde_json::json!(true),
            }],
        };
        let s = serde_json::to_string(&fix).unwrap();
        let back: FixProposal = serde_json::from_str(&s).unwrap();
        assert_eq!(fix, back);
    }

    #[test]
    fn set_attr_serializes_with_snake_case_op() {
        let edit = FixEdit::SetAttr {
            resource_id: "aws_lb.web".into(),
            key: "availability_zones".into(),
            value: serde_json::json!(["us-east-1a", "us-east-1b"]),
        };
        let s = serde_json::to_string(&edit).unwrap();
        assert!(s.contains("\"op\":\"set_attr\""), "got: {s}");
    }

    #[test]
    fn load_missing_file_returns_read_error() {
        let p = std::path::Path::new("/nonexistent/fix.json");
        assert!(matches!(load(p), Err(FixError::Read { .. })));
    }

    #[test]
    fn apply_fix_overwrites_existing_attr() {
        let graph = from_json(FIXTURE).unwrap();
        let fix = FixProposal {
            scenario_name: "x".into(),
            explanation: "x".into(),
            edits: vec![FixEdit::SetAttr {
                resource_id: "aws_elasticache_cluster.cache".into(),
                key: "availability_zone".into(),
                value: serde_json::json!("us-east-1b"),
            }],
        };
        let patched = apply_fix(&graph, &fix).unwrap();
        let idx = patched
            .node_indices()
            .find(|i| patched[*i].id == "aws_elasticache_cluster.cache")
            .expect("fixture contains elasticache.cache");
        assert_eq!(
            patched[idx].attrs["availability_zone"],
            serde_json::json!("us-east-1b")
        );
    }

    #[test]
    fn apply_fix_inserts_new_attr() {
        let graph = from_json(FIXTURE).unwrap();
        let fix = FixProposal {
            scenario_name: "x".into(),
            explanation: "x".into(),
            edits: vec![FixEdit::SetAttr {
                resource_id: "aws_db_instance.primary".into(),
                key: "failover_seconds_max".into(),
                value: serde_json::json!(60),
            }],
        };
        let patched = apply_fix(&graph, &fix).unwrap();
        let idx = patched
            .node_indices()
            .find(|i| patched[*i].id == "aws_db_instance.primary")
            .unwrap();
        assert_eq!(
            patched[idx].attrs["failover_seconds_max"],
            serde_json::json!(60)
        );
    }

    #[test]
    fn apply_fix_leaves_original_graph_untouched() {
        let graph = from_json(FIXTURE).unwrap();
        let fix = FixProposal {
            scenario_name: "x".into(),
            explanation: "x".into(),
            edits: vec![FixEdit::SetAttr {
                resource_id: "aws_elasticache_cluster.cache".into(),
                key: "availability_zone".into(),
                value: serde_json::json!("us-east-1b"),
            }],
        };
        let _ = apply_fix(&graph, &fix).unwrap();
        let orig_idx = graph
            .node_indices()
            .find(|i| graph[*i].id == "aws_elasticache_cluster.cache")
            .unwrap();
        assert_eq!(
            graph[orig_idx].attrs["availability_zone"],
            serde_json::json!("us-east-1a"),
            "original graph must not be mutated"
        );
    }

    #[test]
    fn apply_fix_unknown_resource_errors() {
        let graph = from_json(FIXTURE).unwrap();
        let fix = FixProposal {
            scenario_name: "x".into(),
            explanation: "x".into(),
            edits: vec![FixEdit::SetAttr {
                resource_id: "aws_nope.ghost".into(),
                key: "foo".into(),
                value: serde_json::json!(1),
            }],
        };
        match apply_fix(&graph, &fix) {
            Err(FixError::UnknownResource(id)) => assert_eq!(id, "aws_nope.ghost"),
            other => panic!("expected UnknownResource, got {other:?}"),
        }
    }
}
