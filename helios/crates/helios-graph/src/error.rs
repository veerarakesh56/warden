use std::path::PathBuf;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("failed to read {path}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse terraform JSON: {0}")]
    Parse(#[from] serde_json::Error),

    #[error("unknown resource type {0} (extend ResourceKind to support it)")]
    UnknownResourceType(String),

    #[error(
        "not a `terraform show -json` document: it has neither `values` (from `terraform show -json` \
         on a state) nor `planned_values` (from `terraform show -json <planfile>`)"
    )]
    NotTerraformJson,

    /// The edges a resource's `down` reads (`Contains`, `Spread`, an ALB's `subnets`, a Lambda's
    /// `subnet_ids`) formed a cycle of exact edges, so "is it down" has no unique answer.
    #[error("dependency cycle through failure-propagating edges: {}", .0.join(" -> "))]
    DependencyCycle(Vec<String>),
}
