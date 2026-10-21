//! Parses `terraform show -json` output — of a state, or of a saved plan — into a typed resource
//! graph.
//!
//! The public entry point is [`load`]. All other items in this module are building blocks.

use std::collections::HashMap;
use std::path::Path;

mod error;
mod resource;
mod tfjson;

pub use error::Error;
pub use resource::{
    Dependency, PendingPrincipal, Resource, ResourceId, ResourceKind, Skipped, PRINCIPAL_ATTRS,
};

/// A directed graph of typed AWS resources with dependency edges.
pub type ResourceGraph = petgraph::graph::DiGraph<Resource, Dependency>;

/// Which document the graph was read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// `terraform show -json` of a state: every attribute known.
    State,
    /// `terraform show -json <planfile>`: attributes unknown until apply are absent, and edges
    /// fall back to the configuration's references.
    Plan,
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Source::State => "state",
            Source::Plan => "plan",
        })
    }
}

/// Everything a load produces: the graph, which document it came from, and the resources of
/// unsupported types that are NOT in it.
#[derive(Clone, Debug)]
pub struct Loaded {
    pub graph: ResourceGraph,
    pub source: Source,
    /// One entry per unsupported type, most resources first.
    pub skipped: Vec<Skipped>,
}

/// Load a Terraform JSON file (or a directory containing `terraform-show.json`) and build the graph.
pub fn load<P: AsRef<Path>>(path: P) -> Result<ResourceGraph, Error> {
    load_full(path).map(|l| l.graph)
}

/// [`load`], also saying whether the document was a state or a plan.
pub fn load_with_source<P: AsRef<Path>>(path: P) -> Result<(ResourceGraph, Source), Error> {
    load_full(path).map(|l| (l.graph, l.source))
}

/// [`load`], with everything it found: see [`Loaded`].
pub fn load_full<P: AsRef<Path>>(path: P) -> Result<Loaded, Error> {
    let path = path.as_ref();
    let json_path = if path.is_dir() {
        path.join("terraform-show.json")
    } else {
        path.to_path_buf()
    };
    let raw = std::fs::read(&json_path)
        .and_then(decode_text)
        .map_err(|e| Error::ReadFile {
            path: json_path.clone(),
            source: e,
        })?;
    from_json_full(&raw)
}

/// Text as Windows writes it: UTF-8 with or without a byte-order mark, or UTF-16LE with one --
/// what `terraform show -json > plan.json` produces in Windows PowerShell 5.1.
pub fn decode_text(bytes: Vec<u8>) -> std::io::Result<String> {
    let invalid = |e: String| std::io::Error::new(std::io::ErrorKind::InvalidData, e);
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let (pairs, _odd_byte) = rest.as_chunks::<2>();
        let units: Vec<u16> = pairs.iter().map(|&p| u16::from_le_bytes(p)).collect();
        return String::from_utf16(&units).map_err(|e| invalid(e.to_string()));
    }
    let text = String::from_utf8(bytes).map_err(|e| invalid(e.to_string()))?;
    Ok(match text.strip_prefix('\u{feff}') {
        Some(rest) => rest.to_string(),
        None => text,
    })
}

/// Parse a raw Terraform JSON string into a resource graph.
pub fn from_json(raw: &str) -> Result<ResourceGraph, Error> {
    from_json_with_source(raw).map(|(graph, _)| graph)
}

/// [`from_json`], also saying whether the document was a state or a plan.
pub fn from_json_with_source(raw: &str) -> Result<(ResourceGraph, Source), Error> {
    from_json_full(raw).map(|l| (l.graph, l.source))
}

/// [`from_json`], with everything it found: see [`Loaded`].
pub fn from_json_full(raw: &str) -> Result<Loaded, Error> {
    let parsed: tfjson::TerraformShow = serde_json::from_str(raw)?;
    let (values, source) = match (parsed.values, parsed.planned_values) {
        (Some(v), _) => (v, Source::State),
        (None, Some(v)) => (v, Source::Plan),
        (None, None) => return Err(Error::NotTerraformJson),
    };
    let mut config = HashMap::new();
    let mut regions = HashMap::new();
    if let Some(c) = parsed.configuration {
        let providers = c.provider_regions();
        c.root_module
            .expressions("", &providers, &mut config, &mut regions);
    }
    let (graph, skipped) = resource::build_graph(values.root_module.flatten(), &config, &regions)?;
    Ok(Loaded {
        graph,
        source,
        skipped,
    })
}
