//! Minimal typed mirror of `terraform show -json` output, for a state or a saved plan.
//!
//! Only the subset helios-graph actually reads. Schema reference:
//! <https://developer.hashicorp.com/terraform/internals/json-format>

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

/// A state document carries `values`; a plan document carries `planned_values` (unknown-until-apply
/// attributes omitted) and `configuration` (each attribute's references).
#[derive(Deserialize, Debug)]
pub struct TerraformShow {
    pub values: Option<Values>,
    pub planned_values: Option<Values>,
    pub configuration: Option<Configuration>,
}

#[derive(Deserialize, Debug)]
pub struct Values {
    pub root_module: Module,
}

#[derive(Deserialize, Debug, Default)]
pub struct Module {
    #[serde(default)]
    pub resources: Vec<RawResource>,
    #[serde(default)]
    pub child_modules: Vec<Module>,
}

/// A single resource entry from the `resources` array. The `values` field is service-specific;
/// we keep it opaque here and let each `Resource` variant deserialize its own slice.
#[derive(Deserialize, Debug)]
pub struct RawResource {
    pub address: String,
    #[serde(rename = "type")]
    pub tf_type: String,
    /// `"managed"` for real infrastructure, `"data"` for a data source. Terraform always emits it;
    /// it defaults here so hand-written fixtures stay valid. A data source of a modelled type
    /// (`data.aws_subnet.selected`) must NOT be treated as infrastructure that can fail.
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default)]
    pub values: Value,
    /// Terraform's mask of which `values` are sensitive (`true` at each sensitive path). Present in
    /// state and plan documents alike; a hand-written fixture may omit it.
    #[serde(default)]
    pub sensitive_values: Value,
}

fn default_mode() -> String {
    "managed".to_string()
}

impl Module {
    /// Flatten `root_module` + `child_modules` recursively into a single vec of resources.
    pub fn flatten(self) -> Vec<RawResource> {
        let Module {
            mut resources,
            child_modules,
        } = self;
        for child in child_modules {
            resources.extend(child.flatten());
        }
        resources
    }
}

#[derive(Deserialize, Debug)]
pub struct Configuration {
    pub root_module: ConfigModule,
    /// `aws`, `aws.west`, ...: each provider block, whose `region` is the region of every resource
    /// that uses it -- the one region signal a plan has before any ARN exists.
    #[serde(default)]
    pub provider_config: HashMap<String, ProviderConfig>,
}

#[derive(Deserialize, Debug)]
pub struct ProviderConfig {
    #[serde(default)]
    pub expressions: Value,
}

impl Configuration {
    /// Provider config key -> its constant `region`, where it has one.
    pub fn provider_regions(&self) -> HashMap<String, String> {
        self.provider_config
            .iter()
            .filter_map(|(key, p)| {
                let region = p
                    .expressions
                    .get("region")?
                    .get("constant_value")?
                    .as_str()?;
                Some((key.clone(), region.to_string()))
            })
            .collect()
    }
}

#[derive(Deserialize, Debug, Default)]
pub struct ConfigModule {
    #[serde(default)]
    pub resources: Vec<ConfigResource>,
    #[serde(default)]
    pub module_calls: HashMap<String, ModuleCall>,
}

#[derive(Deserialize, Debug)]
pub struct ModuleCall {
    #[serde(default)]
    pub module: ConfigModule,
}

/// One `resource` block. Its `address` is relative to its module and has no instance index.
#[derive(Deserialize, Debug)]
pub struct ConfigResource {
    pub address: String,
    #[serde(default)]
    pub expressions: Value,
    #[serde(default)]
    pub provider_config_key: Option<String>,
}

impl ConfigModule {
    /// Every resource block's expressions, keyed by config address with its module path
    /// (`module.net.aws_subnet.a`): what a planned address becomes with its indices stripped.
    /// Also each block's provider region, from `providers` (see
    /// [`Configuration::provider_regions`]), under the same key.
    pub fn expressions(
        self,
        prefix: &str,
        providers: &HashMap<String, String>,
        out: &mut HashMap<String, Value>,
        regions: &mut HashMap<String, String>,
    ) {
        for r in self.resources {
            let address = format!("{prefix}{}", r.address);
            // A module's key reads `module.x:aws`; its provider is then the root's `aws`.
            let region = r.provider_config_key.as_deref().and_then(|k| {
                providers
                    .get(k)
                    .or_else(|| providers.get(k.rsplit(':').next()?))
            });
            if let Some(region) = region {
                regions.insert(address.clone(), region.clone());
            }
            out.insert(address, r.expressions);
        }
        for (name, call) in self.module_calls {
            call.module
                .expressions(&format!("{prefix}module.{name}."), providers, out, regions);
        }
    }
}
