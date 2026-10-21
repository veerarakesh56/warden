//! What the engine returns to the CLI and to the AI shell.

use serde::{Deserialize, Serialize};

/// One resource that went down under the scenario.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FailedResource {
    /// Terraform address, e.g. `aws_instance.web`.
    pub id: String,
    /// Resource kind name, e.g. `Instance`.
    pub kind: String,
    /// One-line explanation: "single-AZ in us-east-1a, which is down".
    pub reason: String,
}

/// The full engine verdict: which scenario was run and which resources fell.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct FailureChain {
    pub scenario: String,
    pub failures: Vec<FailedResource>,
}

impl FailureChain {
    pub fn is_safe(&self) -> bool {
        self.failures.is_empty()
    }

    /// Plain-text rendering. One line per failure. Colors live in the CLI.
    pub fn render_plain(&self) -> String {
        let mut out = format!("Scenario: {}\n", self.scenario);
        if self.failures.is_empty() {
            out.push_str("No failures — configuration is resilient.\n");
            return out;
        }
        out.push_str(&format!("{} resource(s) impacted:\n", self.failures.len()));
        for f in &self.failures {
            out.push_str(&format!("  - {} ({}): {}\n", f.id, f.kind, f.reason));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_chain_renders_safe_message() {
        let c = FailureChain {
            scenario: "lose-us-east-1a".into(),
            failures: vec![],
        };
        assert!(c.is_safe());
        let out = c.render_plain();
        assert!(out.contains("No failures"));
    }

    #[test]
    fn populated_chain_lists_every_failure() {
        let c = FailureChain {
            scenario: "lose-us-east-1a".into(),
            failures: vec![
                FailedResource {
                    id: "aws_instance.web".into(),
                    kind: "Instance".into(),
                    reason: "single-AZ in us-east-1a".into(),
                },
                FailedResource {
                    id: "aws_subnet.public_a".into(),
                    kind: "Subnet".into(),
                    reason: "lives in us-east-1a".into(),
                },
            ],
        };
        assert!(!c.is_safe());
        let out = c.render_plain();
        assert!(out.contains("2 resource(s) impacted"));
        assert!(out.contains("aws_instance.web"));
        assert!(out.contains("aws_subnet.public_a"));
    }
}
