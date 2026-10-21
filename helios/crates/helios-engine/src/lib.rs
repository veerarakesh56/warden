//! Z3-powered simulation core.

pub mod fix;
pub mod inspect;
pub mod report;
pub mod scenario;
pub mod simulate;
pub mod smt;
pub mod verify;

pub use fix::{apply_fix, FixEdit, FixError, FixProposal};
pub use inspect::{
    build_inspect, scrub_resource, scrub_sensitive_attrs, DepDoc, EdgeDoc, GraphDoc, InspectDoc,
    NodeDoc, REDACTED,
};
pub use report::{FailedResource, FailureChain};
pub use scenario::{Scenario, ScenarioError, ScenarioKind};
pub use simulate::{simulate, SimulateError};
pub use verify::{standard_scenarios, verify, ScenarioDiff, Verdict, VerifyError, VerifyReport};
