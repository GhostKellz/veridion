//! Veridion — a policy authorization layer for AI agent actions.
//!
//! *OPA meets sudo meets AI safety.* An agent that is about to do something
//! consequential describes its intent as an [`ActionRequest`] and asks Veridion
//! whether it may proceed. Veridion answers with an [`ActionDecision`]: allow,
//! deny, or require approval — backed by ordered [`PolicyEngine`] rules, a
//! non-overridable deny floor, a [`RiskScore`], an [`ApprovalWorkflow`], and an
//! [`AuditLog`].
//!
//! ```no_run
//! use veridion::{Config, Veridion};
//! use veridion::action::{ActionRequest, Subject, actions};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let veridion = Veridion::from_config(&Config::default()).await?;
//!
//! let request = ActionRequest::new(actions::EXEC, "rm -rf /tmp/cache")
//!     .subject(Subject::new("jarvis").with_role("agent"))
//!     .attr("repo", "veridion");
//!
//! let auth = veridion.authorize(&request).await?;
//! if auth.permitted {
//!     // run the command
//! }
//! # Ok(())
//! # }
//! ```

pub mod action;
pub mod approval;
pub mod audit;
pub mod config;
pub mod decision;
pub mod engine;
pub mod policy;
pub mod risk;
pub mod telemetry;

pub use action::{ActionRequest, Context, Subject};
pub use approval::{ApprovalOutcome, ApprovalWorkflow, Approver};
pub use audit::{AuditLog, AuditRecord};
pub use config::Config;
pub use decision::{ActionDecision, Effect};
pub use engine::{Authorization, Veridion};
pub use policy::{PolicyEngine, PolicyRule};
pub use risk::{RiskLevel, RiskScore};
