//! Approval workflow for actions the policy engine escalates.
//!
//! When [`PolicyEngine::evaluate`](crate::policy::PolicyEngine::evaluate)
//! returns [`Effect::RequireApproval`](crate::decision::Effect::RequireApproval),
//! the action may proceed only if an [`Approver`] says so. The
//! [`ApprovalWorkflow`] wraps a chosen approver and turns a request-plus-decision
//! into an [`ApprovalOutcome`].
//!
//! Built-in approvers cover the common cases: [`AutoDeny`] (safe headless
//! default), [`AutoApprove`] (dev only), and [`StdinApprover`] (prompt on the
//! terminal). Embedders can supply their own by implementing [`Approver`].

use std::io::{self, Write};

use serde::{Deserialize, Serialize};

use crate::action::ActionRequest;
use crate::config::{ApprovalConfig, ApprovalMode};
use crate::decision::ActionDecision;

/// The result of asking for approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalOutcome {
    /// The action was approved and may proceed.
    Approved,
    /// The action was refused.
    Denied,
}

impl ApprovalOutcome {
    /// Whether the outcome permits the action.
    pub fn is_approved(self) -> bool {
        matches!(self, ApprovalOutcome::Approved)
    }
}

impl std::fmt::Display for ApprovalOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            ApprovalOutcome::Approved => "approved",
            ApprovalOutcome::Denied => "denied",
        };
        f.write_str(text)
    }
}

/// Decides whether an action that requires approval may proceed.
pub trait Approver: Send + Sync {
    /// Resolve the approval for `request` given its `decision`.
    fn approve(&self, request: &ActionRequest, decision: &ActionDecision) -> ApprovalOutcome;
}

/// Refuses everything (the safe default for unattended runs).
pub struct AutoDeny;

impl Approver for AutoDeny {
    fn approve(&self, _request: &ActionRequest, _decision: &ActionDecision) -> ApprovalOutcome {
        ApprovalOutcome::Denied
    }
}

/// Approves everything (dangerous; development only).
pub struct AutoApprove;

impl Approver for AutoApprove {
    fn approve(&self, _request: &ActionRequest, _decision: &ActionDecision) -> ApprovalOutcome {
        ApprovalOutcome::Approved
    }
}

/// Prompts on the terminal and reads a yes/no answer from stdin.
pub struct StdinApprover;

impl Approver for StdinApprover {
    fn approve(&self, request: &ActionRequest, decision: &ActionDecision) -> ApprovalOutcome {
        let mut stderr = io::stderr();
        let _ = writeln!(
            stderr,
            "approval required: {} on '{}' (risk {}) — {}",
            request.action, request.resource, decision.risk.value, decision.reason
        );
        let _ = write!(stderr, "approve? [y/N] ");
        let _ = stderr.flush();

        let mut answer = String::new();
        match io::stdin().read_line(&mut answer) {
            Ok(_) => {
                let a = answer.trim().to_lowercase();
                if a == "y" || a == "yes" {
                    ApprovalOutcome::Approved
                } else {
                    ApprovalOutcome::Denied
                }
            }
            Err(_) => ApprovalOutcome::Denied,
        }
    }
}

/// Resolves approvals through a chosen [`Approver`].
pub struct ApprovalWorkflow {
    approver: Box<dyn Approver>,
}

impl ApprovalWorkflow {
    /// Wrap an arbitrary approver.
    pub fn new(approver: Box<dyn Approver>) -> Self {
        Self { approver }
    }

    /// Refuse anything that needs approval.
    pub fn auto_deny() -> Self {
        Self::new(Box::new(AutoDeny))
    }

    /// Approve anything that needs approval (dev only).
    pub fn auto_approve() -> Self {
        Self::new(Box::new(AutoApprove))
    }

    /// Prompt on the terminal for each approval.
    pub fn interactive() -> Self {
        Self::new(Box::new(StdinApprover))
    }

    /// Build a workflow from configuration.
    pub fn from_config(config: &ApprovalConfig) -> Self {
        match config.default {
            ApprovalMode::Deny => Self::auto_deny(),
            ApprovalMode::Allow => Self::auto_approve(),
            ApprovalMode::Interactive => Self::interactive(),
        }
    }

    /// Ask the approver to resolve this decision.
    pub fn resolve(&self, request: &ActionRequest, decision: &ActionDecision) -> ApprovalOutcome {
        self.approver.approve(request, decision)
    }
}

impl Default for ApprovalWorkflow {
    fn default() -> Self {
        Self::auto_deny()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::actions;

    #[test]
    fn auto_deny_denies() {
        let workflow = ApprovalWorkflow::auto_deny();
        let req = ActionRequest::new(actions::EXEC, "rm -rf build");
        let decision = ActionDecision::require_approval("needs review");
        assert_eq!(workflow.resolve(&req, &decision), ApprovalOutcome::Denied);
    }

    #[test]
    fn auto_approve_approves() {
        let workflow = ApprovalWorkflow::auto_approve();
        let req = ActionRequest::new(actions::EXEC, "rm -rf build");
        let decision = ActionDecision::require_approval("needs review");
        assert_eq!(workflow.resolve(&req, &decision), ApprovalOutcome::Approved);
    }
}
