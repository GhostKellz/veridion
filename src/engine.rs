//! The Veridion facade: one object that ties policy, risk, approval, and audit
//! together.
//!
//! [`Veridion`] is what an agent runtime holds. Call [`Veridion::evaluate`] for a
//! pure, side-effect-free decision, or [`Veridion::authorize`] to run the full
//! workflow: evaluate the request, resolve any required approval, write an audit
//! record, and report whether the action may proceed.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::action::ActionRequest;
use crate::approval::{ApprovalOutcome, ApprovalWorkflow};
use crate::audit::{AuditError, AuditLog, AuditRecord};
use crate::config::Config;
use crate::decision::{ActionDecision, Effect};
use crate::policy::{PolicyEngine, PolicyError};

/// The outcome of a full [`Veridion::authorize`] call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    /// The policy decision.
    pub decision: ActionDecision,
    /// How approval resolved, when the decision required it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<ApprovalOutcome>,
    /// Whether the action may proceed after policy and approval.
    pub permitted: bool,
}

/// Policy engine, approval workflow, and audit log wired together.
pub struct Veridion {
    policy: PolicyEngine,
    approval: ApprovalWorkflow,
    audit: AuditLog,
}

impl Veridion {
    /// Assemble from explicit parts (useful in tests and embedding).
    pub fn new(policy: PolicyEngine, approval: ApprovalWorkflow, audit: AuditLog) -> Self {
        Self {
            policy,
            approval,
            audit,
        }
    }

    /// Build the whole stack from configuration.
    pub async fn from_config(config: &Config) -> Result<Self, VeridionError> {
        let policy = PolicyEngine::from_config(config)?;
        let approval = ApprovalWorkflow::from_config(&config.approval);
        let audit = AuditLog::from_config(&config.audit).await?;
        Ok(Self::new(policy, approval, audit))
    }

    /// A pure decision: no approval, no audit, no side effects.
    pub fn evaluate(&self, request: &ActionRequest) -> ActionDecision {
        self.policy.evaluate(request)
    }

    /// The full workflow: evaluate, resolve approval if required, audit, and
    /// report whether the action may proceed.
    pub async fn authorize(&self, request: &ActionRequest) -> Result<Authorization, VeridionError> {
        let decision = self.policy.evaluate(request);
        let mut record = AuditRecord::from_decision(request, &decision);

        let approval = if decision.needs_approval() {
            let outcome = self.approval.resolve(request, &decision);
            record = record.with_approval(outcome);
            Some(outcome)
        } else {
            None
        };

        self.audit.record(&record).await?;

        let permitted = match decision.effect {
            Effect::Allow => true,
            Effect::Deny => false,
            Effect::RequireApproval => approval.is_some_and(ApprovalOutcome::is_approved),
        };

        Ok(Authorization {
            decision,
            approval,
            permitted,
        })
    }

    /// The policy engine, for reloads and inspection.
    pub fn policy(&self) -> &PolicyEngine {
        &self.policy
    }

    /// The audit log, for querying recent decisions.
    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }
}

/// Errors from building or running the engine.
#[derive(Debug, Error)]
pub enum VeridionError {
    /// Policy loading or compilation failed.
    #[error(transparent)]
    Policy(#[from] PolicyError),
    /// The audit log could not be opened or written.
    #[error(transparent)]
    Audit(#[from] AuditError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::actions;
    use crate::approval::ApprovalWorkflow;
    use crate::policy::{PolicyEngine, RuleEffect};
    use crate::risk::RiskEngine;

    fn veridion(default: RuleEffect, approval: ApprovalWorkflow) -> Veridion {
        let policy =
            PolicyEngine::with_rules(default, vec![], RiskEngine::empty(), None).expect("engine");
        Veridion::new(policy, approval, AuditLog::memory())
    }

    #[tokio::test]
    async fn allow_is_permitted_and_audited() {
        let v = veridion(RuleEffect::Allow, ApprovalWorkflow::auto_deny());
        let req = ActionRequest::new(actions::FS_READ, "src/lib.rs");
        let auth = v.authorize(&req).await.expect("authorize");
        assert!(auth.permitted);
        assert_eq!(auth.decision.effect, Effect::Allow);
        assert_eq!(v.audit().recent(1).await.expect("recent").len(), 1);
    }

    #[tokio::test]
    async fn deny_is_not_permitted() {
        let v = veridion(RuleEffect::Deny, ApprovalWorkflow::auto_deny());
        let req = ActionRequest::new(actions::EXEC, "curl evil.example");
        let auth = v.authorize(&req).await.expect("authorize");
        assert!(!auth.permitted);
        assert_eq!(auth.decision.effect, Effect::Deny);
    }

    #[tokio::test]
    async fn require_approval_respects_approver() {
        let approved = veridion(
            RuleEffect::RequireApproval,
            ApprovalWorkflow::auto_approve(),
        );
        let req = ActionRequest::new(actions::EXEC, "git push");
        let auth = approved.authorize(&req).await.expect("authorize");
        assert!(auth.permitted);
        assert_eq!(auth.approval, Some(ApprovalOutcome::Approved));

        let denied = veridion(RuleEffect::RequireApproval, ApprovalWorkflow::auto_deny());
        let auth = denied.authorize(&req).await.expect("authorize");
        assert!(!auth.permitted);
        assert_eq!(auth.approval, Some(ApprovalOutcome::Denied));
    }
}
