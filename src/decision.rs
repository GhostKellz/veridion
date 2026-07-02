//! The outcome of authorizing an action: an [`ActionDecision`].
//!
//! A decision carries the [`Effect`] (allow, deny, or require approval), a
//! human-readable `reason`, the rule that produced it (if any), and the
//! [`RiskScore`](crate::risk::RiskScore) computed for the request.

use serde::{Deserialize, Serialize};

use crate::risk::RiskScore;

/// What the policy engine decided should happen to an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// The action may proceed.
    Allow,
    /// The action is refused outright.
    Deny,
    /// The action needs explicit approval before it may proceed.
    RequireApproval,
}

impl Effect {
    /// Whether this effect permits the action without further steps.
    pub fn is_allow(self) -> bool {
        matches!(self, Effect::Allow)
    }
}

impl std::fmt::Display for Effect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Effect::Allow => "allow",
            Effect::Deny => "deny",
            Effect::RequireApproval => "require_approval",
        };
        f.write_str(text)
    }
}

/// A reference to the policy rule that produced a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleRef {
    /// The rule's name.
    pub name: String,
    /// The rule's description, if it had one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl RuleRef {
    /// Create a rule reference.
    pub fn new(name: impl Into<String>, description: Option<String>) -> Self {
        Self {
            name: name.into(),
            description,
        }
    }
}

/// The result of evaluating an [`ActionRequest`](crate::action::ActionRequest).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionDecision {
    /// The decided effect.
    pub effect: Effect,
    /// Why the engine decided this way.
    pub reason: String,
    /// The rule that matched, or `None` when the default effect was applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<RuleRef>,
    /// The risk computed for the request.
    pub risk: RiskScore,
}

impl ActionDecision {
    /// An allow decision with the given reason.
    pub fn allow(reason: impl Into<String>) -> Self {
        Self::new(Effect::Allow, reason)
    }

    /// A deny decision with the given reason.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self::new(Effect::Deny, reason)
    }

    /// A require-approval decision with the given reason.
    pub fn require_approval(reason: impl Into<String>) -> Self {
        Self::new(Effect::RequireApproval, reason)
    }

    fn new(effect: Effect, reason: impl Into<String>) -> Self {
        Self {
            effect,
            reason: reason.into(),
            matched_rule: None,
            risk: RiskScore::default(),
        }
    }

    /// Attach the rule that produced this decision.
    pub fn with_rule(mut self, rule: RuleRef) -> Self {
        self.matched_rule = Some(rule);
        self
    }

    /// Attach the computed risk score.
    pub fn with_risk(mut self, risk: RiskScore) -> Self {
        self.risk = risk;
        self
    }

    /// Whether the action may proceed without approval.
    pub fn is_allowed(&self) -> bool {
        self.effect.is_allow()
    }

    /// Whether the action needs approval before proceeding.
    pub fn needs_approval(&self) -> bool {
        matches!(self.effect, Effect::RequireApproval)
    }
}
