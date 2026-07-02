//! End-to-end authorization tests exercising the public [`Veridion`] facade:
//! allow, deny, the always-deny floor, risk escalation, the approval workflow,
//! and audit recording.

use veridion::action::{ActionRequest, Subject, actions};
use veridion::approval::ApprovalWorkflow;
use veridion::audit::AuditLog;
use veridion::decision::Effect;
use veridion::policy::{Conditions, PolicyEngine, PolicyRule, RuleEffect};
use veridion::risk::{DestructiveCommandAnalyzer, RiskEngine};
use veridion::{ApprovalOutcome, Veridion};

fn rule(name: &str, effect: RuleEffect, conditions: Conditions) -> PolicyRule {
    PolicyRule {
        name: name.to_string(),
        description: None,
        priority: Some(10),
        effect,
        conditions,
    }
}

fn veridion(rules: Vec<PolicyRule>, approval: ApprovalWorkflow) -> Veridion {
    let risk = RiskEngine::empty().with_analyzer(Box::new(DestructiveCommandAnalyzer));
    let policy = PolicyEngine::with_rules(RuleEffect::Deny, rules, risk, Some(75)).expect("engine");
    Veridion::new(policy, approval, AuditLog::memory())
}

#[tokio::test]
async fn allowed_action_proceeds_and_is_audited() {
    let allow_reads = rule(
        "allow_reads",
        RuleEffect::Allow,
        Conditions {
            action: Some(actions::FS_READ.to_string()),
            ..Conditions::default()
        },
    );
    let v = veridion(vec![allow_reads], ApprovalWorkflow::auto_deny());

    let req = ActionRequest::new(actions::FS_READ, "src/lib.rs")
        .subject(Subject::new("jarvis").with_role("agent"));
    let auth = v.authorize(&req).await.expect("authorize");

    assert!(auth.permitted);
    assert_eq!(auth.decision.effect, Effect::Allow);

    let recent = v.audit().recent(10).await.expect("recent");
    assert_eq!(recent.len(), 1);
    assert_eq!(recent[0].action, actions::FS_READ);
    assert_eq!(recent[0].subject, "jarvis");
}

#[tokio::test]
async fn default_deny_blocks_unmatched_action() {
    let v = veridion(vec![], ApprovalWorkflow::auto_deny());
    let req = ActionRequest::new(actions::NET_REMOTE, "ssh prod 'reboot'");
    let auth = v.authorize(&req).await.expect("authorize");

    assert!(!auth.permitted);
    assert_eq!(auth.decision.effect, Effect::Deny);
    assert!(auth.decision.matched_rule.is_none());
}

#[tokio::test]
async fn always_deny_floor_cannot_be_overridden() {
    // A permissive rule that would otherwise allow anything.
    let allow_all = rule("allow_all", RuleEffect::Allow, Conditions::default());
    let v = veridion(vec![allow_all], ApprovalWorkflow::auto_approve());

    let req = ActionRequest::new(actions::EXEC, "rm -rf / --no-preserve-root");
    let auth = v.authorize(&req).await.expect("authorize");

    assert!(!auth.permitted);
    assert_eq!(auth.decision.effect, Effect::Deny);
    assert!(auth.decision.reason.contains("always-deny floor"));
}

#[tokio::test]
async fn high_risk_allow_escalates_to_approval() {
    let allow_exec = rule(
        "allow_exec",
        RuleEffect::Allow,
        Conditions {
            action: Some(actions::EXEC.to_string()),
            ..Conditions::default()
        },
    );

    // With an approver that says yes, the escalated action proceeds.
    let approved = veridion(vec![allow_exec.clone()], ApprovalWorkflow::auto_approve());
    let req = ActionRequest::new(actions::EXEC, "dd if=/dev/zero of=./disk.img");
    let auth = approved.authorize(&req).await.expect("authorize");
    assert_eq!(auth.decision.effect, Effect::RequireApproval);
    assert!(auth.decision.risk.value >= 75);
    assert!(auth.permitted);
    assert_eq!(auth.approval, Some(ApprovalOutcome::Approved));

    // With the default deny approver, the same action is refused.
    let denied = veridion(vec![allow_exec], ApprovalWorkflow::auto_deny());
    let auth = denied.authorize(&req).await.expect("authorize");
    assert!(!auth.permitted);
    assert_eq!(auth.approval, Some(ApprovalOutcome::Denied));
}

#[tokio::test]
async fn pure_evaluate_has_no_side_effects() {
    let v = veridion(vec![], ApprovalWorkflow::auto_deny());
    let req = ActionRequest::new(actions::FS_WRITE, "/etc/passwd");

    let decision = v.evaluate(&req);
    assert_eq!(decision.effect, Effect::Deny);

    // evaluate() must not write to the audit log.
    assert!(v.audit().recent(10).await.expect("recent").is_empty());
}
