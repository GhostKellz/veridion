//! How an agent runtime (here, a sketch of Jarvis) gates its actions through
//! Veridion.
//!
//! Jarvis models what it wants to do as an `Action`. Before dispatching, it maps
//! that `Action` to a Veridion [`ActionRequest`] and calls
//! [`Veridion::authorize`]. Only permitted actions run; everything else is
//! refused or escalated to approval — and every decision is audited.
//!
//! Run with: `cargo run --example jarvis_integration`

use veridion::action::{ActionRequest, Subject, actions};
use veridion::approval::ApprovalWorkflow;
use veridion::audit::AuditLog;
use veridion::policy::{Conditions, PolicyEngine, PolicyRule, RuleEffect};
use veridion::risk::RiskEngine;
use veridion::{Config, Veridion};

/// A trimmed-down version of Jarvis's own action type.
enum Action {
    Bash { command: String },
    Read { path: String },
    Write { path: String, contents: String },
    Remote { host: String, command: String },
}

impl Action {
    /// The adapter: turn a Jarvis action into a Veridion request. This is the
    /// only glue code Jarvis needs — Veridion owns the policy logic.
    fn to_request(&self, agent: &str, repo: &str) -> ActionRequest {
        let subject = Subject::new(agent).with_role("agent");
        let base = |action: &str, resource: String| {
            ActionRequest::new(action, resource)
                .subject(subject.clone())
                .attr("repo", repo)
        };
        match self {
            Action::Bash { command } => base(actions::EXEC, command.clone()),
            Action::Read { path } => base(actions::FS_READ, path.clone()),
            Action::Write { path, .. } => base(actions::FS_WRITE, path.clone()),
            Action::Remote { host, command } => {
                base(actions::NET_REMOTE, format!("{host}: {command}"))
            }
        }
    }

    fn describe(&self) -> String {
        match self {
            Action::Bash { command } => format!("bash: {command}"),
            Action::Read { path } => format!("read: {path}"),
            Action::Write { path, contents } => {
                format!("write: {path} ({} bytes)", contents.len())
            }
            Action::Remote { host, command } => format!("remote {host}: {command}"),
        }
    }
}

/// A policy that mirrors how Jarvis might be configured: reads are free, writes
/// inside the repo are allowed, remote execution needs a human, and everything
/// else falls through to deny-by-default.
fn policy_engine() -> PolicyEngine {
    let rules = vec![
        PolicyRule {
            name: "allow_reads".to_string(),
            description: Some("reads are always safe".to_string()),
            priority: Some(10),
            effect: RuleEffect::Allow,
            conditions: Conditions {
                action: Some(actions::FS_READ.to_string()),
                ..Conditions::default()
            },
        },
        PolicyRule {
            name: "allow_repo_writes".to_string(),
            description: Some("writes are allowed inside the working repo".to_string()),
            priority: Some(10),
            effect: RuleEffect::Allow,
            conditions: Conditions {
                action: Some(actions::FS_WRITE.to_string()),
                attributes: [(
                    "repo".to_string(),
                    veridion::policy::AttrCondition::Equals("veridion".to_string()),
                )]
                .into_iter()
                .collect(),
                ..Conditions::default()
            },
        },
        PolicyRule {
            name: "approve_remote".to_string(),
            description: Some("remote execution needs a human".to_string()),
            priority: Some(20),
            effect: RuleEffect::RequireApproval,
            conditions: Conditions {
                action: Some(actions::NET_REMOTE.to_string()),
                ..Conditions::default()
            },
        },
        PolicyRule {
            name: "allow_safe_bash".to_string(),
            description: Some("common read-only shell commands".to_string()),
            priority: Some(10),
            effect: RuleEffect::Allow,
            conditions: Conditions {
                action: Some(actions::EXEC.to_string()),
                resource_regex: vec![r"^(ls|cat|git status|git diff)\b".to_string()],
                ..Conditions::default()
            },
        },
    ];

    let risk = RiskEngine::from_config(&Config::default().risk);
    PolicyEngine::with_rules(RuleEffect::Deny, rules, risk, Some(75)).expect("policy engine")
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Jarvis holds one Veridion instance for its whole session. Here we wire it
    // up by hand; in production `Veridion::from_config` reads `veridion.toml`.
    let veridion = Veridion::new(
        policy_engine(),
        ApprovalWorkflow::auto_deny(), // headless: refuse anything needing a human
        AuditLog::memory(),
    );

    let queue = vec![
        Action::Read {
            path: "src/main.rs".to_string(),
        },
        Action::Bash {
            command: "git status".to_string(),
        },
        Action::Write {
            path: "src/policy.rs".to_string(),
            contents: "// edit".to_string(),
        },
        Action::Bash {
            command: "rm -rf / --no-preserve-root".to_string(),
        },
        Action::Remote {
            host: "prod-1".to_string(),
            command: "systemctl restart api".to_string(),
        },
    ];

    // The dispatch loop: authorize, then run only what Veridion permits.
    for action in &queue {
        let request = action.to_request("jarvis", "veridion");
        let auth = veridion.authorize(&request).await?;

        let verdict = if auth.permitted { "RUN " } else { "BLOCK" };
        println!(
            "[{verdict}] {:<40} risk={:>3} effect={} — {}",
            action.describe(),
            auth.decision.risk.value,
            auth.decision.effect,
            auth.decision.reason
        );
    }

    println!("\n--- audit trail (newest first) ---");
    for record in veridion.audit().recent(10).await? {
        println!(
            "  {} {} on '{}' -> {}",
            &record.id[..8],
            record.action,
            record.resource,
            record.effect
        );
    }

    Ok(())
}
