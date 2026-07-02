//! The policy engine: turning an [`ActionRequest`] into an [`ActionDecision`].
//!
//! Rules are attribute-based. Each [`PolicyRule`] has an [`RuleEffect`]
//! (`allow`, `deny`, or `require_approval`) and a set of [`Conditions`] over the
//! action verb, resource, subject, context attributes, and computed risk. Rules
//! are sorted by priority (descending) and the first match wins — much like
//! OPA's ordered evaluation combined with sudo's allow/deny/ask semantics.
//!
//! Two mechanisms sit outside ordinary rules:
//!
//! * an **always-deny floor** of catastrophic patterns that can never be
//!   overridden (fork bombs, `rm -rf /`, raw disk writes), and
//! * **risk escalation**, which turns an `allow` into `require_approval` when the
//!   request's risk score meets the configured threshold.

use std::{
    cmp::Reverse,
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use globset::{Glob, GlobMatcher};
use regex::Regex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::action::{ActionRequest, AttributeValue};
use crate::config::{Config, DefaultEffect, PolicyConfig};
use crate::decision::{ActionDecision, RuleRef};
use crate::risk::{RiskEngine, RiskScore};

/// The effect a rule applies when it matches.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    /// Permit the action.
    Allow,
    /// Refuse the action.
    #[default]
    Deny,
    /// Require explicit approval before proceeding.
    RequireApproval,
}

impl From<DefaultEffect> for RuleEffect {
    fn from(value: DefaultEffect) -> Self {
        match value {
            DefaultEffect::Allow => RuleEffect::Allow,
            DefaultEffect::Deny => RuleEffect::Deny,
            DefaultEffect::RequireApproval => RuleEffect::RequireApproval,
        }
    }
}

/// A condition on a single context attribute.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum AttrCondition {
    /// The attribute must be present.
    Exists,
    /// The attribute must equal this scalar (or, for a list, contain it).
    Equals(String),
    /// The attribute's scalar form must match this regex.
    Regex(String),
    /// The attribute must equal (or contain) one of these values.
    OneOf(Vec<String>),
}

/// The conditions a rule matches against.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Conditions {
    /// Exact action verb, e.g. `exec`.
    #[serde(default)]
    pub action: Option<String>,
    /// Glob over the action verb, e.g. `fs.*`.
    #[serde(default)]
    pub action_glob: Option<String>,
    /// Exact resource string.
    #[serde(default)]
    pub resource: Option<String>,
    /// Glob over the resource, e.g. `/etc/**`.
    #[serde(default)]
    pub resource_glob: Option<String>,
    /// Regexes the resource must all match.
    #[serde(default)]
    pub resource_regex: Vec<String>,
    /// Exact subject id.
    #[serde(default)]
    pub subject: Option<String>,
    /// Roles the subject must all hold.
    #[serde(default)]
    pub subject_roles: Vec<String>,
    /// Conditions on context attributes (all must hold).
    #[serde(default)]
    pub attributes: BTreeMap<String, AttrCondition>,
    /// Minimum risk score (inclusive) for the rule to apply.
    #[serde(default)]
    pub min_risk: Option<u8>,
    /// Maximum risk score (inclusive) for the rule to apply.
    #[serde(default)]
    pub max_risk: Option<u8>,
}

/// A single policy rule.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRule {
    /// Rule name (used in decisions and audit records).
    pub name: String,
    /// Optional human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Higher priority rules are evaluated first.
    #[serde(default)]
    pub priority: Option<u32>,
    /// The effect applied when the rule matches.
    #[serde(default)]
    pub effect: RuleEffect,
    /// The conditions that must all hold for the rule to match.
    #[serde(default)]
    pub conditions: Conditions,
}

impl PolicyRule {
    fn rule_ref(&self) -> RuleRef {
        RuleRef::new(self.name.clone(), self.description.clone())
    }
}

#[derive(Debug, Deserialize)]
struct PolicyFile {
    #[serde(default)]
    policy: Vec<PolicyRule>,
}

/// Evaluates [`ActionRequest`]s against an ordered set of rules.
pub struct PolicyEngine {
    always_deny: Vec<CompiledRule>,
    rules: Vec<CompiledRule>,
    default_effect: RuleEffect,
    risk: RiskEngine,
    approval_threshold: Option<u8>,
}

impl PolicyEngine {
    /// A policy engine with no user rules, the given default effect, and no risk
    /// analysis. The always-deny floor is always present.
    pub fn new(default_effect: RuleEffect) -> Self {
        Self {
            always_deny: builtin_always_deny(),
            rules: Vec::new(),
            default_effect,
            risk: RiskEngine::empty(),
            approval_threshold: None,
        }
    }

    /// Build an engine from explicit rules (useful in tests and embedding).
    pub fn with_rules(
        default_effect: RuleEffect,
        rules: Vec<PolicyRule>,
        risk: RiskEngine,
        approval_threshold: Option<u8>,
    ) -> Result<Self, PolicyError> {
        Ok(Self {
            always_deny: builtin_always_deny(),
            rules: compile_rules(rules, Path::new("<inline>"))?,
            default_effect,
            risk,
            approval_threshold,
        })
    }

    /// Build an engine from configuration, loading rule files from the policy
    /// directory and wiring up the configured risk analyzers.
    pub fn from_config(config: &Config) -> Result<Self, PolicyError> {
        let rules = load_policy_dir(&config.policy.policy_dir)?;
        Ok(Self {
            always_deny: builtin_always_deny(),
            rules,
            default_effect: config.policy.default_effect.into(),
            risk: RiskEngine::from_config(&config.risk),
            approval_threshold: config.risk.approval_threshold,
        })
    }

    /// Reload rules from the policy directory, replacing the current set.
    pub fn reload(&mut self, config: &PolicyConfig) -> Result<(), PolicyError> {
        self.rules = load_policy_dir(&config.policy_dir)?;
        self.default_effect = config.default_effect.into();
        Ok(())
    }

    /// The heart of Veridion: decide what to do with an action.
    pub fn evaluate(&self, request: &ActionRequest) -> ActionDecision {
        let risk = self.risk.score(request);

        for rule in &self.always_deny {
            if rule.matches(request, risk.value) {
                return ActionDecision::deny(format!(
                    "blocked by always-deny floor: {}",
                    rule.rule.name
                ))
                .with_rule(rule.rule.rule_ref())
                .with_risk(risk);
            }
        }

        for rule in &self.rules {
            if rule.matches(request, risk.value) {
                return self.finalize(
                    rule.rule.effect,
                    format!("matched rule '{}'", rule.rule.name),
                    Some(rule.rule.rule_ref()),
                    risk,
                );
            }
        }

        self.finalize(
            self.default_effect,
            format!(
                "no rule matched; default effect '{}'",
                effect_name(self.default_effect)
            ),
            None,
            risk,
        )
    }

    fn finalize(
        &self,
        effect: RuleEffect,
        reason: String,
        rule: Option<RuleRef>,
        risk: RiskScore,
    ) -> ActionDecision {
        let (effect, reason) = self.escalate(effect, reason, &risk);
        let mut decision = match effect {
            RuleEffect::Allow => ActionDecision::allow(reason),
            RuleEffect::Deny => ActionDecision::deny(reason),
            RuleEffect::RequireApproval => ActionDecision::require_approval(reason),
        };
        if let Some(rule) = rule {
            decision = decision.with_rule(rule);
        }
        decision.with_risk(risk)
    }

    /// Turn an `allow` into `require_approval` when risk meets the threshold.
    fn escalate(
        &self,
        effect: RuleEffect,
        reason: String,
        risk: &RiskScore,
    ) -> (RuleEffect, String) {
        if let (RuleEffect::Allow, Some(threshold)) = (effect, self.approval_threshold)
            && risk.value >= threshold
        {
            return (
                RuleEffect::RequireApproval,
                format!("{reason}; escalated: risk {} ≥ {}", risk.value, threshold),
            );
        }
        (effect, reason)
    }
}

fn effect_name(effect: RuleEffect) -> &'static str {
    match effect {
        RuleEffect::Allow => "allow",
        RuleEffect::Deny => "deny",
        RuleEffect::RequireApproval => "require_approval",
    }
}

fn load_policy_dir(dir: &Path) -> Result<Vec<CompiledRule>, PolicyError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut rules = Vec::new();
    for entry in fs::read_dir(dir).map_err(|err| PolicyError::Io(dir.to_path_buf(), err))? {
        let entry = entry.map_err(|err| PolicyError::Io(dir.to_path_buf(), err))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
            continue;
        }
        let content =
            fs::read_to_string(&path).map_err(|err| PolicyError::Io(path.clone(), err))?;
        let parsed: PolicyFile =
            toml::from_str(&content).map_err(|err| PolicyError::Parse(path.clone(), err))?;
        rules.extend(compile_rules(parsed.policy, &path)?);
    }

    rules.sort_by_key(|rule| rule.sort_key());
    Ok(rules)
}

fn compile_rules(rules: Vec<PolicyRule>, source: &Path) -> Result<Vec<CompiledRule>, PolicyError> {
    let mut compiled = Vec::with_capacity(rules.len());
    for rule in rules {
        compiled.push(CompiledRule::try_new(rule, source)?);
    }
    compiled.sort_by_key(|rule| rule.sort_key());
    Ok(compiled)
}

struct CompiledRule {
    rule: PolicyRule,
    action_glob: Option<GlobMatcher>,
    resource_glob: Option<GlobMatcher>,
    resource_regex: Vec<Regex>,
    attributes: BTreeMap<String, CompiledAttr>,
}

impl CompiledRule {
    fn try_new(rule: PolicyRule, source: &Path) -> Result<Self, PolicyError> {
        let src = source.display().to_string();
        let action_glob = match &rule.conditions.action_glob {
            Some(pat) => Some(compile_glob(pat, &rule.name, &src)?),
            None => None,
        };
        let resource_glob = match &rule.conditions.resource_glob {
            Some(pat) => Some(compile_glob(pat, &rule.name, &src)?),
            None => None,
        };
        let mut resource_regex = Vec::new();
        for pat in &rule.conditions.resource_regex {
            resource_regex.push(compile_regex(pat, &rule.name, &src)?);
        }
        let mut attributes = BTreeMap::new();
        for (key, cond) in &rule.conditions.attributes {
            attributes.insert(key.clone(), CompiledAttr::try_new(cond, &rule.name, &src)?);
        }
        Ok(Self {
            rule,
            action_glob,
            resource_glob,
            resource_regex,
            attributes,
        })
    }

    fn sort_key(&self) -> (Reverse<u32>, String) {
        (
            Reverse(self.rule.priority.unwrap_or(0)),
            self.rule.name.clone(),
        )
    }

    fn matches(&self, request: &ActionRequest, risk: u8) -> bool {
        let c = &self.rule.conditions;

        if let Some(action) = &c.action
            && &request.action != action
        {
            return false;
        }
        if let Some(glob) = &self.action_glob
            && !glob.is_match(&request.action)
        {
            return false;
        }
        if let Some(resource) = &c.resource
            && &request.resource != resource
        {
            return false;
        }
        if let Some(glob) = &self.resource_glob
            && !glob.is_match(&request.resource)
        {
            return false;
        }
        if !self
            .resource_regex
            .iter()
            .all(|re| re.is_match(&request.resource))
        {
            return false;
        }
        if let Some(subject) = &c.subject
            && &request.subject.id != subject
        {
            return false;
        }
        if !c
            .subject_roles
            .iter()
            .all(|role| request.subject.has_role(role))
        {
            return false;
        }
        for (key, cond) in &self.attributes {
            if !cond.matches(request.context.get(key)) {
                return false;
            }
        }
        if let Some(min) = c.min_risk
            && risk < min
        {
            return false;
        }
        if let Some(max) = c.max_risk
            && risk > max
        {
            return false;
        }
        true
    }
}

enum CompiledAttr {
    Exists,
    Equals(String),
    Regex(Regex),
    OneOf(Vec<String>),
}

impl CompiledAttr {
    fn try_new(cond: &AttrCondition, rule: &str, source: &str) -> Result<Self, PolicyError> {
        Ok(match cond {
            AttrCondition::Exists => CompiledAttr::Exists,
            AttrCondition::Equals(v) => CompiledAttr::Equals(v.clone()),
            AttrCondition::Regex(p) => CompiledAttr::Regex(compile_regex(p, rule, source)?),
            AttrCondition::OneOf(vs) => CompiledAttr::OneOf(vs.clone()),
        })
    }

    fn matches(&self, value: Option<&AttributeValue>) -> bool {
        match self {
            CompiledAttr::Exists => value.is_some(),
            CompiledAttr::Equals(expected) => value.is_some_and(|v| scalar_eq(v, expected)),
            CompiledAttr::Regex(re) => value
                .and_then(scalar_string)
                .is_some_and(|s| re.is_match(&s)),
            CompiledAttr::OneOf(opts) => {
                value.is_some_and(|v| opts.iter().any(|o| scalar_eq(v, o)))
            }
        }
    }
}

fn scalar_string(value: &AttributeValue) -> Option<String> {
    match value {
        AttributeValue::Text(s) => Some(s.clone()),
        AttributeValue::Integer(n) => Some(n.to_string()),
        AttributeValue::Bool(b) => Some(b.to_string()),
        AttributeValue::List(_) => None,
    }
}

fn scalar_eq(value: &AttributeValue, expected: &str) -> bool {
    scalar_string(value).is_some_and(|s| s == expected) || value.contains(expected)
}

fn compile_glob(pattern: &str, rule: &str, source: &str) -> Result<GlobMatcher, PolicyError> {
    Glob::from_str(pattern)
        .map(|g| g.compile_matcher())
        .map_err(|err| PolicyError::InvalidRule {
            rule: rule.to_string(),
            reason: format!("invalid glob '{pattern}' in {source}: {err}"),
        })
}

fn compile_regex(pattern: &str, rule: &str, source: &str) -> Result<Regex, PolicyError> {
    Regex::new(pattern).map_err(|err| PolicyError::InvalidRule {
        rule: rule.to_string(),
        reason: format!("invalid regex '{pattern}' in {source}: {err}"),
    })
}

/// The non-overridable deny floor: catastrophic patterns that are refused before
/// any user rule is considered. These are heuristics, not a security boundary.
fn builtin_always_deny() -> Vec<CompiledRule> {
    let patterns = [
        (
            "floor_rm_root",
            r"(?i)\brm\s+-[a-z]*r[a-z]*f?\b.*\s/(\s|\*|$)",
        ),
        (
            "floor_rm_home",
            r"(?i)\brm\s+-[a-z]*r[a-z]*f?\b.*\s~(/|\s|$)",
        ),
        ("floor_mkfs", r"(?i)\bmkfs"),
        ("floor_raw_disk_write", r"(?i)\bof=/dev/(sd|nvme|disk|hd)"),
        ("floor_fork_bomb", r":\(\)\s*\{"),
    ];

    patterns
        .into_iter()
        .map(|(name, pattern)| PolicyRule {
            name: name.to_string(),
            description: Some("built-in catastrophic-command floor".to_string()),
            priority: Some(u32::MAX),
            effect: RuleEffect::Deny,
            conditions: Conditions {
                resource_regex: vec![pattern.to_string()],
                ..Conditions::default()
            },
        })
        .map(|rule| CompiledRule::try_new(rule, Path::new("<builtin>")))
        .collect::<Result<Vec<_>, _>>()
        .expect("built-in deny patterns are valid")
}

/// Errors from loading or compiling policy.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// A policy file could not be read.
    #[error("failed to read policy from {0:?}: {1}")]
    Io(PathBuf, #[source] std::io::Error),
    /// A policy file was not valid TOML.
    #[error("failed to parse policy file {0:?}: {1}")]
    Parse(PathBuf, toml::de::Error),
    /// A rule contained an invalid glob or regex.
    #[error("invalid policy rule '{rule}': {reason}")]
    InvalidRule {
        /// The offending rule's name.
        rule: String,
        /// Why it was rejected.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::{ActionRequest, Subject, actions};
    use crate::decision::Effect;

    fn risk_engine() -> RiskEngine {
        RiskEngine::empty().with_analyzer(Box::new(crate::risk::DestructiveCommandAnalyzer))
    }

    #[test]
    fn always_deny_floor_blocks_rm_root() {
        let engine = PolicyEngine::with_rules(RuleEffect::Allow, vec![], risk_engine(), None)
            .expect("engine");
        let req = ActionRequest::new(actions::EXEC, "rm -rf / --no-preserve-root");
        let decision = engine.evaluate(&req);
        assert_eq!(decision.effect, Effect::Deny);
        assert!(decision.matched_rule.is_some());
    }

    #[test]
    fn higher_priority_rule_wins() {
        let allow = PolicyRule {
            name: "allow_git".to_string(),
            description: None,
            priority: Some(10),
            effect: RuleEffect::Allow,
            conditions: Conditions {
                action: Some(actions::EXEC.to_string()),
                ..Conditions::default()
            },
        };
        let deny = PolicyRule {
            name: "deny_git_push".to_string(),
            description: None,
            priority: Some(100),
            effect: RuleEffect::Deny,
            conditions: Conditions {
                resource_regex: vec!["git push".to_string()],
                ..Conditions::default()
            },
        };
        let engine = PolicyEngine::with_rules(
            RuleEffect::Deny,
            vec![allow, deny],
            RiskEngine::empty(),
            None,
        )
        .expect("engine");

        let push = ActionRequest::new(actions::EXEC, "git push origin main");
        assert_eq!(engine.evaluate(&push).effect, Effect::Deny);

        let status = ActionRequest::new(actions::EXEC, "git status");
        assert_eq!(engine.evaluate(&status).effect, Effect::Allow);
    }

    #[test]
    fn attribute_and_role_conditions_match() {
        let rule = PolicyRule {
            name: "allow_trusted_in_repo".to_string(),
            description: None,
            priority: Some(50),
            effect: RuleEffect::Allow,
            conditions: Conditions {
                subject_roles: vec!["trusted".to_string()],
                attributes: BTreeMap::from([(
                    "repo".to_string(),
                    AttrCondition::Equals("veridion".to_string()),
                )]),
                ..Conditions::default()
            },
        };
        let engine =
            PolicyEngine::with_rules(RuleEffect::Deny, vec![rule], RiskEngine::empty(), None)
                .expect("engine");

        let allowed = ActionRequest::new(actions::FS_WRITE, "src/main.rs")
            .subject(Subject::new("jarvis").with_role("trusted"))
            .attr("repo", "veridion");
        assert_eq!(engine.evaluate(&allowed).effect, Effect::Allow);

        let wrong_repo = ActionRequest::new(actions::FS_WRITE, "src/main.rs")
            .subject(Subject::new("jarvis").with_role("trusted"))
            .attr("repo", "other");
        assert_eq!(engine.evaluate(&wrong_repo).effect, Effect::Deny);

        let missing_role = ActionRequest::new(actions::FS_WRITE, "src/main.rs")
            .subject(Subject::new("jarvis"))
            .attr("repo", "veridion");
        assert_eq!(engine.evaluate(&missing_role).effect, Effect::Deny);
    }

    #[test]
    fn risk_escalates_allow_to_approval() {
        let engine = PolicyEngine::with_rules(RuleEffect::Allow, vec![], risk_engine(), Some(75))
            .expect("engine");

        // High risk (dd, weight 80) but not caught by the always-deny floor: the
        // target is a regular file, not a raw block device. Allow is escalated to
        // require_approval by the risk threshold.
        let req = ActionRequest::new(actions::EXEC, "dd if=/dev/zero of=./disk.img");
        let decision = engine.evaluate(&req);
        assert_eq!(decision.effect, Effect::RequireApproval);
        assert!(decision.risk.value >= 75);
    }

    #[test]
    fn always_deny_floor_beats_risk_escalation() {
        let engine = PolicyEngine::with_rules(RuleEffect::Allow, vec![], risk_engine(), Some(75))
            .expect("engine");

        // A raw disk write is caught by the floor before risk escalation applies.
        let req = ActionRequest::new(actions::EXEC, "dd if=/dev/zero of=/dev/sdb");
        assert_eq!(engine.evaluate(&req).effect, Effect::Deny);
    }
}
