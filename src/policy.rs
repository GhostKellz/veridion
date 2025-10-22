use globset::{Glob, GlobMatcher};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::{
    cmp::Reverse,
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    time::SystemTime,
};
use std::{fmt, str::FromStr};
use thiserror::Error;

use crate::config::{PoliciesConfig, PolicyMode};

pub struct PolicyEngine {
    rules: Vec<CompiledPolicyRule>,
    default_mode: PolicyMode,
    last_loaded: Option<SystemTime>,
}

impl PolicyEngine {
    pub fn new(default_mode: PolicyMode) -> Self {
        Self {
            rules: Vec::new(),
            default_mode,
            last_loaded: None,
        }
    }

    pub fn with_rules(
        default_mode: PolicyMode,
        rules: Vec<PolicyRule>,
    ) -> Result<Self, PolicyError> {
        let compiled = compile_rules(rules)?;
        Ok(Self {
            rules: compiled,
            default_mode,
            last_loaded: Some(SystemTime::now()),
        })
    }

    pub fn reload(&mut self, config: &PoliciesConfig) -> Result<(), PolicyError> {
        let rules = load_policy_dir(&config.policy_dir)?;
        self.rules = rules;
        self.last_loaded = Some(SystemTime::now());
        Ok(())
    }

    pub fn evaluate(&self, context: &PolicyContext) -> PolicyDecision {
        for rule in &self.rules {
            if rule.matches(context) {
                return PolicyDecision {
                    action: rule.action(),
                    rule: Some(rule.summary()),
                };
            }
        }

        PolicyDecision {
            action: match self.default_mode {
                PolicyMode::Allow => PolicyAction::Allow,
                PolicyMode::Deny => PolicyAction::Deny,
                PolicyMode::Warn => PolicyAction::Warn,
            },
            rule: None,
        }
    }

    pub fn last_loaded(&self) -> Option<SystemTime> {
        self.last_loaded
    }
}

fn load_policy_dir(dir: &Path) -> Result<Vec<CompiledPolicyRule>, PolicyError> {
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
        for rule in parsed.policy.into_iter() {
            rules.push(CompiledPolicyRule::try_new(rule, path.clone())?);
        }
    }

    rules.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    Ok(rules)
}

fn compile_rules(rules: Vec<PolicyRule>) -> Result<Vec<CompiledPolicyRule>, PolicyError> {
    let mut compiled = Vec::with_capacity(rules.len());
    for rule in rules {
        compiled.push(CompiledPolicyRule::try_new(
            rule,
            PathBuf::from("<inline>"),
        )?);
    }
    compiled.sort_by(|a, b| a.sort_key().cmp(&b.sort_key()));
    Ok(compiled)
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyDecision {
    pub action: PolicyAction,
    pub rule: Option<PolicySummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicySummary {
    pub name: String,
    pub description: Option<String>,
}

struct CompiledPolicyRule {
    rule: PolicyRule,
    conditions: CompiledPolicyConditions,
}

impl CompiledPolicyRule {
    fn try_new(rule: PolicyRule, source: PathBuf) -> Result<Self, PolicyError> {
        let conditions = CompiledPolicyConditions::try_from(&rule, &source)?;
        Ok(Self { rule, conditions })
    }

    fn matches(&self, context: &PolicyContext<'_>) -> bool {
        self.conditions.matches(context)
    }

    fn action(&self) -> PolicyAction {
        self.rule.action
    }

    fn summary(&self) -> PolicySummary {
        self.rule.summary()
    }

    fn priority(&self) -> u32 {
        self.rule.priority.unwrap_or(0)
    }

    fn sort_key(&self) -> (Reverse<u32>, String) {
        (Reverse(self.priority()), self.rule.name.clone())
    }
}

#[derive(Debug)]
pub struct PolicyContext<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub headers: &'a HashMap<String, String>,
    pub input_preview: Option<&'a str>,
    pub token_count: Option<usize>,
}

impl<'a> PolicyContext<'a> {
    pub fn new(
        method: &'a str,
        path: &'a str,
        headers: &'a HashMap<String, String>,
        input_preview: Option<&'a str>,
        token_count: Option<usize>,
    ) -> PolicyContext<'a> {
        PolicyContext {
            method,
            path,
            headers,
            input_preview,
            token_count,
        }
    }
}

struct CompiledPolicyConditions {
    method: Option<String>,
    path: Option<String>,
    path_glob: Option<GlobMatcher>,
    headers: HashMap<String, CompiledHeaderCondition>,
    input_contains: Vec<String>,
    input_regex: Vec<Regex>,
    token_count: Option<TokenRange>,
}

impl CompiledPolicyConditions {
    fn try_from(rule: &PolicyRule, source: &PathBuf) -> Result<Self, PolicyError> {
        let source_path = source.display().to_string();
        let mut path_glob = None;
        if let Some(pattern) = &rule.conditions.path_glob {
            let glob = Glob::from_str(pattern).map_err(|err| PolicyError::InvalidRule {
                rule: rule.name.clone(),
                reason: format!("invalid path_glob pattern '{pattern}' in {source_path}: {err}"),
            })?;
            path_glob = Some(glob.compile_matcher());
        }

        let mut headers = HashMap::new();
        for (key, condition) in &rule.conditions.headers {
            let compiled = CompiledHeaderCondition::try_from(condition, rule, key, &source_path)?;
            headers.insert(key.to_string(), compiled);
        }

        let mut input_regex = Vec::new();
        for pattern in &rule.conditions.input_regex {
            input_regex.push(Regex::new(pattern).map_err(|err| PolicyError::InvalidRule {
                rule: rule.name.clone(),
                reason: format!("invalid input_regex '{pattern}' in {source_path}: {err}"),
            })?);
        }

        Ok(Self {
            method: rule
                .conditions
                .method
                .as_ref()
                .map(|m| m.to_ascii_uppercase()),
            path: rule.conditions.path.clone(),
            path_glob,
            headers,
            input_contains: rule
                .conditions
                .input_contains
                .iter()
                .map(|s| s.to_lowercase())
                .collect(),
            input_regex,
            token_count: rule.conditions.token_count.clone(),
        })
    }

    fn matches(&self, context: &PolicyContext<'_>) -> bool {
        if let Some(expected) = &self.method {
            if !context.method.eq_ignore_ascii_case(expected) {
                return false;
            }
        }

        if let Some(expected_path) = &self.path {
            if context.path != expected_path {
                return false;
            }
        }

        if let Some(glob) = &self.path_glob {
            if !glob.is_match(context.path) {
                return false;
            }
        }

        for (key, condition) in &self.headers {
            let actual = context.headers.get(key);
            if !condition.matches(actual.map(String::as_str)) {
                return false;
            }
        }

        if !self.input_contains.is_empty() {
            let input = match context.input_preview {
                Some(preview) => preview.to_lowercase(),
                None => return false,
            };

            if !self
                .input_contains
                .iter()
                .all(|needle| input.contains(needle))
            {
                return false;
            }
        }

        if !self.input_regex.is_empty() {
            let input = match context.input_preview {
                Some(preview) => preview,
                None => return false,
            };

            if !self.input_regex.iter().all(|regex| regex.is_match(input)) {
                return false;
            }
        }

        if let Some(range) = &self.token_count {
            if let Some(tokens) = context.token_count {
                if tokens < range.min.unwrap_or_default() {
                    return false;
                }
                if let Some(max) = range.max {
                    if tokens > max {
                        return false;
                    }
                }
            } else {
                return false;
            }
        }

        true
    }
}

#[derive(Debug, Clone)]
enum CompiledHeaderCondition {
    Exists,
    Equals(String),
    Regex(Regex),
}

impl CompiledHeaderCondition {
    fn try_from(
        condition: &HeaderCondition,
        rule: &PolicyRule,
        header: &str,
        source_path: &str,
    ) -> Result<Self, PolicyError> {
        match condition {
            HeaderCondition::Exists => Ok(Self::Exists),
            HeaderCondition::Equals(value) => Ok(Self::Equals(value.clone())),
            HeaderCondition::Regex(pattern) => {
                Ok(Self::Regex(Regex::new(pattern).map_err(|err| {
                    PolicyError::InvalidRule {
                        rule: rule.name.clone(),
                        reason: format!(
                            "invalid header regex for '{header}' in {source_path}: {err}"
                        ),
                    }
                })?))
            }
        }
    }

    fn matches(&self, value: Option<&str>) -> bool {
        match self {
            Self::Exists => value.is_some(),
            Self::Equals(expected) => value.map(|v| v == expected).unwrap_or(false),
            Self::Regex(regex) => value.map(|v| regex.is_match(v)).unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyRule {
    pub name: String,
    pub description: Option<String>,
    #[serde(default)]
    pub priority: Option<u32>,
    #[serde(default)]
    pub action: PolicyAction,
    #[serde(default)]
    pub conditions: PolicyConditions,
}

impl PolicyRule {
    fn summary(&self) -> PolicySummary {
        PolicySummary {
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Allow,
    Deny,
    Warn,
}

impl Default for PolicyAction {
    fn default() -> Self {
        PolicyAction::Deny
    }
}

impl fmt::Display for PolicyAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            PolicyAction::Allow => "allow",
            PolicyAction::Deny => "deny",
            PolicyAction::Warn => "warn",
        };
        f.write_str(text)
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolicyConditions {
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub path_glob: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, HeaderCondition>,
    #[serde(default)]
    pub input_contains: Vec<String>,
    #[serde(default)]
    pub input_regex: Vec<String>,
    #[serde(default)]
    pub token_count: Option<TokenRange>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "value")]
pub enum HeaderCondition {
    Exists,
    Equals(String),
    Regex(String),
}

#[derive(Debug, Clone, Deserialize)]
pub struct TokenRange {
    #[serde(default)]
    pub min: Option<usize>,
    #[serde(default)]
    pub max: Option<usize>,
}

impl Default for TokenRange {
    fn default() -> Self {
        Self {
            min: None,
            max: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct PolicyFile {
    #[serde(default)]
    policy: Vec<PolicyRule>,
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to read policy from {0:?}: {1}")]
    Io(PathBuf, #[source] std::io::Error),
    #[error("failed to parse policy file {0:?}: {1}")]
    Parse(PathBuf, toml::de::Error),
    #[error("invalid policy rule '{rule}': {reason}")]
    InvalidRule { rule: String, reason: String },
}

impl From<std::io::Error> for PolicyError {
    fn from(error: std::io::Error) -> Self {
        PolicyError::Io(PathBuf::new(), error)
    }
}

pub type PolicyResult<T> = Result<T, PolicyError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn higher_priority_rule_takes_precedence() -> Result<(), PolicyError> {
        let allow_rule = PolicyRule {
            name: "allow_default".to_string(),
            description: None,
            priority: Some(10),
            action: PolicyAction::Allow,
            conditions: PolicyConditions::default(),
        };

        let deny_rule = PolicyRule {
            name: "deny_secret".to_string(),
            description: None,
            priority: Some(100),
            action: PolicyAction::Deny,
            conditions: PolicyConditions {
                input_regex: vec!["secret".to_string()],
                ..PolicyConditions::default()
            },
        };

        let engine = PolicyEngine::with_rules(PolicyMode::Allow, vec![allow_rule, deny_rule])?;

        let headers = HashMap::new();

        let deny_context = PolicyContext::new(
            "POST",
            "/v1/chat/completions",
            &headers,
            Some("this prompt leaks secret info"),
            Some(10),
        );
        let deny_decision = engine.evaluate(&deny_context);
        assert_eq!(deny_decision.action, PolicyAction::Deny);
        assert_eq!(
            deny_decision
                .rule
                .as_ref()
                .map(|summary| summary.name.as_str()),
            Some("deny_secret")
        );

        let allow_context = PolicyContext::new(
            "POST",
            "/v1/chat/completions",
            &headers,
            Some("regular prompt"),
            Some(10),
        );
        let allow_decision = engine.evaluate(&allow_context);
        assert_eq!(allow_decision.action, PolicyAction::Allow);

        Ok(())
    }

    #[test]
    fn glob_and_method_conditions_match() -> Result<(), PolicyError> {
        let warn_rule = PolicyRule {
            name: "warn_get_chat".to_string(),
            description: None,
            priority: Some(50),
            action: PolicyAction::Warn,
            conditions: PolicyConditions {
                method: Some("GET".to_string()),
                path_glob: Some("/v1/chat/*".to_string()),
                ..PolicyConditions::default()
            },
        };

        let engine = PolicyEngine::with_rules(PolicyMode::Allow, vec![warn_rule])?;

        let headers = HashMap::new();

        let warn_context = PolicyContext::new("GET", "/v1/chat/history", &headers, None, Some(10));
        let decision = engine.evaluate(&warn_context);
        assert_eq!(decision.action, PolicyAction::Warn);

        let allow_context =
            PolicyContext::new("POST", "/v1/chat/history", &headers, None, Some(10));
        let allow_decision = engine.evaluate(&allow_context);
        assert_eq!(allow_decision.action, PolicyAction::Allow);

        Ok(())
    }
}
