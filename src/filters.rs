use crate::config::{FiltersConfig, InputFiltersConfig, OutputFiltersConfig};
use serde::Serialize;
use std::{borrow::Cow, fmt};
use thiserror::Error;

#[derive(Debug, Default, Clone)]
pub struct FilterEngine {
    input: InputFiltersConfig,
    output: OutputFiltersConfig,
}

impl FilterEngine {
    pub fn new(config: &FiltersConfig) -> Self {
        Self {
            input: config.input.clone(),
            output: config.output.clone(),
        }
    }

    pub fn inspect_input<'a>(&self, text: &'a str) -> Result<FilterVerdict<'a>, FilterError> {
        if !self.input.enabled {
            return Ok(FilterVerdict::allow());
        }

        let mut verdict = FilterVerdict::allow();
        if self.input.detect_injection && looks_like_prompt_injection(text) {
            verdict.block(FilterViolation::PromptInjection(Cow::Owned(
                "Potential prompt injection detected".to_string(),
            )));
        }

        if self.input.detect_jailbreak && looks_like_jailbreak(text) {
            verdict.warn(FilterViolation::Jailbreak(Cow::Owned(
                "Possible jailbreak attempt".to_string(),
            )));
        }

        Ok(verdict)
    }

    pub fn inspect_output<'a>(&self, text: &'a str) -> Result<FilterVerdict<'a>, FilterError> {
        if !self.output.enabled {
            return Ok(FilterVerdict::allow());
        }

        let mut verdict = FilterVerdict::allow();
        if self.output.scan_pii && text.contains("@") {
            // basic placeholder scan
            verdict.redact(FilterViolation::Pii(Cow::Owned(
                "Output appears to contain an email address".to_string(),
            )));
        }

        if self.output.scan_secrets && text.to_lowercase().contains("api_key") {
            verdict.block(FilterViolation::Secret(Cow::Owned(
                "Output appears to contain a secret".to_string(),
            )));
        }

        Ok(verdict)
    }
}

fn looks_like_prompt_injection(text: &str) -> bool {
    let lowered = text.to_lowercase();
    lowered.contains("ignore previous instructions")
        || lowered.contains("disregard all prior")
        || lowered.contains("system: you are now")
}

fn looks_like_jailbreak(text: &str) -> bool {
    let lowered = text.to_lowercase();
    lowered.contains("do anything now") || lowered.contains("jailbreak")
}

#[derive(Debug, Default, Serialize)]
pub struct FilterVerdict<'a> {
    pub decision: FilterDecision,
    pub violations: Vec<FilterViolation<'a>>,
}

impl<'a> FilterVerdict<'a> {
    pub fn allow() -> Self {
        Self {
            decision: FilterDecision::Allow,
            violations: Vec::new(),
        }
    }

    pub fn block(&mut self, violation: FilterViolation<'a>) {
        self.decision = FilterDecision::Block;
        self.violations.push(violation);
    }

    pub fn warn(&mut self, violation: FilterViolation<'a>) {
        if self.decision != FilterDecision::Block {
            self.decision = FilterDecision::Warn;
        }
        self.violations.push(violation);
    }

    pub fn redact(&mut self, violation: FilterViolation<'a>) {
        if self.decision != FilterDecision::Block {
            self.decision = FilterDecision::Redact;
        }
        self.violations.push(violation);
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FilterDecision {
    #[default]
    Allow,
    Warn,
    Redact,
    Block,
}

#[derive(Debug, Clone, Serialize)]
pub enum FilterViolation<'a> {
    PromptInjection(Cow<'a, str>),
    Jailbreak(Cow<'a, str>),
    Pii(Cow<'a, str>),
    Secret(Cow<'a, str>),
    Custom {
        code: Cow<'a, str>,
        message: Cow<'a, str>,
    },
}

impl fmt::Display for FilterDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            FilterDecision::Allow => "allow",
            FilterDecision::Warn => "warn",
            FilterDecision::Redact => "redact",
            FilterDecision::Block => "block",
        };
        f.write_str(text)
    }
}

impl<'a> fmt::Display for FilterViolation<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterViolation::PromptInjection(msg)
            | FilterViolation::Jailbreak(msg)
            | FilterViolation::Pii(msg)
            | FilterViolation::Secret(msg) => f.write_str(msg),
            FilterViolation::Custom { code, message } => {
                write!(f, "{}: {}", code, message)
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum FilterError {
    #[error("filter engine misconfiguration: {0}")]
    Misconfigured(&'static str),
}
