//! Risk scoring for actions.
//!
//! Where the policy engine answers "is this allowed by the rules?", risk scoring
//! answers "how dangerous does this look?". A set of [`RiskAnalyzer`]s inspect an
//! [`ActionRequest`] and emit weighted [`RiskSignal`]s; the [`RiskEngine`]
//! aggregates them into a single [`RiskScore`] on a 0–100 scale.
//!
//! Policy rules can then match on risk (e.g. "require approval when risk ≥ 60"),
//! and the engine can escalate high-risk actions to approval automatically.
//!
//! The built-in analyzers are intentionally simple, string-level heuristics
//! (destructive commands, secret-looking arguments, prompt-injection and
//! jailbreak phrasing). They are a useful backstop, not a guarantee — hardening
//! them is ordinary feature work.

use serde::{Deserialize, Serialize};

use crate::action::ActionRequest;
use crate::config::RiskConfig;

/// A coarse risk band derived from a [`RiskScore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    /// Score 0–24.
    Low,
    /// Score 25–49.
    Medium,
    /// Score 50–74.
    High,
    /// Score 75–100.
    Critical,
}

/// A single risk observation contributed by an analyzer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskSignal {
    /// Stable machine code, e.g. `destructive_command` or `secret_in_argument`.
    pub code: String,
    /// How much this signal contributes to the aggregate score (0–100).
    pub weight: u8,
    /// Human-readable explanation.
    pub detail: String,
}

impl RiskSignal {
    /// Create a risk signal.
    pub fn new(code: impl Into<String>, weight: u8, detail: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            weight,
            detail: detail.into(),
        }
    }
}

/// The aggregated risk for an action: a 0–100 value plus the signals behind it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskScore {
    /// Aggregate score, saturating at 100.
    pub value: u8,
    /// The signals that contributed to the score.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<RiskSignal>,
}

impl RiskScore {
    /// A zero score with no signals.
    pub fn none() -> Self {
        Self::default()
    }

    /// Build a score from signals, summing their weights (saturating at 100).
    pub fn from_signals(signals: Vec<RiskSignal>) -> Self {
        let value = signals
            .iter()
            .fold(0u16, |acc, s| acc + s.weight as u16)
            .min(100) as u8;
        Self { value, signals }
    }

    /// The band this score falls into.
    pub fn level(&self) -> RiskLevel {
        match self.value {
            0..=24 => RiskLevel::Low,
            25..=49 => RiskLevel::Medium,
            50..=74 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }
}

/// Inspects an action and reports any risk signals it finds.
pub trait RiskAnalyzer: Send + Sync {
    /// The analyzer's stable name (for configuration and diagnostics).
    fn name(&self) -> &str;
    /// Emit any risk signals for `request`.
    fn analyze(&self, request: &ActionRequest) -> Vec<RiskSignal>;
}

/// Flags shell commands that destroy data or hardware at scale.
pub struct DestructiveCommandAnalyzer;

impl RiskAnalyzer for DestructiveCommandAnalyzer {
    fn name(&self) -> &str {
        "destructive_command"
    }

    fn analyze(&self, request: &ActionRequest) -> Vec<RiskSignal> {
        if request.action != crate::action::actions::EXEC
            && request.action != crate::action::actions::NET_REMOTE
        {
            return Vec::new();
        }

        let cmd = request.resource.to_lowercase();
        let patterns = [
            ("rm -rf /", "recursive delete from root"),
            ("rm -rf /*", "recursive delete of root contents"),
            ("rm -rf ~", "recursive delete of home"),
            ("mkfs", "filesystem format"),
            ("dd if=", "raw disk write via dd"),
            ("of=/dev/sd", "raw write to block device"),
            ("of=/dev/nvme", "raw write to nvme device"),
            (":(){", "fork bomb"),
        ];

        patterns
            .iter()
            .filter(|(needle, _)| cmd.contains(needle))
            .map(|(_, detail)| RiskSignal::new("destructive_command", 80, *detail))
            .collect()
    }
}

/// Flags arguments that look like they embed a credential.
pub struct SecretAnalyzer;

impl RiskAnalyzer for SecretAnalyzer {
    fn name(&self) -> &str {
        "secret_in_argument"
    }

    fn analyze(&self, request: &ActionRequest) -> Vec<RiskSignal> {
        let haystack = request.resource.to_lowercase();
        let markers = [
            "api_key",
            "api-key",
            "secret",
            "password",
            "bearer ",
            "-----begin",
        ];
        if markers.iter().any(|m| haystack.contains(m)) {
            vec![RiskSignal::new(
                "secret_in_argument",
                40,
                "argument contains credential-like text",
            )]
        } else {
            Vec::new()
        }
    }
}

/// Flags prompt-injection phrasing in the action or its context.
pub struct InjectionAnalyzer;

impl RiskAnalyzer for InjectionAnalyzer {
    fn name(&self) -> &str {
        "prompt_injection"
    }

    fn analyze(&self, request: &ActionRequest) -> Vec<RiskSignal> {
        let haystack = request.resource.to_lowercase();
        let phrases = [
            "ignore previous instructions",
            "disregard all prior",
            "system: you are now",
        ];
        if phrases.iter().any(|p| haystack.contains(p)) {
            vec![RiskSignal::new(
                "prompt_injection",
                50,
                "resource contains prompt-injection phrasing",
            )]
        } else {
            Vec::new()
        }
    }
}

/// Flags jailbreak phrasing in the action or its context.
pub struct JailbreakAnalyzer;

impl RiskAnalyzer for JailbreakAnalyzer {
    fn name(&self) -> &str {
        "jailbreak"
    }

    fn analyze(&self, request: &ActionRequest) -> Vec<RiskSignal> {
        let haystack = request.resource.to_lowercase();
        let phrases = ["do anything now", "jailbreak"];
        if phrases.iter().any(|p| haystack.contains(p)) {
            vec![RiskSignal::new(
                "jailbreak",
                40,
                "resource contains jailbreak phrasing",
            )]
        } else {
            Vec::new()
        }
    }
}

/// Runs a set of analyzers and aggregates their signals into a [`RiskScore`].
pub struct RiskEngine {
    analyzers: Vec<Box<dyn RiskAnalyzer>>,
}

impl RiskEngine {
    /// A risk engine with no analyzers; every action scores zero.
    pub fn empty() -> Self {
        Self {
            analyzers: Vec::new(),
        }
    }

    /// Build a risk engine from configuration, enabling the built-in analyzers
    /// the config selects.
    pub fn from_config(config: &RiskConfig) -> Self {
        if !config.enabled {
            return Self::empty();
        }

        let mut analyzers: Vec<Box<dyn RiskAnalyzer>> = Vec::new();
        if config.detect_destructive {
            analyzers.push(Box::new(DestructiveCommandAnalyzer));
        }
        if config.detect_secrets {
            analyzers.push(Box::new(SecretAnalyzer));
        }
        if config.detect_injection {
            analyzers.push(Box::new(InjectionAnalyzer));
            analyzers.push(Box::new(JailbreakAnalyzer));
        }
        Self { analyzers }
    }

    /// Register an additional analyzer.
    pub fn with_analyzer(mut self, analyzer: Box<dyn RiskAnalyzer>) -> Self {
        self.analyzers.push(analyzer);
        self
    }

    /// Score a request by running every analyzer and summing their signals.
    pub fn score(&self, request: &ActionRequest) -> RiskScore {
        let signals: Vec<RiskSignal> = self
            .analyzers
            .iter()
            .flat_map(|a| a.analyze(request))
            .collect();
        RiskScore::from_signals(signals)
    }
}

impl Default for RiskEngine {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::actions;

    fn engine() -> RiskEngine {
        RiskEngine::empty()
            .with_analyzer(Box::new(DestructiveCommandAnalyzer))
            .with_analyzer(Box::new(SecretAnalyzer))
    }

    #[test]
    fn destructive_command_scores_high() {
        let req = ActionRequest::new(actions::EXEC, "rm -rf / --no-preserve-root");
        let score = engine().score(&req);
        assert!(score.value >= 75);
        assert_eq!(score.level(), RiskLevel::Critical);
    }

    #[test]
    fn benign_command_scores_zero() {
        let req = ActionRequest::new(actions::EXEC, "ls -la");
        let score = engine().score(&req);
        assert_eq!(score.value, 0);
        assert_eq!(score.level(), RiskLevel::Low);
    }

    #[test]
    fn weights_saturate_at_100() {
        let req = ActionRequest::new(actions::EXEC, "rm -rf / with api_key=secret password");
        let score = engine().score(&req);
        assert_eq!(score.value, 100);
    }
}
