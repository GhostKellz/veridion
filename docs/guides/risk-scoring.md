# Risk Scoring

The risk engine scores each `ActionRequest` for danger before a decision is finalized. The
score is advisory input to policy: rules can match on it via `min_risk` / `max_risk`, and
the engine escalates an `allow` to `require_approval` when the score reaches
`approval_threshold`. This is about grading how dangerous a *request* is, not about
inspecting or altering any model output.

## Signals and Scores

`RiskEngine` runs a set of `RiskAnalyzer`s over the request. Each analyzer emits zero or
more `RiskSignal { code, weight: u8, detail }`. The engine combines them into a
`RiskScore { value: u8, signals }`, where `value` is a saturating sum in the range 0–100.

The score maps to a `RiskLevel`:

| Level | Range |
|-------|-------|
| Low | 0–24 |
| Medium | 25–49 |
| High | 50–74 |
| Critical | 75–100 |

## Built-in Analyzers

Each analyzer is toggled through `[risk]` configuration.

| Analyzer | Weight | Detects |
|----------|--------|---------|
| `DestructiveCommandAnalyzer` | 80 per hit | `rm -rf /`, `rm -rf /*`, `rm -rf ~`, `mkfs`, `dd if=`, `of=/dev/sd`, `of=/dev/nvme`, fork bomb — only on `exec` and `net.remote` |
| `SecretAnalyzer` | 40 | resource contains `api_key`, `api-key`, `secret`, `password`, `bearer `, or `-----begin` |
| `InjectionAnalyzer` | 50 | `ignore previous instructions`, `disregard all prior`, `system: you are now` |
| `JailbreakAnalyzer` | 40 | `do anything now`, `jailbreak` |

Matching is case-insensitive substring matching.

## Configuration

```toml
[risk]
enabled = true
detect_destructive = true
detect_secrets = true
detect_injection = true       # enables BOTH injection and jailbreak analyzers
approval_threshold = 50       # escalate allows at or above this score
```

`detect_injection` enables the injection and jailbreak analyzers together. With the
defaults above, a destructive `exec` scores 80 (Critical) and, if a rule allows it, is
escalated to approval because it exceeds `approval_threshold`.

## Heuristic Status

These analyzers are simple string heuristics. They are a useful backstop that raises the
cost of the obviously dangerous cases, **not a security boundary** — do not rely on them to
catch a determined adversary. Enforce real controls with [policy rules](writing-policies.md)
and route uncertain cases through [approvals](approvals.md).

## Matching on Risk in Policy

Because the score is attached to the decision, rules can gate on the risk band:

```toml
[[policy]]
name = "approve_high_risk_exec"
priority = 80
effect = "require_approval"

[policy.conditions]
action = "exec"
min_risk = 50                 # High or Critical only
```

See [Writing Policies](writing-policies.md) for the full evaluation model.

## Custom Analyzers

Implement the `RiskAnalyzer` trait and register it on the engine. The trait is two methods:

```rust
struct WeekendAnalyzer;

impl RiskAnalyzer for WeekendAnalyzer {
    fn name(&self) -> &str {
        "weekend"
    }

    fn analyze(&self, request: &ActionRequest) -> Vec<RiskSignal> {
        if request.action == "net.remote" {
            vec![RiskSignal {
                code: "off_hours_network".into(),
                weight: 20,
                detail: "outbound network action".into(),
            }]
        } else {
            Vec::new()
        }
    }
}

let engine = RiskEngine::default().with_analyzer(Box::new(WeekendAnalyzer));
```

Custom signals are summed with the built-ins, so they raise the score and can trip both
`min_risk` rules and `approval_threshold` escalation.

## Next Steps

- [Writing Policies](writing-policies.md) - Match on `min_risk` / `max_risk`
- [Approvals](approvals.md) - What happens when risk escalates a decision
