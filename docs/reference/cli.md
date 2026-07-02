# CLI

The `veridion` binary is a thin wrapper over the library. It reads a JSON
[`ActionRequest`](library-api.md#action--the-request) on stdin, authorizes it,
and prints the resulting `Authorization` as pretty JSON on stdout. The exit code
reflects the outcome, so it can gate a shell pipeline.

```bash
echo '{"action":"exec","resource":"ls -la"}' | veridion && run-the-thing
```

## Input

A single JSON object on stdin, deserialized into an `ActionRequest`:

```json
{
  "action": "exec",
  "resource": "git push origin main",
  "subject": { "id": "jarvis", "roles": ["agent"] },
  "context": { "repo": "veridion" }
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `action` | yes | The action verb, e.g. `exec`, `fs.read`, `net.remote` |
| `resource` | yes | The target: a command, path, host, URL, etc. |
| `subject` | no | `{ "id": string, "roles": [string], "on_behalf_of": string }`; defaults to `unknown` with no roles |
| `context` | no | A flat map of attribute name to value (text, integer, bool, or list) |

## Output

The `Authorization` as pretty-printed JSON:

```json
{
  "decision": {
    "effect": "deny",
    "reason": "matched rule 'deny_git_push'",
    "matched_rule": { "name": "deny_git_push" },
    "risk": { "value": 0 }
  },
  "permitted": false
}
```

The `decision` object carries `effect` (`allow`, `deny`, or `require_approval`),
`reason`, an optional `matched_rule`, and the computed `risk`. An `approval`
field (`approved` or `denied`) appears when the decision required approval.
`permitted` is the final verdict after policy and approval.

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | The action is permitted |
| `1` | The action is not permitted (denied, or approval refused) |
| `2` | An error occurred (bad JSON, config load failure, audit error) |

## Configuration

The config path is read from the `VERIDION_CONFIG` environment variable. When
unset, the built-in defaults apply: deny-by-default policy, SQLite audit, risk
analysis on.

```bash
printf '%s\n' '{"action":"fs.read","resource":"src/lib.rs"}' \
  | VERIDION_CONFIG=/etc/veridion/veridion.toml veridion
```

Approval mode follows the config's `[approval]` section. In `interactive` mode a
`require_approval` decision prompts on the controlling terminal; in the default
headless `deny` mode it is refused.

## Examples

An allowed action exits `0` and prints an `allow` decision:

```bash
$ echo '{"action":"fs.read","resource":"src/lib.rs",
         "subject":{"id":"jarvis","roles":["agent"]}}' | veridion
{
  "decision": {
    "effect": "allow",
    "reason": "matched rule 'allow_reads'",
    "matched_rule": { "name": "allow_reads" },
    "risk": { "value": 0 }
  },
  "permitted": true
}
$ echo $?
0
```

A denied action exits `1`. Here the always-deny floor blocks a catastrophic
command regardless of policy:

```bash
$ echo '{"action":"exec","resource":"rm -rf / --no-preserve-root"}' | veridion
{
  "decision": {
    "effect": "deny",
    "reason": "blocked by always-deny floor: floor_rm_root",
    "matched_rule": { "name": "floor_rm_root" },
    "risk": { "value": 100, "signals": [ ... ] }
  },
  "permitted": false
}
$ echo $?
1
```

## Next Steps

- [Library API](library-api.md) - The types the CLI serializes
- [Policy Language](policy-language.md) - Authoring the rules that produce these decisions
- [Architecture](../internals/architecture.md) - The authorize lifecycle behind each call
