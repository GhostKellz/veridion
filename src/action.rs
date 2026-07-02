//! The unit of authorization: an [`ActionRequest`].
//!
//! Veridion authorizes *actions*, not network traffic. An agent that is about to
//! do something consequential — run a shell command, write a file, delegate to
//! another agent — describes that intent as an [`ActionRequest`] and asks the
//! [`PolicyEngine`](crate::policy::PolicyEngine) whether it may proceed.
//!
//! The shape is deliberately close to attribute-based access control (ABAC): a
//! `subject` performs an `action` on a `resource` within a `context` of
//! arbitrary attributes that rules can match against.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Well-known action verbs.
///
/// Actions are namespaced strings so any agent can introduce its own verbs
/// without a breaking change. These constants cover the common cases and map
/// directly onto the action categories an agent runtime already distinguishes
/// (shell, filesystem, delegation, remote execution, durable memory).
pub mod actions {
    /// Execute a shell command.
    pub const EXEC: &str = "exec";
    /// Read a file or directory.
    pub const FS_READ: &str = "fs.read";
    /// Create or overwrite a file.
    pub const FS_WRITE: &str = "fs.write";
    /// Modify an existing file in place.
    pub const FS_EDIT: &str = "fs.edit";
    /// Hand work to another agent or tool.
    pub const AGENT_DELEGATE: &str = "agent.delegate";
    /// Execute something on a remote host.
    pub const NET_REMOTE: &str = "net.remote";
    /// Persist a durable fact to long-term memory.
    pub const MEMORY_REMEMBER: &str = "memory.remember";
}

/// Who is requesting an action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    /// Stable identity of the actor (agent name, service, or user).
    pub id: String,
    /// The principal the actor operates on behalf of, when different from `id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
    /// Roles or capabilities used for ABAC matching.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
}

impl Subject {
    /// A subject identified only by `id`, with no roles.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            on_behalf_of: None,
            roles: Vec::new(),
        }
    }

    /// Attach a role, returning the updated subject.
    pub fn with_role(mut self, role: impl Into<String>) -> Self {
        self.roles.push(role.into());
        self
    }

    /// Record the principal this actor is acting for.
    pub fn on_behalf_of(mut self, principal: impl Into<String>) -> Self {
        self.on_behalf_of = Some(principal.into());
        self
    }

    /// Whether the subject holds the named role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }
}

impl Default for Subject {
    fn default() -> Self {
        Self::new("unknown")
    }
}

/// A typed context attribute value.
///
/// Attributes are the ABAC inputs a policy rule can match on — for example the
/// repository a command runs in, the model driving the agent, or whether the
/// session is interactive. Kept to a small closed set of types so rule matching
/// stays simple and predictable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AttributeValue {
    /// A text value.
    Text(String),
    /// A whole number.
    Integer(i64),
    /// A boolean flag.
    Bool(bool),
    /// A list of text values (e.g. tags, groups).
    List(Vec<String>),
}

impl AttributeValue {
    /// Borrow the value as text, if it is textual.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            AttributeValue::Text(s) => Some(s),
            _ => None,
        }
    }

    /// Read the value as an integer, if it is numeric.
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            AttributeValue::Integer(n) => Some(*n),
            _ => None,
        }
    }

    /// Read the value as a boolean, if it is boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            AttributeValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Whether `needle` is present in this value (membership for lists, equality
    /// for text). Used by `in`/`contains` rule conditions.
    pub fn contains(&self, needle: &str) -> bool {
        match self {
            AttributeValue::Text(s) => s == needle,
            AttributeValue::List(items) => items.iter().any(|i| i == needle),
            _ => false,
        }
    }
}

impl From<&str> for AttributeValue {
    fn from(value: &str) -> Self {
        AttributeValue::Text(value.to_string())
    }
}

impl From<String> for AttributeValue {
    fn from(value: String) -> Self {
        AttributeValue::Text(value)
    }
}

impl From<i64> for AttributeValue {
    fn from(value: i64) -> Self {
        AttributeValue::Integer(value)
    }
}

impl From<bool> for AttributeValue {
    fn from(value: bool) -> Self {
        AttributeValue::Bool(value)
    }
}

impl From<Vec<String>> for AttributeValue {
    fn from(value: Vec<String>) -> Self {
        AttributeValue::List(value)
    }
}

/// The attribute bag an action carries for ABAC evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Context {
    /// Attributes keyed by name (ordered for stable serialization).
    pub attributes: BTreeMap<String, AttributeValue>,
}

impl Context {
    /// An empty context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set an attribute, returning the updated context.
    pub fn with(mut self, key: impl Into<String>, value: impl Into<AttributeValue>) -> Self {
        self.attributes.insert(key.into(), value.into());
        self
    }

    /// Look up an attribute by name.
    pub fn get(&self, key: &str) -> Option<&AttributeValue> {
        self.attributes.get(key)
    }
}

/// A request to perform a single action, pending authorization.
///
/// Build one with [`ActionRequest::new`] and the chaining setters:
///
/// ```
/// use veridion::action::{ActionRequest, Subject, actions};
///
/// let request = ActionRequest::new(actions::EXEC, "rm -rf /tmp/cache")
///     .subject(Subject::new("jarvis").with_role("agent"))
///     .attr("repo", "veridion")
///     .attr("interactive", true);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRequest {
    /// The action verb (see [`actions`] for well-known values).
    pub action: String,
    /// The target of the action: a command, path, agent name, URL, etc.
    pub resource: String,
    /// Who is asking.
    #[serde(default)]
    pub subject: Subject,
    /// Attributes describing the surrounding situation.
    #[serde(default)]
    pub context: Context,
}

impl ActionRequest {
    /// Create a request for `action` on `resource` with a default subject and
    /// empty context.
    pub fn new(action: impl Into<String>, resource: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            resource: resource.into(),
            subject: Subject::default(),
            context: Context::new(),
        }
    }

    /// Set the subject.
    pub fn subject(mut self, subject: Subject) -> Self {
        self.subject = subject;
        self
    }

    /// Add a context attribute.
    pub fn attr(mut self, key: impl Into<String>, value: impl Into<AttributeValue>) -> Self {
        self.context = self.context.with(key, value);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_sets_fields() {
        let request = ActionRequest::new(actions::EXEC, "ls")
            .subject(Subject::new("jarvis").with_role("agent"))
            .attr("repo", "veridion")
            .attr("count", 3i64);

        assert_eq!(request.action, "exec");
        assert_eq!(request.resource, "ls");
        assert!(request.subject.has_role("agent"));
        assert_eq!(
            request
                .context
                .get("repo")
                .and_then(AttributeValue::as_text),
            Some("veridion")
        );
        assert_eq!(
            request
                .context
                .get("count")
                .and_then(AttributeValue::as_integer),
            Some(3)
        );
    }

    #[test]
    fn attribute_contains_matches_list_and_text() {
        let list = AttributeValue::from(vec!["a".to_string(), "b".to_string()]);
        assert!(list.contains("a"));
        assert!(!list.contains("c"));

        let text = AttributeValue::from("hello");
        assert!(text.contains("hello"));
        assert!(!text.contains("world"));
    }
}
