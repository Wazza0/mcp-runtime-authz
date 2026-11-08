//! Shared types. Everything in the system hangs off ToolCall, Context, Decision.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub type Args = Map<String, Value>;

/// Who originated a value: user prompt, model output, or a tool result.
/// Tool-sourced data is untrusted; M4 propagates that as taint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    User,
    Model,
    Tool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub tool: String,
    pub args: Args,
    pub source: Source,
}

impl ToolCall {
    pub fn new(tool: impl Into<String>, args: Args) -> Self {
        Self { tool: tool.into(), args, source: Source::Model }
    }

    pub fn arg(&self, k: &str) -> &str {
        self.args.get(k).and_then(Value::as_str).unwrap_or_default()
    }

    /// Every string in args, flattened. Used for argument inspection.
    pub fn strings(&self) -> Vec<&str> {
        self.args.values().filter_map(Value::as_str).collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub text: String,
    /// Set when the content came from outside the trust boundary.
    pub tainted: bool,
    pub origin: Option<String>,
}

impl ToolResult {
    pub fn trusted(text: impl Into<String>) -> Self {
        Self { text: text.into(), tainted: false, origin: None }
    }

    pub fn untrusted(text: impl Into<String>, origin: impl Into<String>) -> Self {
        Self { text: text.into(), tainted: true, origin: Some(origin.into()) }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Block { reason: String, rule: String },
    Escalate { reason: String, rule: String },
}

impl Decision {
    pub fn block(rule: &str, reason: impl Into<String>) -> Self {
        Self::Block { reason: reason.into(), rule: rule.into() }
    }

    pub fn escalate(rule: &str, reason: impl Into<String>) -> Self {
        Self::Escalate { reason: reason.into(), rule: rule.into() }
    }

    pub fn allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    pub fn reason(&self) -> &str {
        match self {
            Self::Allow => "within policy",
            Self::Block { reason, .. } | Self::Escalate { reason, .. } => reason,
        }
    }

    pub fn rule(&self) -> &str {
        match self {
            Self::Allow => "-",
            Self::Block { rule, .. } | Self::Escalate { rule, .. } => rule,
        }
    }
}

/// Anything that can run a tool call. The agent only ever holds one of these.
pub trait Executor {
    fn exec(&self, call: &ToolCall) -> impl Future<Output = ToolResult> + Send;
}

/// What the guard knows about the session when it judges a call.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Context {
    /// The task the user actually asked for. Scope is derived from this.
    pub task: String,
    pub scope: Vec<String>,
    pub history: Vec<ToolCall>,
    /// Fragments of untrusted data seen so far (M4).
    pub taint: Vec<String>,
}

impl Context {
    pub fn new(task: impl Into<String>, scope: Vec<String>) -> Self {
        Self { task: task.into(), scope, history: Vec::new(), taint: Vec::new() }
    }
}
