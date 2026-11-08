//! Shared types. Everything in the system hangs off ToolCall, Context, Decision.

use std::collections::BTreeMap;

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

/// The engine: ToolCall + Context -> Decision. Pure, no side effects.
pub trait Policy: Send + Sync {
    fn decide(&self, call: &ToolCall, ctx: &Context) -> Decision;
}

/// Anything that can run a tool call. The agent only ever holds one of these.
pub trait Executor {
    fn exec(&self, call: &ToolCall) -> impl Future<Output = ToolResult> + Send;
}

/// Tool annotations as declared by the MCP server. Untrusted: the server may lie,
/// so policy may only use these to tighten a decision, never to loosen one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hints {
    pub read_only: bool,
    pub destructive: bool,
    pub open_world: bool,
}

impl Hints {
    /// Applies the MCP spec defaults for absent hints (pessimistic).
    pub fn from_mcp(read_only: Option<bool>, destructive: Option<bool>, open_world: Option<bool>) -> Self {
        let read_only = read_only.unwrap_or(false);
        Self {
            read_only,
            destructive: !read_only && destructive.unwrap_or(true),
            open_world: open_world.unwrap_or(true),
        }
    }
}

/// What the guard knows about the session when it judges a call.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Context {
    /// The task the user actually asked for. Trusted; entities named here are permitted.
    pub task: String,
    pub scope: Vec<String>,
    pub history: Vec<ToolCall>,
    /// Fragments of untrusted data seen so far (M4).
    pub taint: Vec<String>,
    pub tools: BTreeMap<String, Hints>,
}

impl Context {
    pub fn new(task: impl Into<String>, scope: Vec<String>) -> Self {
        Self { task: task.into(), scope, ..Default::default() }
    }
}
