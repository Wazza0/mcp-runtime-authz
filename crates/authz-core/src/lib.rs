//! Shared types. Everything in the system hangs off ToolCall, Context, Decision.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub type Args = Map<String, Value>;

/// Who proposed a call. Every call reaching the guard today comes from the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    User,
    Model,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub text: String,
}

impl ToolResult {
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Decision {
    Allow,
    /// `also`: other rules that matched but were not the most severe.
    Block {
        reason: String,
        rule: String,
        #[serde(default)]
        also: Vec<String>,
    },
    Escalate {
        reason: String,
        rule: String,
        #[serde(default)]
        also: Vec<String>,
    },
}

impl Decision {
    pub fn block(rule: &str, reason: impl Into<String>) -> Self {
        Self::Block { reason: reason.into(), rule: rule.into(), also: Vec::new() }
    }

    pub fn escalate(rule: &str, reason: impl Into<String>) -> Self {
        Self::Escalate { reason: reason.into(), rule: rule.into(), also: Vec::new() }
    }

    pub fn with_also(mut self, ids: Vec<String>) -> Self {
        if let Self::Block { also, .. } | Self::Escalate { also, .. } = &mut self {
            *also = ids;
        }
        self
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

    pub fn also(&self) -> &[String] {
        match self {
            Self::Allow => &[],
            Self::Block { also, .. } | Self::Escalate { also, .. } => also,
        }
    }
}

/// The engine: ToolCall + Context -> Decision. Pure, no side effects.
pub trait Policy: Send + Sync {
    fn decide(&self, call: &ToolCall, ctx: &Context) -> Decision;

    /// Label to attach to this tool's output, if the policy tracks it as tainted.
    fn taint(&self, _tool: &str) -> Option<String> {
        None
    }
}

/// Anything that can run a tool call. The agent only ever holds one of these.
pub trait Executor {
    fn exec(&self, call: &ToolCall) -> impl Future<Output = ToolResult> + Send;
}

/// A tool as described to the model. Plain data: holding one grants no ability to run it.
/// The description comes from the server, so it is untrusted text.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub schema: Value,
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
    pub fn from_mcp(
        read_only: Option<bool>,
        destructive: Option<bool>,
        open_world: Option<bool>,
    ) -> Self {
        let read_only = read_only.unwrap_or(false);
        Self {
            read_only,
            destructive: !read_only && destructive.unwrap_or(true),
            open_world: open_world.unwrap_or(true),
        }
    }
}

/// Output of an executed call that the policy labeled. Recorded by the interceptor,
/// never by the model, so the agent cannot launder data by claiming it is clean.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Taint {
    pub label: String,
    /// e.g. `fs_read notes/roadmap.md`
    pub source: String,
    pub step: usize,
    pub text: String,
}

/// What the guard knows about the session when it judges a call.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Context {
    /// The task the user actually asked for. Trusted; entities named here are permitted.
    pub task: String,
    pub scope: Vec<String>,
    pub history: Vec<ToolCall>,
    pub taint: Vec<Taint>,
    pub tools: BTreeMap<String, Hints>,
}

impl Context {
    pub fn new(task: impl Into<String>, scope: Vec<String>) -> Self {
        Self { task: task.into(), scope, ..Default::default() }
    }
}
