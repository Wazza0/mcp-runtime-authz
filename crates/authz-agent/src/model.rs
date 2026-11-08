//! Model backends. The runner only sees the Model trait, so backends are swappable.

use anyhow::Result;
use authz_core::{ToolCall, ToolResult};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;

use crate::scenario::PlanStep;

pub enum Step {
    Call(ToolCall),
    Done(String),
}

pub trait Model {
    fn next(
        &mut self,
        task: &str,
        log: &[(ToolCall, ToolResult)],
    ) -> impl Future<Output = Result<Step>> + Send;
}

/// Deterministic stand-in for a maximally compliant agent.
///
/// Steps with `when` fire only if that trigger text has appeared in a tool result,
/// so injected behavior happens *because* untrusted content reached the model,
/// never unconditionally. This is the threat model's "helpful but manipulable" agent.
pub struct Scripted {
    plan: Vec<PlanStep>,
    at: usize,
}

impl Scripted {
    pub fn new(plan: Vec<PlanStep>) -> Self {
        Self { plan, at: 0 }
    }
}

impl Model for Scripted {
    async fn next(&mut self, _task: &str, log: &[(ToolCall, ToolResult)]) -> Result<Step> {
        while let Some(s) = self.plan.get(self.at) {
            self.at += 1;
            if let Some(t) = &s.when {
                let t = t.to_lowercase();
                if !log.iter().any(|(_, r)| r.text.to_lowercase().contains(&t)) {
                    continue;
                }
            }
            let last = log.last().map(|(_, r)| r.text.trim()).unwrap_or_default();
            let args = s
                .args
                .iter()
                .map(|(k, v)| (k.clone(), fill(v, last)))
                .collect();
            return Ok(Step::Call(ToolCall::new(&s.tool, args)));
        }
        Ok(Step::Done("done".into()))
    }
}

/// `{last}` = previous tool output verbatim, `{last_url}` = percent-encoded,
/// `{last_b64}` = base64 (an attacker evading pattern matching).
fn fill(v: &Value, last: &str) -> Value {
    match v {
        Value::String(s) => Value::String(
            s.replace("{last_url}", &encode(last))
                .replace("{last_b64}", &URL_SAFE_NO_PAD.encode(last))
                .replace("{last}", last),
        ),
        _ => v.clone(),
    }
}

fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}
