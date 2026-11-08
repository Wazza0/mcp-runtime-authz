//! The one decision path: decide, log, ask a human if escalated, mint an Authorization.
//!
//! Both front ends use this and nothing else. The in-process `Interceptor` serves the
//! bundled agent; the `proxy` serves any MCP client. Neither re-implements a verdict.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use authz_core::{Context, Decision, Hints, Policy, Taint, ToolCall};

use crate::{
    approval::Approver,
    audit::Audit,
    token::{Authorization, Refusal, approve, authorize},
};

/// Why a call was refused, in the words the agent is allowed to hear.
pub struct Denied {
    pub message: String,
}

/// What the agent sees. Deliberately says nothing about which rule fired or why:
/// that detail would let injected instructions probe the policy and retry around it.
/// Humans read the reason in the audit log via the reference.
fn denied(seq: Option<u64>, what: &str) -> Denied {
    let r = seq.map(|n| format!(" (audit #{n})")).unwrap_or_default();
    Denied { message: format!("BLOCKED: {what}{r}") }
}

fn audit_down() -> Denied {
    denied(None, "the decision could not be recorded, so the action was not run")
}

fn describe(call: &ToolCall) -> String {
    let first = call.args.values().find_map(|v| v.as_str()).unwrap_or_default();
    format!("{} {}", call.tool, first.chars().take(80).collect::<String>())
}

pub struct Gate {
    policy: Box<dyn Policy>,
    approver: Arc<dyn Approver>,
    audit: Audit,
    ctx: Mutex<Context>,
}

impl Gate {
    pub fn new(
        policy: Box<dyn Policy>,
        approver: Arc<dyn Approver>,
        audit: Audit,
        ctx: Context,
    ) -> Self {
        Self { policy, approver, audit, ctx: Mutex::new(ctx) }
    }

    /// Record the tool annotations the server declared. Untrusted; policy may only
    /// tighten on them.
    pub fn set_hints(&self, hints: impl IntoIterator<Item = (String, Hints)>) {
        self.ctx().tools = hints.into_iter().collect();
    }

    /// Survives a poisoned lock: dropping history or taint here would fail open.
    fn ctx(&self) -> MutexGuard<'_, Context> {
        self.ctx.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn snapshot(&self) -> Context {
        self.ctx().clone()
    }

    /// Ok means the call is authorized and the decision is already on disk.
    pub fn check(&self, call: &ToolCall) -> Result<Authorization, Denied> {
        let ctx = self.snapshot();
        match authorize(self.policy.as_ref(), call, &ctx) {
            Ok(a) => match self.audit.record(call, &Decision::Allow, "executing") {
                Ok(_) => Ok(a),
                Err(_) => Err(audit_down()),
            },
            Err(Refusal::Blocked(d)) => {
                let seq = self.audit.record(call, &d, "not executed").ok();
                Err(denied(seq, "this action is not permitted by policy"))
            }
            Err(Refusal::Pending(esc)) => {
                let d = esc.decision().clone();
                if self.audit.record(call, &d, "awaiting approval").is_err() {
                    return Err(audit_down());
                }
                let a = self.approver.review(call, &d);
                let Ok(seq) = self.audit.answer(call, &d, a.granted, &a.by) else {
                    return Err(audit_down());
                };
                approve(*esc, &a).map_err(|_| denied(Some(seq), "a reviewer declined this action"))
            }
        }
    }

    /// Refuse for a reason outside the policy, e.g. a tool that changed since it was pinned.
    /// Same message to the agent as a policy refusal; the detail goes to the audit log.
    pub fn refuse(&self, call: &ToolCall, d: &Decision) -> Denied {
        let seq = self.audit.record(call, d, "not executed").ok();
        denied(seq, "this action is not permitted by policy")
    }

    /// Record what an executed call returned, so later calls can be judged against it.
    /// Called by the front end with the real output; the model never writes here.
    pub fn observe(&self, call: &ToolCall, text: &str) {
        let label = self.policy.taint(&call.tool);
        let mut c = self.ctx();
        c.history.push(call.clone());
        if let Some(label) = label {
            let step = c.history.len();
            c.taint.push(Taint { label, source: describe(call), step, text: text.to_string() });
        }
    }
}
