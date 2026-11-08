//! The only path to tool execution: decide, log, ask a human if escalated, then run.

use std::sync::{Arc, Mutex};

use authz_core::{Context, Decision, Executor, Policy, Taint, ToolCall, ToolResult, ToolSpec};

use crate::{
    approval::Approver,
    audit::Audit,
    mcp::Mcp,
    token::{Refusal, approve, authorize},
};

pub struct Interceptor {
    mcp: Mcp,
    policy: Box<dyn Policy>,
    approver: Arc<dyn Approver>,
    audit: Audit,
    ctx: Mutex<Context>,
    catalog: Vec<ToolSpec>,
}

/// What the agent sees. Deliberately says nothing about which rule fired or why:
/// that detail would let injected instructions probe the policy and retry around it.
/// Humans read the reason in the audit log via the reference.
fn blocked(seq: Option<u64>, what: &str) -> ToolResult {
    let r = seq.map(|n| format!(" (audit #{n})")).unwrap_or_default();
    ToolResult::new(format!("BLOCKED: {what}{r}"))
}

fn describe(call: &ToolCall) -> String {
    let first = call.args.values().find_map(|v| v.as_str()).unwrap_or_default();
    format!("{} {}", call.tool, first.chars().take(80).collect::<String>())
}

fn audit_down(_: std::io::Error) -> ToolResult {
    blocked(None, "the decision could not be recorded, so the action was not run")
}

impl Interceptor {
    pub async fn new(
        mcp: Mcp,
        policy: Box<dyn Policy>,
        approver: Arc<dyn Approver>,
        audit: Audit,
        mut ctx: Context,
    ) -> anyhow::Result<Self> {
        let tools = mcp.tools().await?;
        ctx.tools = tools.iter().map(|(s, h)| (s.name.clone(), *h)).collect();
        let catalog = tools.into_iter().map(|(s, _)| s).collect();
        Ok(Self { mcp, policy, approver, audit, ctx: Mutex::new(ctx), catalog })
    }

    /// What the model may be told about. Descriptions only; execution stays here.
    pub fn catalog(&self) -> &[ToolSpec] {
        &self.catalog
    }

    pub async fn close(self) -> anyhow::Result<()> {
        self.mcp.close().await
    }

    fn snapshot(&self) -> Context {
        self.ctx.lock().map(|c| c.clone()).unwrap_or_default()
    }
}

impl Executor for Interceptor {
    async fn exec(&self, call: &ToolCall) -> ToolResult {
        let ctx = self.snapshot();
        let auth = match authorize(self.policy.as_ref(), call, &ctx) {
            Ok(a) => {
                if let Err(e) = self.audit.record(call, &Decision::Allow, "executing") {
                    return audit_down(e);
                }
                a
            }
            Err(Refusal::Blocked(d)) => {
                let seq = self.audit.record(call, &d, "not executed").ok();
                return blocked(seq, "this action is not permitted by policy");
            }
            Err(Refusal::Pending(esc)) => {
                let d = esc.decision().clone();
                if let Err(e) = self.audit.record(call, &d, "awaiting approval") {
                    return audit_down(e);
                }
                let a = self.approver.review(call, &d);
                let seq = match self.audit.answer(call, &d, a.granted, &a.by) {
                    Ok(n) => n,
                    Err(e) => return audit_down(e),
                };
                match approve(esc, &a) {
                    Ok(auth) => auth,
                    Err(_) => return blocked(Some(seq), "a reviewer declined this action"),
                }
            }
        };
        let r = self.mcp.exec(auth).await;
        let label = self.policy.taint(&call.tool);
        if let Ok(mut c) = self.ctx.lock() {
            c.history.push(call.clone());
            if let Some(label) = label {
                let step = c.history.len();
                c.taint.push(Taint { label, source: describe(call), step, text: r.text.clone() });
            }
        }
        r
    }
}
