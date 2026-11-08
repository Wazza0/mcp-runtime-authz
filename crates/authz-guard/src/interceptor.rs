//! The only path to tool execution: decide, log, ask a human if escalated, then run.

use std::sync::{Arc, Mutex};

use authz_core::{Context, Decision, Executor, Policy, ToolCall, ToolResult, ToolSpec};

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

fn blocked(d: &Decision, extra: &str) -> ToolResult {
    ToolResult::trusted(format!("BLOCKED [{}]: {}{extra}", d.rule(), d.reason()))
}

fn audit_down(e: std::io::Error) -> ToolResult {
    blocked(&Decision::block("audit", format!("audit log unavailable: {e}")), "")
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
                let _ = self.audit.record(call, &d, "not executed");
                return blocked(&d, "");
            }
            Err(Refusal::Pending(esc)) => {
                let d = esc.decision().clone();
                if let Err(e) = self.audit.record(call, &d, "awaiting approval") {
                    return audit_down(e);
                }
                let a = self.approver.review(call, &d);
                if let Err(e) = self.audit.answer(call, &d, a.granted, &a.by) {
                    return audit_down(e);
                }
                match approve(esc, &a) {
                    Ok(auth) => auth,
                    Err(d) => return blocked(&d, &format!(" (denied by {})", a.by)),
                }
            }
        };
        let r = self.mcp.exec(auth).await;
        if let Ok(mut c) = self.ctx.lock() {
            c.history.push(call.clone());
        }
        r
    }
}
