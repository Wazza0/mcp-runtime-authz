//! The only path to tool execution: decide, log, then (maybe) run.

use std::sync::Mutex;

use authz_core::{Context, Decision, Executor, Policy, ToolCall, ToolResult};

use crate::{audit::Audit, mcp::Mcp, token::authorize};

pub struct Interceptor {
    mcp: Mcp,
    policy: Box<dyn Policy>,
    audit: Audit,
    ctx: Mutex<Context>,
}

impl Interceptor {
    pub async fn new(
        mcp: Mcp,
        policy: Box<dyn Policy>,
        audit: Audit,
        mut ctx: Context,
    ) -> anyhow::Result<Self> {
        ctx.tools = mcp.tools().await?.into_iter().collect();
        Ok(Self { mcp, policy, audit, ctx: Mutex::new(ctx) })
    }

    pub async fn close(self) -> anyhow::Result<()> {
        self.mcp.close().await
    }

    fn snapshot(&self) -> Context {
        self.ctx.lock().map(|c| c.clone()).unwrap_or_default()
    }

    fn refuse(&self, call: &ToolCall, d: &Decision) -> ToolResult {
        let _ = self.audit.record(call, d, "not executed");
        ToolResult::trusted(format!("BLOCKED [{}]: {}", d.rule(), d.reason()))
    }
}

impl Executor for Interceptor {
    async fn exec(&self, call: &ToolCall) -> ToolResult {
        let ctx = self.snapshot();
        let auth = match authorize(self.policy.as_ref(), call, &ctx) {
            Ok(a) => a,
            // M3 adds the human-approval path; until then escalate fails closed.
            Err(d) => return self.refuse(call, &d),
        };
        if let Err(e) = self.audit.record(call, &Decision::Allow, "executing") {
            let d = Decision::block("audit", format!("audit log unavailable: {e}"));
            return ToolResult::trusted(format!("BLOCKED [{}]: {}", d.rule(), d.reason()));
        }
        let r = self.mcp.exec(auth).await;
        if let Ok(mut c) = self.ctx.lock() {
            c.history.push(call.clone());
        }
        r
    }
}
