//! In-process front end for the bundled agent. All verdicts come from `Gate`.

use std::sync::Arc;

use authz_core::{Context, Executor, Policy, ToolCall, ToolResult, ToolSpec};

use crate::{approval::Approver, audit::Audit, gate::Gate, mcp::Mcp};

pub struct Interceptor {
    mcp: Mcp,
    gate: Gate,
    catalog: Vec<ToolSpec>,
}

impl Interceptor {
    pub async fn new(
        mcp: Mcp,
        policy: Box<dyn Policy>,
        approver: Arc<dyn Approver>,
        audit: Audit,
        ctx: Context,
    ) -> anyhow::Result<Self> {
        let tools = mcp.tools().await?;
        let gate = Gate::new(policy, approver, audit, ctx);
        gate.set_hints(tools.iter().map(|(s, h)| (s.name.clone(), *h)));
        let catalog = tools.into_iter().map(|(s, _)| s).collect();
        Ok(Self { mcp, gate, catalog })
    }

    /// What the model may be told about. Descriptions only; execution stays here.
    pub fn catalog(&self) -> &[ToolSpec] {
        &self.catalog
    }

    pub async fn close(self) -> anyhow::Result<()> {
        self.mcp.close().await
    }
}

impl Executor for Interceptor {
    async fn exec(&self, call: &ToolCall) -> ToolResult {
        let auth = match self.gate.check(call) {
            Ok(a) => a,
            Err(d) => return ToolResult::new(d.message),
        };
        let r = self.mcp.exec(auth).await;
        self.gate.observe(call, &r.text);
        r
    }
}
