//! MCP client over stdio to the tool server. Raw execution, no policy.

use std::path::Path;

use anyhow::{Context as _, Result};
use authz_core::{Executor, ToolCall, ToolResult};
use rmcp::{
    RoleClient, ServiceExt,
    model::CallToolRequestParams,
    service::RunningService,
    transport::TokioChildProcess,
};
use tokio::process::Command;

/// Tools whose output originates outside the trust boundary.
const UNTRUSTED: &[&str] = &["http_fetch", "fs_read"];

pub struct Mcp {
    svc: RunningService<RoleClient, ()>,
}

impl Mcp {
    pub async fn spawn(
        server: &Path,
        args: &[String],
        sandbox: &Path,
        fixtures: &Path,
    ) -> Result<Self> {
        let mut cmd = Command::new(server);
        cmd.args(args).env("AUTHZ_SANDBOX", sandbox).env("AUTHZ_FIXTURES", fixtures);
        let svc = ().serve(TokioChildProcess::new(cmd)?).await.context("mcp handshake")?;
        Ok(Self { svc })
    }

    pub async fn tools(&self) -> Result<Vec<String>> {
        Ok(self.svc.list_all_tools().await?.into_iter().map(|t| t.name.into_owned()).collect())
    }

    pub async fn close(self) -> Result<()> {
        self.svc.cancel().await?;
        Ok(())
    }

    pub(crate) async fn raw(&self, call: &ToolCall) -> ToolResult {
        let req = CallToolRequestParams::new(call.tool.clone()).with_arguments(call.args.clone());
        let text = match self.svc.call_tool(req).await {
            Ok(r) => r
                .content
                .iter()
                .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
                .collect::<Vec<_>>()
                .join("\n"),
            Err(e) => format!("tool error: {e}"),
        };
        if UNTRUSTED.contains(&call.tool.as_str()) {
            ToolResult::untrusted(text, call.tool.clone())
        } else {
            ToolResult::trusted(text)
        }
    }
}

/// M0 only: unguarded direct execution. Replaced by the interceptor in M1.
impl Executor for Mcp {
    async fn exec(&self, call: &ToolCall) -> ToolResult {
        self.raw(call).await
    }
}
