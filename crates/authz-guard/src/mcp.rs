//! MCP client over stdio to the tool server.
//! Execution is crate-private and needs an Authorization, so outside this crate
//! the only way to run a tool is the Interceptor. Proven by tests/ui/bypass_exec.rs.

use std::path::Path;

use anyhow::{Context as _, Result};
use authz_core::ToolResult;
use rmcp::{
    RoleClient, ServiceExt,
    model::CallToolRequestParams,
    service::RunningService,
    transport::TokioChildProcess,
};
use tokio::process::Command;

use crate::token::Authorization;

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

    pub(crate) async fn exec(&self, auth: Authorization) -> ToolResult {
        let call = auth.call();
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
