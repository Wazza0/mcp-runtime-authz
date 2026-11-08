//! MCP client over stdio to the tool server.
//! Execution is crate-private and needs an Authorization, so outside this crate
//! the only way to run a tool is the Interceptor. Proven by tests/ui/bypass_exec.rs.

use std::path::Path;

use anyhow::{Context as _, Result};
use authz_core::{Hints, ToolResult, ToolSpec};
use rmcp::{
    RoleClient, ServiceExt,
    model::CallToolRequestParams,
    service::RunningService,
    transport::TokioChildProcess,
};
use tokio::process::Command;

use crate::token::Authorization;

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

    /// Tool descriptions with their server-declared (untrusted) annotations.
    pub async fn tools(&self) -> Result<Vec<(ToolSpec, Hints)>> {
        Ok(self
            .svc
            .list_all_tools()
            .await?
            .into_iter()
            .map(|t| {
                let a = t.annotations.unwrap_or_default();
                let h = Hints::from_mcp(a.read_only_hint, a.destructive_hint, a.open_world_hint);
                let spec = ToolSpec {
                    name: t.name.into_owned(),
                    description: t.description.map(|d| d.into_owned()).unwrap_or_default(),
                    schema: serde_json::Value::Object((*t.input_schema).clone()),
                };
                (spec, h)
            })
            .collect())
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
        ToolResult::new(text)
    }
}
