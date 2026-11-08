//! MCP client to a downstream tool server.
//! Execution is crate-private and needs an Authorization, so outside this crate
//! the only way to run a tool is through the Gate. Proven by tests/ui/bypass_exec.rs.

use std::{ffi::OsStr, path::Path, sync::Arc};

use anyhow::{Context as _, Result};
use authz_core::{Hints, ToolResult, ToolSpec};
use rmcp::{
    RoleClient, ServiceExt,
    model::{CallToolRequestParams, CallToolResult, ServerPeerInfo},
    service::{RunningService, ServiceError},
    transport::TokioChildProcess,
};
use tokio::process::Command;

use crate::token::Authorization;

pub struct Mcp {
    svc: RunningService<RoleClient, ()>,
}

impl Mcp {
    /// Launch any MCP server over stdio. `env` is applied on top of the inherited
    /// environment; the child's stdin/stdout become the protocol channel.
    pub async fn connect(
        program: impl AsRef<OsStr>,
        args: &[String],
        env: &[(String, String)],
    ) -> Result<Self> {
        let mut cmd = Command::new(program);
        cmd.args(args);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let svc = ().serve(TokioChildProcess::new(cmd)?).await.context("mcp handshake")?;
        Ok(Self { svc })
    }

    /// The bundled simulated tool server, pinned to a sandbox and fixture tree.
    pub async fn spawn(
        server: &Path,
        args: &[String],
        sandbox: &Path,
        fixtures: &Path,
    ) -> Result<Self> {
        let env = [
            ("AUTHZ_SANDBOX".into(), sandbox.display().to_string()),
            ("AUTHZ_FIXTURES".into(), fixtures.display().to_string()),
        ];
        Self::connect(server, args, &env).await
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

    /// The downstream tool list, unmodified, for faithful pass-through.
    pub(crate) async fn list_raw(&self) -> Result<Vec<rmcp::model::Tool>, ServiceError> {
        self.svc.list_all_tools().await
    }

    /// What the downstream server said about itself at handshake.
    pub fn downstream_info(&self) -> Option<Arc<ServerPeerInfo>> {
        self.svc.peer_info()
    }

    pub async fn close(self) -> Result<()> {
        self.svc.cancel().await?;
        Ok(())
    }

    /// Full-fidelity call: keeps structured content, images and tool errors intact.
    pub(crate) async fn exec_raw(
        &self,
        auth: Authorization,
    ) -> Result<CallToolResult, ServiceError> {
        let call = auth.call();
        let req = CallToolRequestParams::new(call.tool.clone()).with_arguments(call.args.clone());
        self.svc.call_tool(req).await
    }

    /// Text-only call, for the bundled agent whose transcript is text.
    pub(crate) async fn exec(&self, auth: Authorization) -> ToolResult {
        let text = match self.exec_raw(auth).await {
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
