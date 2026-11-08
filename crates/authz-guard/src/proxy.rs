//! MCP proxy: an MCP server to your client, an MCP client to the real server.
//!
//! Put it between an agent and the tools it already uses. Every `tools/call` goes
//! through the same `Gate` as the bundled agent, so there is one decision path.
//!
//! stdout is the protocol channel, so nothing here may print to it. stdin is too, so a
//! console approver cannot run in this mode; escalations fail closed unless the
//! configured approver answers without a terminal.

use std::sync::Arc;

use anyhow::Result;
use authz_core::{Context, Policy, ToolCall};
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
        PaginatedRequestParams, ServerConfig,
    },
    service::RequestContext,
    transport::stdio,
};

use crate::{approval::Approver, audit::Audit, gate::Gate, mcp::Mcp};

pub struct Proxy {
    down: Mcp,
    gate: Gate,
}

impl Proxy {
    pub async fn new(
        down: Mcp,
        policy: Box<dyn Policy>,
        approver: Arc<dyn Approver>,
        audit: Audit,
        ctx: Context,
    ) -> Result<Self> {
        let gate = Gate::new(policy, approver, audit, ctx);
        let tools = down.tools().await?;
        gate.set_hints(tools.into_iter().map(|(s, h)| (s.name, h)));
        Ok(Self { down, gate })
    }

    /// Serve on stdio until the client disconnects.
    pub async fn run(self) -> Result<()> {
        ServiceExt::serve(self, stdio()).await?.waiting().await?;
        Ok(())
    }
}

impl ServerHandler for Proxy {
    /// Mirror the downstream server so the client sees the same tools and capabilities,
    /// with the name marked so it is obvious the guard is in the path.
    fn get_info(&self) -> ServerConfig {
        let mut cfg = ServerConfig::default();
        let mut down = "downstream".to_string();
        if let Some(i) = self.down.downstream_info() {
            cfg.protocol_version = i.protocol_version.clone();
            cfg.capabilities = i.capabilities.clone();
            if let Some(s) = i.server_info.clone() {
                down = s.name.clone();
                cfg.server_info = s;
            }
        }
        cfg.server_info.name = format!("authz-guard({down})");
        cfg.instructions = Some(format!(
            "Calls to {down} are checked against a least-privilege policy before they run. \
             A refused call returns a BLOCKED message with an audit reference; the reason is \
             recorded in the audit log, not returned here."
        ));
        cfg
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let tools =
            self.down.list_raw().await.map_err(|e| {
                McpError::internal_error(format!("downstream list_tools: {e}"), None)
            })?;
        Ok(ListToolsResult { tools, ..Default::default() })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let call =
            ToolCall::new(request.name.to_string(), request.arguments.clone().unwrap_or_default());
        let auth = match self.gate.check(&call) {
            Ok(a) => a,
            // Ok(error result), not Err: a protocol error would hide the message.
            Err(d) => return Ok(CallToolResult::error(vec![ContentBlock::text(d.message)]).into()),
        };
        let res =
            self.down.exec_raw(auth).await.map_err(|e| {
                McpError::internal_error(format!("downstream call_tool: {e}"), None)
            })?;
        let text = res
            .content
            .iter()
            .filter_map(|c| c.as_text().map(|t| t.text.as_str()))
            .collect::<Vec<_>>()
            .join("\n");
        self.gate.observe(&call, &text);
        Ok(res.into())
    }
}
