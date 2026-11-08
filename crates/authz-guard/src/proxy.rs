//! MCP proxy: an MCP server to your client, an MCP client to the real server.
//!
//! Put it between an agent and the tools it already uses. Every `tools/call` goes
//! through the same `Gate` as the bundled agent, so there is one decision path.
//!
//! stdout is the protocol channel, so nothing here may print to it. stdin is too, so a
//! console approver cannot run in this mode; escalations fail closed unless the
//! configured approver answers without a terminal.

use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use anyhow::Result;
use authz_core::{Context, Decision, Policy, ToolCall};
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, ListToolsResult,
        PaginatedRequestParams, ServerConfig, Tool,
    },
    service::RequestContext,
    transport::stdio,
};

use crate::{
    approval::Approver,
    audit::Audit,
    gate::Gate,
    mcp::Mcp,
    pin::{Drift, Pins, fingerprint},
};

/// Where to keep tool pins, and whether to accept the server's current tools as the new pins.
pub struct PinFile {
    pub path: PathBuf,
    pub repin: bool,
}

pub struct Proxy {
    down: Mcp,
    gate: Gate,
    pins: Option<Pins>,
    /// Latest fingerprint seen for each tool, refreshed on every listing.
    seen: Mutex<BTreeMap<String, String>>,
}

fn err(what: &str, e: impl std::fmt::Display) -> McpError {
    McpError::internal_error(format!("downstream {what}: {e}"), None)
}

impl Proxy {
    pub async fn new(
        down: Mcp,
        policy: Box<dyn Policy>,
        approver: Arc<dyn Approver>,
        audit: Audit,
        ctx: Context,
        pin: Option<PinFile>,
    ) -> Result<Self> {
        let gate = Gate::new(policy, approver, audit, ctx);
        let tools = down.tools().await?;
        gate.set_hints(tools.into_iter().map(|(s, h)| (s.name, h)));
        let raw = down.list_raw().await?;
        let pins = match pin {
            None => None,
            Some(f) => {
                let now = Pins::of(&raw);
                match Pins::load(&f.path)? {
                    Some(old) if !f.repin => Some(old),
                    _ => {
                        now.save(&f.path)?;
                        eprintln!(
                            "authz proxy: pinned {} tools to {}",
                            now.tools.len(),
                            f.path.display()
                        );
                        Some(now)
                    }
                }
            }
        };
        let p = Self { down, gate, pins, seen: Mutex::new(BTreeMap::new()) };
        p.remember(&raw);
        if let Some(pins) = &p.pins {
            for t in &raw {
                if let Some(d) = pins.drift(&t.name, &fingerprint(t)) {
                    eprintln!(
                        "authz proxy: tool {} {} since it was pinned: hidden and refused \
                         (review the change, then run with --repin to accept it)",
                        t.name,
                        if d == Drift::Changed { "changed" } else { "appeared" }
                    );
                }
            }
        }
        Ok(p)
    }

    /// Serve on stdio until the client disconnects.
    pub async fn run(self) -> Result<()> {
        ServiceExt::serve(self, stdio()).await?.waiting().await?;
        Ok(())
    }

    fn remember(&self, tools: &[Tool]) {
        if let Ok(mut s) = self.seen.lock() {
            *s = tools.iter().map(|t| (t.name.to_string(), fingerprint(t))).collect();
        }
    }

    /// Whether this tool has drifted from its pin. Unknown tools count as new.
    async fn drift(&self, name: &str) -> Result<Option<Drift>, McpError> {
        let Some(pins) = &self.pins else { return Ok(None) };
        let mut fp = self.seen.lock().ok().and_then(|s| s.get(name).cloned());
        if fp.is_none() {
            self.remember(&self.down.list_raw().await.map_err(|e| err("list_tools", e))?);
            fp = self.seen.lock().ok().and_then(|s| s.get(name).cloned());
        }
        Ok(fp.map_or(Some(Drift::New), |fp| pins.drift(name, &fp)))
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

    /// A tool that drifted from its pin is left out, so its new description never
    /// reaches the agent.
    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut tools = self.down.list_raw().await.map_err(|e| err("list_tools", e))?;
        self.remember(&tools);
        if let Some(pins) = &self.pins {
            tools.retain(|t| pins.drift(&t.name, &fingerprint(t)).is_none());
        }
        Ok(ListToolsResult { tools, ..Default::default() })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let call =
            ToolCall::new(request.name.to_string(), request.arguments.clone().unwrap_or_default());
        // Ok(error result), not Err: a protocol error would hide the message.
        let refused = |msg: String| Ok(CallToolResult::error(vec![ContentBlock::text(msg)]).into());
        if let Some(d) = self.drift(&call.tool).await? {
            let why = format!("{} differs from its pinned definition ({})", call.tool, d.rule());
            return refused(self.gate.refuse(&call, &Decision::block(d.rule(), why)).message);
        }
        let auth = match self.gate.check(&call) {
            Ok(a) => a,
            Err(d) => return refused(d.message),
        };
        let res = self.down.exec_raw(auth).await.map_err(|e| err("call_tool", e))?;
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
