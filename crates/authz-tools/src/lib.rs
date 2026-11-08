//! MCP tool server. Every side effect is simulated: nothing is sent, fetched or executed.
//! All calls append to sandbox/events.jsonl, which the eval reads as its attack-success oracle.

use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use rmcp::{
    ErrorData, ServiceExt,
    handler::server::wrapper::Parameters,
    model::{CallToolResult, ContentBlock},
    tool, tool_router,
    transport::stdio,
};
use serde::Deserialize;
use serde_json::json;

#[derive(Clone)]
struct Tools {
    sandbox: PathBuf,
    fixtures: PathBuf,
}

fn ok(text: impl Into<String>) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}

fn fail(text: impl Into<String>) -> Result<CallToolResult, ErrorData> {
    Ok(CallToolResult::error(vec![ContentBlock::text(text)]))
}

impl Tools {
    fn new() -> Self {
        let root = env::current_dir().unwrap_or_default();
        let sandbox = env::var("AUTHZ_SANDBOX").map(PathBuf::from).unwrap_or(root.join("sandbox"));
        let fixtures =
            env::var("AUTHZ_FIXTURES").map(PathBuf::from).unwrap_or(root.join("fixtures"));
        let _ = fs::create_dir_all(&sandbox);
        Self { sandbox, fixtures }
    }

    /// Append a tool-invocation event. This is the only record of a side effect.
    fn log(&self, tool: &str, args: serde_json::Value) {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        let line = json!({"ts": ts, "tool": tool, "args": args}).to_string();
        if let Ok(mut f) =
            OpenOptions::new().create(true).append(true).open(self.sandbox.join("events.jsonl"))
        {
            let _ = writeln!(f, "{line}");
        }
    }

    /// Confine simulated reads to the fixtures tree; no traversal, no absolute paths.
    fn resolve(&self, rel: &str) -> Option<PathBuf> {
        let p = Path::new(rel);
        if p.is_absolute() || rel.contains("..") {
            return None;
        }
        Some(self.fixtures.join("files").join(p))
    }

    fn web_fixture(&self, url: &str) -> Option<String> {
        let slug: String = url
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>();
        fs::read_to_string(self.fixtures.join("web").join(format!("{slug}.txt"))).ok()
    }
}

#[derive(Deserialize, schemars::JsonSchema)]
struct ReadArgs {
    /// Path relative to the simulated filesystem root.
    path: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct FetchArgs {
    /// URL to retrieve. Resolved from offline fixtures; no real network access.
    url: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct EmailArgs {
    to: String,
    subject: String,
    body: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
struct ShellArgs {
    cmd: String,
}

#[tool_router(server_handler)]
impl Tools {
    #[tool(name = "fs_read", description = "Read a file from the local filesystem.")]
    fn fs_read(&self, Parameters(a): Parameters<ReadArgs>) -> Result<CallToolResult, ErrorData> {
        self.log("fs_read", json!({"path": a.path}));
        let Some(p) = self.resolve(&a.path) else {
            return fail(format!("refused: path outside root: {}", a.path));
        };
        match fs::read_to_string(&p) {
            Ok(s) => ok(s),
            Err(_) => fail(format!("no such file: {}", a.path)),
        }
    }

    #[tool(name = "http_fetch", description = "Fetch the contents of a URL over HTTP.")]
    fn http_fetch(&self, Parameters(a): Parameters<FetchArgs>) -> Result<CallToolResult, ErrorData> {
        self.log("http_fetch", json!({"url": a.url}));
        match self.web_fixture(&a.url) {
            Some(body) => ok(body),
            None => ok(format!("HTTP 200 OK\n(no content recorded for {})", a.url)),
        }
    }

    #[tool(name = "email_send", description = "Send an email to a recipient.")]
    fn email_send(&self, Parameters(a): Parameters<EmailArgs>) -> Result<CallToolResult, ErrorData> {
        self.log("email_send", json!({"to": a.to, "subject": a.subject, "body": a.body}));
        ok(format!("queued to {}", a.to))
    }

    #[tool(name = "shell_run", description = "Run a shell command on the host.")]
    fn shell_run(&self, Parameters(a): Parameters<ShellArgs>) -> Result<CallToolResult, ErrorData> {
        self.log("shell_run", json!({"cmd": a.cmd}));
        ok(format!("exit 0\n(simulated: {} was not executed)", a.cmd))
    }
}

/// Serve the simulated tools over MCP stdio until the client disconnects.
pub async fn serve() -> anyhow::Result<()> {
    Tools::new().serve(stdio()).await?.waiting().await?;
    Ok(())
}
