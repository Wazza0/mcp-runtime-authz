//! The proxy in front of the official MCP filesystem server
//! (`@modelcontextprotocol/server-filesystem`), driven by the official SDK client.
//!
//! Opt-in: needs Node and network for `npx`. Run with
//! `cargo test -p authz-cli --test proxy_filesystem -- --ignored`.

use std::{fs, path::Path};

use rmcp::{
    ServiceExt,
    model::{CallToolRequestParams, CallToolResult},
    transport::TokioChildProcess,
};
use serde_json::{Value, json};
use tokio::process::Command;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap()
}

fn text(r: &CallToolResult) -> String {
    r.content.iter().filter_map(|c| c.as_text().map(|t| t.text.clone())).collect::<Vec<_>>().join("\n")
}

fn call(name: &str, args: Value) -> CallToolRequestParams {
    CallToolRequestParams::new(name.to_string()).with_arguments(args.as_object().unwrap().clone())
}

#[tokio::test]
#[ignore = "needs node + network (npx @modelcontextprotocol/server-filesystem)"]
async fn guards_the_official_filesystem_server() {
    let work = root().join("sandbox").join("test-proxy-fs");
    let _ = fs::remove_dir_all(&work);
    let dir = work.join("project");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("notes.md"), "Ship the parser fix by Friday.\n").unwrap();
    fs::write(dir.join(".env"), "API_TOKEN=sk-live-FAKE0000demo0000key\n").unwrap();
    let audit = work.join("audit.jsonl");
    let d = dir.to_string_lossy().replace('\\', "/");

    let npx = if cfg!(windows) { "npx.cmd" } else { "npx" };
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_authz"));
    cmd.args(["proxy", "--policy"])
        .arg(root().join("policies").join("filesystem.yaml"))
        .arg("--audit")
        .arg(&audit)
        .args(["--", npx, "-y", "@modelcontextprotocol/server-filesystem"])
        .arg(&dir);
    let client = ().serve(TokioChildProcess::new(cmd).unwrap()).await.unwrap();
    assert!(client.list_all_tools().await.unwrap().iter().any(|t| t.name == "read_multiple_files"));

    let ok = [
        ("read_text_file", json!({"path": format!("{d}/notes.md")})),
        ("write_file", json!({"path": format!("{d}/notes2.md"), "content": "hello"})),
    ];
    for (tool, args) in ok {
        let r = client.call_tool(call(tool, args)).await.unwrap();
        assert_ne!(r.is_error, Some(true), "{tool}: {}", text(&r));
    }

    let refused = [
        ("read_text_file", json!({"path": format!("{d}/.env")})),
        ("read_multiple_files", json!({"paths": [format!("{d}/notes.md"), format!("{d}/.env")]})),
        ("write_file", json!({"path": format!("{d}/.git/hooks/pre-commit"), "content": "echo x"})),
        ("write_file", json!({"path": format!("{d}/config.txt"), "content": "k=sk-live-FAKE0000demo0000key"})),
    ];
    for (tool, args) in refused {
        let r = client.call_tool(call(tool, args.clone())).await.unwrap();
        let t = text(&r);
        assert_eq!(r.is_error, Some(true), "{tool} {args}: {t}");
        assert!(t.starts_with("BLOCKED") && !t.contains("sk-live"), "{tool}: {t}");
    }
    client.cancel().await.unwrap();

    assert!(dir.join("notes2.md").exists());
    assert!(!dir.join("config.txt").exists() && !dir.join(".git").exists(), "a refused write landed");
    let log = fs::read_to_string(&audit).unwrap();
    for rule in ["sensitive-read", "runs-later-write", "secret-write"] {
        assert!(log.contains(rule), "audit missing {rule}");
    }
}
