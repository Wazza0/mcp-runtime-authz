//! Tool pinning end to end: a tool whose definition changed, or that appeared after
//! pinning, is hidden from the agent and refused, until the change is accepted.

use std::{fs, path::Path};

use rmcp::{
    RoleClient, ServiceExt,
    model::{CallToolRequestParams, CallToolResult},
    service::RunningService,
    transport::TokioChildProcess,
};
use serde_json::{Value, json};
use tokio::process::Command;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap()
}

fn text(r: &CallToolResult) -> String {
    r.content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn call(name: &str, args: Value) -> CallToolRequestParams {
    CallToolRequestParams::new(name.to_string()).with_arguments(args.as_object().unwrap().clone())
}

async fn proxy(run: &Path, pin: &Path, extra: &[&str]) -> RunningService<RoleClient, ()> {
    fs::create_dir_all(run).unwrap();
    let bin = env!("CARGO_BIN_EXE_authz");
    let mut cmd = Command::new(bin);
    cmd.current_dir(root())
        .env("AUTHZ_SANDBOX", run)
        .env("AUTHZ_FIXTURES", root().join("fixtures"))
        .args(["proxy", "--policy", "policies/example-proxy.yaml", "--audit"])
        .arg(run.join("audit.jsonl"))
        .arg("--pin")
        .arg(pin)
        .args(extra)
        .args(["--", bin, "serve-tools"]);
    ().serve(TokioChildProcess::new(cmd).unwrap()).await.unwrap()
}

async fn names(c: &RunningService<RoleClient, ()>) -> Vec<String> {
    let mut v: Vec<_> =
        c.list_all_tools().await.unwrap().into_iter().map(|t| t.name.into_owned()).collect();
    v.sort();
    v
}

#[tokio::test]
async fn drifted_tools_are_hidden_and_refused_until_repinned() {
    let dir = root().join("sandbox").join("test-pin");
    let _ = fs::remove_dir_all(&dir);
    let pin = dir.join("tools.lock");

    let c = proxy(&dir.join("first"), &pin, &[]).await;
    assert_eq!(names(&c).await, ["email_send", "fs_read", "http_fetch", "shell_run"]);
    c.cancel().await.unwrap();
    let mut pins: Value = serde_json::from_str(&fs::read_to_string(&pin).unwrap()).unwrap();
    assert_eq!(pins["tools"].as_object().unwrap().len(), 4, "first run pins every tool");

    // As if the server edited fs_read and added http_fetch after the pin was taken.
    pins["tools"]["fs_read"] = json!("sha256:0000");
    pins["tools"].as_object_mut().unwrap().remove("http_fetch");
    fs::write(&pin, pins.to_string()).unwrap();

    let run = dir.join("drifted");
    let c = proxy(&run, &pin, &[]).await;
    assert_eq!(names(&c).await, ["email_send", "shell_run"], "drifted tools are hidden");
    for (tool, args) in [
        ("fs_read", json!({"path": "notes/meeting.md"})),
        ("http_fetch", json!({"url": "http://docs.test/x"})),
    ] {
        let r = c.call_tool(call(tool, args)).await.unwrap();
        assert_eq!(r.is_error, Some(true), "{tool}");
        assert!(text(&r).starts_with("BLOCKED") && !text(&r).contains("tool-"), "{}", text(&r));
    }
    c.cancel().await.unwrap();
    let audit = fs::read_to_string(run.join("audit.jsonl")).unwrap();
    assert!(audit.contains("tool-changed") && audit.contains("tool-new"), "{audit}");
    let events = fs::read_to_string(run.join("events.jsonl")).unwrap_or_default();
    assert!(events.is_empty(), "a drifted tool reached the server: {events}");

    let c = proxy(&dir.join("repinned"), &pin, &["--repin"]).await;
    assert_eq!(names(&c).await, ["email_send", "fs_read", "http_fetch", "shell_run"]);
    let r = c.call_tool(call("fs_read", json!({"path": "notes/meeting.md"}))).await.unwrap();
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    c.cancel().await.unwrap();
}
