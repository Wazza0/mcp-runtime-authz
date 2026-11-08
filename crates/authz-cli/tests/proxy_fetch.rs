//! The proxy in front of the official fetch server (`mcp-server-fetch`), driven by the
//! official SDK client.
//!
//! Opt-in: needs uv and network. Run with
//! `cargo test -p authz-cli --test proxy_fetch -- --ignored`.

use std::{
    fs,
    io::Write,
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering::SeqCst},
    },
    thread,
};

use authz_guard::Rules;
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

fn policy() -> PathBuf {
    root().join("policies").join("fetch.yaml")
}

fn text(r: &CallToolResult) -> String {
    r.content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn fetch(url: &str) -> CallToolRequestParams {
    CallToolRequestParams::new("fetch")
        .with_arguments(json!({"url": url}).as_object().unwrap().clone())
}

async fn proxy(policy: &Path, audit: &Path) -> RunningService<RoleClient, ()> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_authz"));
    cmd.args(["proxy", "--policy"]).arg(policy).arg("--audit").arg(audit).args([
        "--",
        "uvx",
        "mcp-server-fetch",
        "--allow-private-ips",
    ]);
    ().serve(TokioChildProcess::new(cmd).unwrap()).await.unwrap()
}

#[test]
fn fetch_policy_loads() {
    assert_eq!(Rules::load(&policy()).unwrap().tool_names(), ["fetch"]);
}

#[tokio::test]
#[ignore = "needs uv + network"]
async fn guards_the_official_fetch_server() {
    let work = root().join("sandbox").join("test-proxy-fetch");
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).unwrap();
    let audit = work.join("audit.jsonl");

    // Counts every connection, so a refused call that went out anyway shows up.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicUsize::new(0));
    let h = hits.clone();
    thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            h.fetch_add(1, SeqCst);
            let _ =
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
        }
    });

    // The server runs with --allow-private-ips and the allow list names local addresses,
    // so only the policy's rules stand in the way. Rules only restrict: anything this
    // wider copy refuses, the shipped file refuses too.
    let shipped = fs::read_to_string(policy()).unwrap();
    let wide = shipped.replacen(
        "    - example.org\n",
        "    - example.org\n    - 127.0.0.1\n    - localhost\n    - 169.254.169.254\n",
        1,
    );
    assert_ne!(wide, shipped);
    let wide_path = work.join("fetch-wide.yaml");
    fs::write(&wide_path, wide).unwrap();
    let rules = Rules::load(&wide_path).unwrap();

    let client = proxy(&wide_path, &audit).await;
    let mut tools: Vec<String> =
        client.list_all_tools().await.unwrap().into_iter().map(|t| t.name.to_string()).collect();
    tools.sort();
    assert_eq!(tools, rules.tool_names(), "the policy lists every real tool");

    let r = client.call_tool(fetch("https://example.com/")).await.unwrap();
    assert_ne!(r.is_error, Some(true), "{}", text(&r));
    assert!(text(&r).contains("Example Domain"), "{}", text(&r));

    let local = format!("127.0.0.1:{port}");
    let refused = [
        (format!("http://{local}/"), "internal-host"),
        (format!("http://localhost:{port}/"), "internal-host"),
        (format!("http://[::1]:{port}/"), "internal-host"),
        (format!("http://2130706433:{port}/"), "internal-host"),
        (format!("http://example.com:x@{local}/"), "internal-host"),
        ("http://169.254.169.254/latest/meta-data/".into(), "internal-host"),
        ("http://10.0.0.1/".into(), "internal-host"),
        ("http://172.16.0.1/".into(), "internal-host"),
        ("http://192.168.0.1/".into(), "internal-host"),
        ("https://user:hunter2@example.com/".into(), "url-credentials"),
        ("https://example.com/?api_key=hunter2".into(), "url-credentials"),
        ("https://example.com/?q=sk-live-FAKE0000demo0000key".into(), "secret-egress"),
        (
            "https://example.com/c/T1BFTkFJX0FQSV9LRVk9c2stbGl2ZS1GQUtFMDAwMGRlbW8wMDAwa2V5".into(),
            "secret-egress",
        ),
        ("https://example.net/".into(), "unlisted-host"),
        ("file:///etc/passwd".into(), "unlisted-host"),
    ];
    for (url, _) in &refused {
        let r = client.call_tool(fetch(url)).await.unwrap();
        let t = text(&r);
        assert_eq!(r.is_error, Some(true), "{url}: {t}");
        assert!(t.starts_with("BLOCKED"), "{url}: {t}");
        assert!(rules.rule_ids().iter().all(|id| !t.contains(id)), "names a rule: {t}");
        assert!(!t.contains("hunter2") && !t.contains("sk-live"), "{t}");
    }
    client.cancel().await.unwrap();
    assert_eq!(hits.load(SeqCst), 0, "a refused call reached the local server");

    let log: Vec<Value> = fs::read_to_string(&audit)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    for (url, rule) in &refused {
        assert!(
            log.iter()
                .any(|a| a["args"]["url"] == *url && a["rule"] == *rule && a["verdict"] == "block"),
            "{url} not refused by {rule}"
        );
    }

    // Control: with no policy in the way, the same call does reach it.
    let open = work.join("open.yaml");
    fs::write(&open, "default: allow\n").unwrap();
    let client = proxy(&open, &work.join("open-audit.jsonl")).await;
    let r = client.call_tool(fetch(&format!("http://{local}/"))).await.unwrap();
    client.cancel().await.unwrap();
    assert!(hits.load(SeqCst) > 0, "control never arrived: {}", text(&r));
}
