//! The proxy in front of the official git server (`mcp-server-git`), driven by the
//! official SDK client against a throwaway repository.
//!
//! Opt-in: needs uv and network. Run with
//! `cargo test -p authz-cli --test proxy_git -- --ignored`.

use std::{
    fs,
    path::{Path, PathBuf},
    process,
};

use authz_guard::Rules;
use rmcp::{
    RoleClient, ServiceExt,
    model::{CallToolRequestParams, CallToolResult},
    service::Peer,
    transport::TokioChildProcess,
};
use serde_json::{Value, json};
use tokio::process::Command;

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap()
}

fn policy() -> PathBuf {
    root().join("policies").join("git.yaml")
}

fn text(r: &CallToolResult) -> String {
    r.content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("\n")
}

fn call(name: &str, args: &Value) -> CallToolRequestParams {
    CallToolRequestParams::new(name.to_string()).with_arguments(args.as_object().unwrap().clone())
}

fn git(repo: &Path, args: &[&str]) -> String {
    let o = process::Command::new("git").arg("-C").arg(repo).args(args).output().unwrap();
    assert!(o.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).into_owned()
}

async fn ok(c: &Peer<RoleClient>, calls: &[(&str, Value)]) {
    for (tool, args) in calls {
        let r = c.call_tool(call(tool, args)).await.unwrap();
        assert_ne!(r.is_error, Some(true), "{tool} {args}: {}", text(&r));
    }
}

#[test]
fn git_policy_loads() {
    Rules::load(&policy()).unwrap();
}

#[tokio::test]
#[ignore = "needs uv + network"]
async fn guards_the_official_git_server() {
    let work = root().join("sandbox").join("test-proxy-git");
    let _ = fs::remove_dir_all(&work);
    let repo = work.join("repo");
    fs::create_dir_all(repo.join("certs")).unwrap();
    let audit = work.join("audit.jsonl");
    git(&repo, &["init", "-q", "-b", "main"]);
    git(&repo, &["config", "user.name", "t"]);
    git(&repo, &["config", "user.email", "t@example.com"]);
    fs::write(repo.join("README.md"), "# demo\n").unwrap();
    // A credential committed by mistake long ago.
    fs::write(repo.join(".env"), "API_TOKEN=sk-live-FAKE0000demo0000key\n").unwrap();
    git(&repo, &["add", "-f", "README.md", ".env"]);
    git(&repo, &["-c", "commit.gpgsign=false", "commit", "-qm", "init"]);
    fs::write(repo.join("notes.md"), "Ship the parser fix by Friday.\n").unwrap();
    fs::write(repo.join(".env.local"), "API_TOKEN=sk-live-FAKE0000demo0000key\n").unwrap();
    fs::write(repo.join("certs").join("server.key"), "-----BEGIN PRIVATE KEY-----\n").unwrap();

    let rules = Rules::load(&policy()).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_authz"));
    cmd.args(["proxy", "--policy"])
        .arg(policy())
        .arg("--audit")
        .arg(&audit)
        .args(["--", "uvx", "mcp-server-git", "--repository"])
        .arg(&repo);
    let client = ().serve(TokioChildProcess::new(cmd).unwrap()).await.unwrap();
    let mut tools: Vec<String> =
        client.list_all_tools().await.unwrap().into_iter().map(|t| t.name.to_string()).collect();
    tools.sort();
    assert_eq!(tools, rules.tool_names(), "the policy lists every real tool");

    let r = repo.to_string_lossy().to_string();
    ok(
        &client,
        &[
            ("git_status", json!({"repo_path": r})),
            ("git_log", json!({"repo_path": r})),
            ("git_diff_unstaged", json!({"repo_path": r})),
            ("git_diff_staged", json!({"repo_path": r})),
            ("git_diff", json!({"repo_path": r, "target": "HEAD"})),
            ("git_show", json!({"repo_path": r, "revision": "HEAD:README.md"})),
            ("git_branch", json!({"repo_path": r, "branch_type": "local"})),
            ("git_remote", json!({"repo_path": r})),
            ("git_add", json!({"repo_path": r, "files": ["notes.md"]})),
            ("git_commit", json!({"repo_path": r, "message": "Add notes"})),
            ("git_create_branch", json!({"repo_path": r, "branch_name": "feature"})),
            ("git_checkout", json!({"repo_path": r, "branch_name": "feature"})),
        ],
    )
    .await;
    fs::write(repo.join("notes.md"), "Ship the parser fix by Thursday.\n").unwrap();
    ok(&client, &[("git_add", json!({"repo_path": r, "files": ["notes.md"]}))]).await;

    // Unguarded, each of these stages a credential, prints one, or commits one.
    let refused = [
        ("git_add", json!({"repo_path": r, "files": [".env.local"]}), "sensitive-stage"),
        (
            "git_add",
            json!({"repo_path": r, "files": ["notes.md", "certs/server.key"]}),
            "sensitive-stage",
        ),
        ("git_add", json!({"repo_path": r, "files": ["."]}), "sweeping-stage"),
        ("git_add", json!({"repo_path": r, "files": ["[.]env.local"]}), "sweeping-stage"),
        ("git_add", json!({"repo_path": r, "files": [":(literal).env.local"]}), "sweeping-stage"),
        ("git_show", json!({"repo_path": r, "revision": "HEAD:.env"}), "sensitive-read"),
        (
            "git_commit",
            json!({"repo_path": r, "message": "Rotate sk-live-FAKE0000demo0000key"}),
            "secret-write",
        ),
    ];
    for (tool, args, _) in &refused {
        let res = client.call_tool(call(tool, args)).await.unwrap();
        let t = text(&res);
        assert_eq!(res.is_error, Some(true), "{tool} {args}: {t}");
        assert!(t.starts_with("BLOCKED"), "{tool} {args}: {t}");
        assert!(rules.rule_ids().iter().all(|id| !t.contains(id)), "names a rule: {t}");
        assert!(!t.contains("sk-live"), "{t}");
    }
    assert_eq!(
        git(&repo, &["diff", "--cached", "--name-only"]).trim(),
        "notes.md",
        "a refused stage landed"
    );
    assert_eq!(
        git(&repo, &["log", "--all", "--format=%s"]),
        "Add notes\ninit\n",
        "a refused commit landed"
    );

    ok(&client, &[("git_reset", json!({"repo_path": r}))]).await;
    client.cancel().await.unwrap();

    assert_eq!(git(&repo, &["diff", "--cached", "--name-only"]), "", "git_reset unstages");
    assert_eq!(git(&repo, &["diff", "--name-only"]).trim(), "notes.md", "and keeps the edit");
    assert_eq!(git(&repo, &["ls-files"]), ".env\nREADME.md\nnotes.md\n");
    assert_eq!(git(&repo, &["branch", "--show-current"]).trim(), "feature");
    let log: Vec<Value> = fs::read_to_string(&audit)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    for (tool, args, rule) in &refused {
        assert!(
            log.iter().any(|a| a["tool"] == *tool && a["args"] == *args && a["rule"] == *rule),
            "{tool} {args} not refused by {rule}"
        );
    }
}
