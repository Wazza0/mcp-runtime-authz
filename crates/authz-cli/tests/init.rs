//! `authz init` drafts a policy from a real server's tool list that loads and protects.

use std::process::Command;

use authz_core::{Context, Policy, ToolCall};
use authz_guard::Rules;
use serde_json::{Value, json};

fn call(tool: &str, args: Value) -> ToolCall {
    ToolCall::new(tool, args.as_object().cloned().unwrap_or_default())
}

#[test]
fn drafts_a_loadable_protective_policy_for_a_real_server() {
    let bin = env!("CARGO_BIN_EXE_authz");
    let out = Command::new(bin).args(["init", "--", bin, "serve-tools"]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let y = String::from_utf8(out.stdout).unwrap();
    let r = Rules::parse(&y).unwrap_or_else(|e| panic!("draft must load: {e}\n{y}"));

    for (tool, class) in [
        ("fs_read", "read"),
        ("http_fetch", "egress"),
        ("email_send", "egress"),
        ("shell_run", "exec"),
    ] {
        assert!(
            y.contains(&format!("{tool}: {{action: allow, class: {class}")),
            "{tool} -> {class}"
        );
    }

    // With an empty allow list, the draft refuses every destination and command.
    let none = Context::new("", r.tool_names());
    let refused = [
        call("http_fetch", json!({"url": "http://anywhere.test/"})),
        call("email_send", json!({"to": "someone@corp.test", "subject": "s", "body": "b"})),
        call("shell_run", json!({"cmd": "ls"})),
        call("fs_read", json!({"path": "app/.env"})),
    ];
    for c in &refused {
        assert!(!r.decide(c, &none).allowed(), "{} should be refused by default", c.tool);
    }
    assert!(r.decide(&call("fs_read", json!({"path": "notes/meeting.md"})), &none).allowed());
}
