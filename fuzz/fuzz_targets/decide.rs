//! The full decision path on the shipped policies with arbitrary tool calls: no panic,
//! and the same call in the same context always gets the same verdict.
#![no_main]

use std::sync::LazyLock;

use authz_core::{Context, Policy, ToolCall};
use authz_guard::Rules;
use libfuzzer_sys::fuzz_target;

static POLICIES: LazyLock<Vec<Rules>> = LazyLock::new(|| {
    [
        include_str!("../../policies.yaml"),
        include_str!("../../policies/filesystem.yaml"),
        include_str!("../../policies/example-proxy.yaml"),
    ]
    .iter()
    .map(|s| Rules::parse(s).expect("shipped policy loads"))
    .collect()
});

const TOOLS: &[&str] = &[
    "fs_read", "http_fetch", "email_send", "shell_run", "read_text_file",
    "read_multiple_files", "write_file", "edit_file", "move_file", "unknown_tool",
];

fuzz_target!(|data: &[u8]| {
    let Some((&pick, rest)) = data.split_first() else { return };
    let Ok(serde_json::Value::Object(args)) = serde_json::from_slice(rest) else { return };
    let call = ToolCall::new(TOOLS[pick as usize % TOOLS.len()], args);
    let ctx = Context::new("Read notes.md and email team@corp.test", vec!["fs_read".into()]);
    for p in POLICIES.iter() {
        assert_eq!(p.decide(&call, &ctx), p.decide(&call, &ctx), "verdict not deterministic");
    }
});
