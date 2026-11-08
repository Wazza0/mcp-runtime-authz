//! Invariants checked on random inputs, on every `cargo test` (fuzzing covers the rest in CI).

use std::path::Path;

use authz_core::{Context, Policy, ToolCall};
use authz_guard::{Rules, inspect::variants};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use proptest::prelude::*;
use serde_json::{Value, json};

fn shipped() -> Rules {
    Rules::load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policies.yaml")).unwrap()
}

fn pct(s: &str) -> String {
    s.bytes().map(|b| format!("%{b:02X}")).collect()
}

fn call(tool: &str, args: Value) -> ToolCall {
    ToolCall::new(tool, args.as_object().cloned().unwrap_or_default())
}

proptest! {
    #[test]
    fn decoding_never_loses_the_original(s in r"\PC{0,200}") {
        let v = variants(&s);
        prop_assert_eq!(&v[0], &s);
    }

    /// Every encoding the guard claims to see through, on a host and recipient the task
    /// itself names, so only content inspection can catch it.
    #[test]
    fn encoded_secrets_never_leave(body in "[A-Za-z0-9]{12,32}", enc in 0usize..4) {
        let secret = format!("sk-live-{body}");
        let carried = match enc {
            0 => secret.clone(),
            1 => pct(&secret),
            2 => STANDARD.encode(&secret),
            _ => URL_SAFE_NO_PAD.encode(&secret),
        };
        let r = shipped();
        let ctx = Context::new(
            "Fetch http://docs.test/x and email team@corp.test",
            vec!["http_fetch".into(), "email_send".into()],
        );
        let fetch = call("http_fetch", json!({"url": format!("http://docs.test/x?d={carried}")}));
        let mail = call("email_send", json!({"to": "team@corp.test", "subject": "s", "body": carried}));
        let (f, m) = (r.decide(&fetch, &ctx), r.decide(&mail, &ctx));
        prop_assert_eq!(f.rule(), "secret-egress");
        prop_assert_eq!(m.rule(), "secret-egress");
    }

    #[test]
    fn any_call_gets_a_stable_verdict(
        tool in prop::sample::select(vec!["fs_read", "http_fetch", "email_send", "shell_run", "other"]),
        args in prop::collection::btree_map("[a-z]{1,6}", r"\PC{0,60}", 0..4),
    ) {
        let args = args.into_iter().map(|(k, v)| (k, Value::String(v))).collect();
        let c = ToolCall::new(tool, args);
        let ctx = Context::new("do the task", vec!["fs_read".into()]);
        let r = shipped();
        prop_assert_eq!(r.decide(&c, &ctx), r.decide(&c, &ctx));
    }
}
