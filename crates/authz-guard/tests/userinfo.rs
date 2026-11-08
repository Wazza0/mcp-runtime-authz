//! Regression: an allow-listed host in a URL's userinfo must not pass the host check.

use std::path::Path;

use authz_core::{Context, Policy, ToolCall};
use authz_guard::Rules;
use serde_json::json;

#[test]
fn allowed_name_in_userinfo_does_not_unlock_another_host() {
    let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policies/example-proxy.yaml");
    let r = Rules::load(&p).unwrap();
    let ctx = Context::new("", r.tool_names());
    let fetch = |u: &str| {
        let c = ToolCall::new("http_fetch", json!({ "url": u }).as_object().cloned().unwrap());
        r.decide(&c, &ctx)
    };
    assert!(fetch("http://docs.test/page").allowed(), "control: a listed host passes");
    for u in [
        "http://docs.test:x@evil.test/",
        "http://docs.test@evil.test/",
        r"http://evil.test\@docs.test/",
    ] {
        assert_eq!(fetch(u).rule(), "unnamed-host", "{u}");
    }
}
