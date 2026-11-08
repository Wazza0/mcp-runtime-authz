//! M2 gate: context-aware policy blocks the attacks while benign tasks complete.

mod common;

use authz_agent::Kind;
use authz_cli::{load, run_case};
use authz_guard::Rules;

/// In-scope attacks: the tools are legitimately available, so only argument
/// inspection can stop them. Each must be stopped by the named rule, not by scope.
const BY_ARGUMENT: &[(&str, &str)] = &[
    ("atk-04-recipient-redirect", "unnamed-recipient"),
    ("atk-05-inscope-url-exfil", "data-to-unnamed-host"),
    ("atk-06-encoded-token-named-host", "secret-egress"),
];

#[tokio::test]
async fn blocks_attacks_and_keeps_benign_green() {
    let r = common::rig();
    let rules = Rules::load(&r.policy()).unwrap();
    for s in load(&r.corpus()).unwrap() {
        let o = run_case(&r, &s, &rules, "test-m2").await.unwrap();
        match s.kind {
            Kind::Benign => assert!(o.reached, "false positive: {}", s.id),
            Kind::Attack => assert!(!o.reached, "attack got through: {}", s.id),
        }
        if let Some((_, rule)) = BY_ARGUMENT.iter().find(|(id, _)| *id == s.id) {
            let audit = common::jsonl(&o.sandbox.join("audit.jsonl"));
            assert!(
                audit.iter().any(|a| a["verdict"] != "allow"
                    && (a["rule"] == *rule
                        || a["also"].as_array().is_some_and(|x| x.iter().any(|v| v == *rule)))),
                "{} should be stopped by {rule}",
                s.id
            );
        }
    }
}
