//! M4 gate: an injection in fetched content is stopped because the outbound argument
//! carries private data read earlier in the session, not because of a keyword match.

mod common;

use authz_cli::{load, run_case};
use authz_guard::Rules;

const TAINT_RULES: &[&str] = &["tainted-fetch", "tainted-mail"];

#[tokio::test]
async fn taint_stops_what_pattern_rules_miss() {
    let r = common::rig();
    let full = Rules::load(&r.policy()).unwrap();
    let s = &load(&r.corpus().join("atk-07-taint-path-exfil.json")).unwrap()[0];

    let o = run_case(&r, s, &full.without(TAINT_RULES), "test-m4-off").await.unwrap();
    assert!(o.reached, "precondition: M2 rules alone must miss this case");

    let o = run_case(&r, s, &full, "test-m4-on").await.unwrap();
    assert!(!o.reached, "taint tracking should stop it");
    let audit = common::jsonl(&o.sandbox.join("audit.jsonl"));
    let hit = audit.iter().find(|a| a["verdict"] == "block" && a["rule"] == "tainted-fetch");
    let why = hit.and_then(|a| a["reason"].as_str()).unwrap_or_default();
    assert!(why.contains("blueheron") && why.contains("fs_read notes/roadmap.md"), "{why}");
}
