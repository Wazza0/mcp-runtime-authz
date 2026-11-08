//! M3 gate: a borderline call pauses for a human; approve runs it, deny stops it,
//! both are logged. A human can never approve past a deny.

mod common;

use std::sync::Arc;

use authz_cli::{load, run_case};
use authz_core::{Decision, ToolCall};
use authz_guard::{AllowAll, Approval, Approver, Rules};
use serde_json::Value;

struct Says(bool);

impl Approver for Says {
    fn review(&self, _: &ToolCall, _: &Decision) -> Approval {
        Approval { granted: self.0, by: "test".into() }
    }
}

fn verdicts(audit: &[Value], tool: &str) -> Vec<String> {
    audit
        .iter()
        .filter(|a| a["tool"] == tool)
        .map(|a| a["verdict"].as_str().unwrap_or_default().to_string())
        .collect()
}

#[tokio::test]
async fn borderline_call_waits_for_a_human() {
    let mut r = common::rig();
    let rules = Rules::load(&r.policy()).unwrap();
    let case = &load(&r.root.join("eval/escalation/borderline-recipient-from-file.json")).unwrap()[0];

    r.approver = Arc::new(Says(true));
    let o = run_case(&r, case, &rules, "test-m3-yes").await.unwrap();
    assert!(o.reached, "approved call should run");
    let audit = common::jsonl(&o.sandbox.join("audit.jsonl"));
    assert_eq!(verdicts(&audit, "email_send"), ["escalate", "approved"]);
    assert!(audit.iter().any(|a| a["rule"] == "unnamed-recipient"));

    r.approver = Arc::new(Says(false));
    let o = run_case(&r, case, &rules, "test-m3-no").await.unwrap();
    assert!(!o.reached, "denied call must not run");
    let audit = common::jsonl(&o.sandbox.join("audit.jsonl"));
    assert_eq!(verdicts(&audit, "email_send"), ["escalate", "denied"]);
    let events = common::jsonl(&o.sandbox.join("events.jsonl"));
    assert!(events.iter().all(|e| e["tool"] != "email_send"));
}

#[tokio::test]
async fn approving_everything_cannot_override_a_deny() {
    let mut r = common::rig();
    r.approver = Arc::new(AllowAll);
    let rules = Rules::load(&r.policy()).unwrap();
    for id in ["atk-01-web-exfil", "atk-03-ci-shell", "atk-06-encoded-token-named-host"] {
        let s = &load(&r.corpus().join(format!("{id}.json"))).unwrap()[0];
        let o = run_case(&r, s, &rules, "test-m3-allowall").await.unwrap();
        assert!(!o.reached, "{id}: a deny was approved past");
        let audit = common::jsonl(&o.sandbox.join("audit.jsonl"));
        assert!(audit.iter().any(|a| a["verdict"] == "block"), "{id}: expected a hard block");
    }
}
