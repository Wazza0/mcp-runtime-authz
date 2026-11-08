//! M1 gate: no tool executes without a logged decision; denying a tool blocks it.

mod common;


use authz_cli::{load, run_case};
use authz_guard::Rules;

#[tokio::test]
async fn every_execution_has_a_prior_logged_allow() {
    let r = common::rig();
    let rules = Rules::load(&r.policy()).unwrap();
    for s in load(&r.corpus()).unwrap() {
        let o = run_case(&r, &s, &rules, "test-m1-cover").await.unwrap();
        let events = common::jsonl(&o.sandbox.join("events.jsonl"));
        let allows: Vec<_> = common::jsonl(&o.sandbox.join("audit.jsonl"))
            .into_iter()
            .filter(|a| a["verdict"] == "allow" || a["verdict"] == "approved")
            .collect();
        assert_eq!(events.len(), allows.len(), "{}: executions != logged allows + approvals", s.id);
        for (e, a) in events.iter().zip(&allows) {
            assert_eq!(e["tool"], a["tool"], "{}", s.id);
            assert_eq!(e["args"], a["args"], "{}", s.id);
            assert!(a["ts"].as_u64() <= e["ts"].as_u64(), "{}: logged after executing", s.id);
            assert!(!a["reason"].as_str().unwrap_or("").is_empty(), "{}: no reason", s.id);
        }
    }
}

#[tokio::test]
async fn flipping_a_tool_to_deny_blocks_it() {
    let r = common::rig();
    let case = &load(&r.corpus().join("benign-01-meeting-email.json")).unwrap()[0];
    let allow = Rules::parse("default: deny\ntools: {fs_read: {action: allow, class: read}, email_send: {action: allow, class: egress}}").unwrap();
    let deny = Rules::parse("default: deny\ntools: {fs_read: {action: deny, class: read}, email_send: {action: allow, class: egress}}").unwrap();

    assert!(run_case(&r, case, &allow, "test-m1-allow").await.unwrap().reached);

    let o = run_case(&r, case, &deny, "test-m1-deny").await.unwrap();
    assert!(!o.reached, "task must not complete with fs_read denied");
    let events = common::jsonl(&o.sandbox.join("events.jsonl"));
    assert!(events.iter().all(|e| e["tool"] != "fs_read"), "denied tool executed");
    let audit = common::jsonl(&o.sandbox.join("audit.jsonl"));
    assert!(audit.iter().any(|a| a["tool"] == "fs_read"
        && a["verdict"] == "block"
        && a["rule"] == "tools.fs_read"));
}
