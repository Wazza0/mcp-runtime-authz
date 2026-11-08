//! If a decision cannot be written to the audit log, the call does not run: on the allow
//! path, the escalation path, and the block path. /dev/full fails every write; it exists
//! on Linux only (not macOS).
#![cfg(target_os = "linux")]

use std::{path::Path, sync::Arc};

use authz_core::{Context, ToolCall};
use authz_guard::{AllowAll, Audit, Gate, Rules};

fn gate(policy: Rules) -> Gate {
    let audit = Audit::open(Path::new("/dev/full")).unwrap();
    Gate::new(Box::new(policy), Arc::new(AllowAll), audit, Context::new("", vec!["t".into()]))
}

fn refused(g: &Gate, what: &str) -> String {
    let Err(d) = g.check(&ToolCall::new("t", Default::default())) else {
        panic!("{what}: ran without a record");
    };
    d.message
}

fn policy(action: &str) -> Rules {
    Rules::parse(&format!("default: deny\ntools:\n  t: {{action: {action}, class: read}}\n"))
        .unwrap()
}

#[test]
fn an_unrecorded_decision_never_runs() {
    for (what, p) in [("allow", Rules::permit_all()), ("escalate", policy("escalate"))] {
        let m = refused(&gate(p), what);
        assert!(m.contains("could not be recorded"), "{what}: {m}");
    }
    let m = refused(&gate(policy("deny")), "deny");
    assert!(m.starts_with("BLOCKED") && !m.contains("audit #"), "{m}");
}
