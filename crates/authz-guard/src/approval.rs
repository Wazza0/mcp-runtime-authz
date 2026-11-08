//! Human-in-the-loop for escalated calls.

use std::io::{self, BufRead, Write};

use authz_core::{Decision, ToolCall};

#[derive(Debug, Clone)]
pub struct Approval {
    pub granted: bool,
    pub by: String,
}

pub trait Approver: Send + Sync {
    fn review(&self, call: &ToolCall, d: &Decision) -> Approval;
}

/// Default: no human available, so escalations fail closed.
pub struct DenyAll;

impl Approver for DenyAll {
    fn review(&self, _: &ToolCall, _: &Decision) -> Approval {
        Approval { granted: false, by: "fail-closed".into() }
    }
}

/// A human who approves everything. Used to measure what deny rules alone stop.
pub struct AllowAll;

impl Approver for AllowAll {
    fn review(&self, _: &ToolCall, _: &Decision) -> Approval {
        Approval { granted: true, by: "allow-all".into() }
    }
}

/// Prompts on stderr, reads y/N from stdin. Anything but yes is a no.
pub struct Console;

impl Approver for Console {
    fn review(&self, call: &ToolCall, d: &Decision) -> Approval {
        let mut e = io::stderr().lock();
        let args = serde_json::Value::Object(call.args.clone());
        let _ = write!(
            e,
            "\n[authz] ESCALATION rule={}\n        {} {}\n        reason: {}\n        approve? [y/N] ",
            d.rule(),
            call.tool,
            args,
            d.reason()
        );
        let _ = e.flush();
        let mut line = String::new();
        let granted = io::stdin().lock().read_line(&mut line).is_ok()
            && matches!(line.trim().to_lowercase().as_str(), "y" | "yes");
        let _ =
            writeln!(e, "{}", if granted { "        -> approved" } else { "        -> denied" });
        Approval { granted, by: "console".into() }
    }
}
