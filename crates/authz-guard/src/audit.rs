//! Append-only JSONL decision log. Written before any action runs.
//! Verdicts: allow, block, escalate, then approved / denied for escalations.

use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use authz_core::{Decision, ToolCall};
use serde_json::json;

pub struct Audit {
    f: Mutex<(File, u64)>,
}

impl Audit {
    pub fn open(p: &Path) -> io::Result<Self> {
        let f = OpenOptions::new().create(true).append(true).open(p)?;
        Ok(Self { f: Mutex::new((f, 0)) })
    }

    /// Persist a policy decision. Callers must not act if this fails.
    pub fn record(&self, call: &ToolCall, d: &Decision, note: &str) -> io::Result<u64> {
        let v = match d {
            Decision::Allow => "allow",
            Decision::Block { .. } => "block",
            Decision::Escalate { .. } => "escalate",
        };
        self.write(call, v, d, note)
    }

    /// Persist a human's answer to an escalation.
    pub fn answer(
        &self,
        call: &ToolCall,
        d: &Decision,
        granted: bool,
        by: &str,
    ) -> io::Result<u64> {
        self.write(call, if granted { "approved" } else { "denied" }, d, &format!("by {by}"))
    }

    /// Returns the record's sequence number.
    fn write(&self, call: &ToolCall, verdict: &str, d: &Decision, note: &str) -> io::Result<u64> {
        let mut g = self.f.lock().map_err(|_| io::Error::other("audit poisoned"))?;
        g.1 += 1;
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        let line = json!({
            "seq": g.1, "ts": ts, "tool": call.tool, "args": call.args,
            "verdict": verdict, "rule": d.rule(), "also": d.also(), "reason": d.reason(), "note": note,
        });
        writeln!(g.0, "{line}")?;
        g.0.sync_data()?;
        Ok(g.1)
    }
}
