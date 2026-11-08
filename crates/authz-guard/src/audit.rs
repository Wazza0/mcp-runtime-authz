//! Append-only JSONL decision log. Written before any action runs.

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
    f: Mutex<File>,
    seq: Mutex<u64>,
}

impl Audit {
    pub fn open(p: &Path) -> io::Result<Self> {
        let f = OpenOptions::new().create(true).append(true).open(p)?;
        Ok(Self { f: Mutex::new(f), seq: Mutex::new(0) })
    }

    /// Persist a decision. Callers must not act if this fails.
    pub fn record(&self, call: &ToolCall, d: &Decision, note: &str) -> io::Result<()> {
        let mut seq = self.seq.lock().map_err(|_| io::Error::other("audit poisoned"))?;
        *seq += 1;
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
        let verdict = match d {
            Decision::Allow => "allow",
            Decision::Block { .. } => "block",
            Decision::Escalate { .. } => "escalate",
        };
        let line = json!({
            "seq": *seq, "ts": ts, "tool": call.tool, "args": call.args,
            "verdict": verdict, "rule": d.rule(), "reason": d.reason(), "note": note,
        });
        let mut f = self.f.lock().map_err(|_| io::Error::other("audit poisoned"))?;
        writeln!(f, "{line}")?;
        f.sync_data()
    }
}
