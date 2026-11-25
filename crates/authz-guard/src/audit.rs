//! Append-only JSONL decision log. Written before any action runs.
//! Verdicts: allow, block, escalate, then approved / denied for escalations.

use std::{
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
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
    /// Opens (or creates) the log for appending. Sequence numbers continue from the last
    /// record already in the file, so they stay unique across proxy restarts.
    pub fn open(p: &Path) -> io::Result<Self> {
        let f = OpenOptions::new().create(true).append(true).read(true).open(p)?;
        let last = last_seq(&f)?;
        Ok(Self { f: Mutex::new((f, last)) })
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

/// Highest `seq` in an existing log; 0 for an empty file or a non-regular file (a device such
/// as /dev/full reads forever). Lines that don't parse (for example a record cut short by a
/// crash) are skipped rather than failing the open.
fn last_seq(f: &File) -> io::Result<u64> {
    if !f.metadata()?.is_file() {
        return Ok(0);
    }
    let mut max = 0;
    for line in BufReader::new(f).lines() {
        let seq = serde_json::from_str::<serde_json::Value>(&line?)
            .ok()
            .and_then(|v| v.get("seq")?.as_u64());
        max = max.max(seq.unwrap_or(0));
    }
    Ok(max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_continues_across_reopen() {
        let p = std::env::temp_dir().join(format!("authz-audit-test-{}.jsonl", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let call = ToolCall::new("read", Default::default());
        let a = Audit::open(&p).unwrap();
        assert_eq!(a.record(&call, &Decision::Allow, "").unwrap(), 1);
        assert_eq!(a.record(&call, &Decision::Allow, "").unwrap(), 2);
        drop(a);
        // A torn final line must not stop the proxy from starting.
        OpenOptions::new().append(true).open(&p).unwrap().write_all(b"{\"seq\":").unwrap();
        let b = Audit::open(&p).unwrap();
        assert_eq!(b.record(&call, &Decision::Allow, "").unwrap(), 3);
        drop(b);
        std::fs::remove_file(&p).unwrap();
    }
}
