//! `authz audit`: the audit log as a table a human can read at a glance.

use serde_json::Value;

/// The argument a reader cares about most for a call: what it touches or where it goes.
fn target(args: &Value) -> String {
    for k in ["path", "paths", "url", "to", "cmd", "destination", "source"] {
        match &args[k] {
            Value::String(s) => return s.clone(),
            Value::Array(v) => {
                return v.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ");
            }
            _ => {}
        }
    }
    args.as_object().and_then(|o| o.values().find_map(Value::as_str)).unwrap_or_default().into()
}

fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.into()
    } else {
        s.chars().take(n - 1).collect::<String>() + "…"
    }
}

/// One line per decision, then a summary. Escalations show both steps: the policy's
/// `escalate` and the human's `approved` / `denied`.
pub fn audit_table(log: &str) -> String {
    let rows: Vec<Value> = log.lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
    let (mut ran, mut refused) = (0, 0);
    let mut out = String::new();
    for r in &rows {
        let v = r["verdict"].as_str().unwrap_or("?");
        let mark = match v {
            "allow" | "approved" => {
                ran += 1;
                "✓"
            }
            "block" | "denied" => {
                refused += 1;
                "✕"
            }
            _ => "…",
        };
        let rule = if v == "allow" { "" } else { r["rule"].as_str().unwrap_or("") };
        out += &format!(
            "{mark} {v:<9} {:<21} {:<30} {rule}\n",
            r["tool"].as_str().unwrap_or("?"),
            clip(&target(&r["args"]), 30),
        );
    }
    out + &format!("\n{} calls: {ran} ran, {refused} refused\n", ran + refused)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shows_each_decision_and_counts_outcomes() {
        let log = [
            r#"{"tool":"read_text_file","args":{"path":"notes.md"},"verdict":"allow","rule":"-"}"#,
            r#"{"tool":"read_multiple_files","args":{"paths":["a.md",".env"]},"verdict":"block","rule":"sensitive-read"}"#,
            r#"{"tool":"email_send","args":{"to":"x@y.test"},"verdict":"escalate","rule":"unnamed-recipient"}"#,
            r#"{"tool":"email_send","args":{"to":"x@y.test"},"verdict":"denied","rule":"unnamed-recipient"}"#,
        ]
        .join("\n");
        let t = audit_table(&log);
        assert!(t.contains("✓ allow") && t.contains("notes.md"));
        assert!(t.contains("✕ block") && t.contains("a.md, .env") && t.contains("sensitive-read"));
        assert!(t.contains("… escalate") && t.contains("✕ denied"));
        assert!(t.ends_with("3 calls: 1 ran, 2 refused\n"), "{t}");
    }
}
