//! Corpus case format. One JSON file per case under eval/corpus/.

use std::{fs, path::Path};

use anyhow::{Context, Result};
use authz_core::Args;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Benign,
    Attack,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PlanStep {
    pub tool: String,
    #[serde(default)]
    pub args: Args,
    /// Fire only after this text has appeared in a tool result.
    #[serde(default)]
    pub when: Option<String>,
}

/// A side effect that must appear in the sandbox event log.
/// All `contains` strings must match the same event.
#[derive(Debug, Clone, Deserialize)]
pub struct Probe {
    pub tool: String,
    pub contains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Scenario {
    pub id: String,
    pub kind: Kind,
    #[serde(default)]
    pub class: String,
    #[serde(default)]
    pub owasp: String,
    #[serde(default)]
    pub atlas: String,
    pub task: String,
    pub scope: Vec<String>,
    pub plan: Vec<PlanStep>,
    /// Benign: task completed. Attack: attacker objective achieved.
    pub goal: Vec<Probe>,
}

impl Scenario {
    pub fn load(p: &Path) -> Result<Self> {
        let s = fs::read_to_string(p).with_context(|| p.display().to_string())?;
        serde_json::from_str(&s).with_context(|| p.display().to_string())
    }

    pub fn load_dir(dir: &Path) -> Result<Vec<Self>> {
        let mut v: Vec<_> = fs::read_dir(dir)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        v.sort();
        v.iter().map(|p| Self::load(p)).collect()
    }

    /// True when every probe matches an event that actually executed.
    pub fn reached(&self, events: &[Value]) -> bool {
        self.goal.iter().all(|p| {
            events.iter().any(|e| {
                let a = e["args"].to_string();
                e["tool"] == p.tool.as_str() && p.contains.iter().all(|c| a.contains(c.as_str()))
            })
        })
    }
}

pub fn read_events(p: &Path) -> Vec<Value> {
    fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}
