//! Wiring: scenario -> model -> executor -> sandboxed tool server.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use authz_agent::{Kind, Scenario, Scripted, Transcript, run, scenario::read_events};
use authz_guard::Mcp;

pub const MAX_STEPS: usize = 16;

/// Where the repo lives and how to launch the tool server.
pub struct Rig {
    pub root: PathBuf,
    pub server: PathBuf,
    pub server_args: Vec<String>,
}

impl Rig {
    pub fn from_env() -> Result<Self> {
        let root = env::current_dir()?;
        let (server, server_args) = match env::var("AUTHZ_TOOL_SERVER") {
            Ok(p) => (p.into(), vec![]),
            Err(_) => (env::current_exe()?, vec!["serve-tools".into()]),
        };
        Ok(Self { root, server, server_args })
    }

    pub fn corpus(&self) -> PathBuf {
        self.root.join("eval").join("corpus")
    }
}

pub struct Outcome {
    pub reached: bool,
    pub transcript: Transcript,
}

pub async fn run_case(rig: &Rig, s: &Scenario) -> Result<Outcome> {
    let sandbox = rig.root.join("sandbox").join(&s.id);
    let _ = fs::remove_dir_all(&sandbox);
    fs::create_dir_all(&sandbox)?;
    let fixtures = rig.root.join("fixtures");
    if !fixtures.is_dir() {
        anyhow::bail!("fixtures/ missing under {}", rig.root.display());
    }

    let mcp = Mcp::spawn(&rig.server, &rig.server_args, &sandbox, &fixtures).await?;
    let mut model = Scripted::new(s.plan.clone());
    let transcript = run(&mut model, &mcp, &s.task, MAX_STEPS).await?;
    mcp.close().await?;

    let events = read_events(&sandbox.join("events.jsonl"));
    Ok(Outcome { reached: s.reached(&events), transcript })
}

pub fn label(k: Kind, reached: bool) -> &'static str {
    match (k, reached) {
        (Kind::Benign, true) => "completed",
        (Kind::Benign, false) => "FAILED",
        (Kind::Attack, true) => "ATTACK SUCCEEDED",
        (Kind::Attack, false) => "attack failed",
    }
}

pub fn load(p: &Path) -> Result<Vec<Scenario>> {
    if p.is_dir() {
        Scenario::load_dir(p)
    } else {
        Ok(vec![Scenario::load(p).context("loading case")?])
    }
}
