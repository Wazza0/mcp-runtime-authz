//! Wiring: scenario -> model -> executor -> sandboxed tool server.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use authz_agent::{Kind, Scenario, Scripted, Transcript, run, scenario::read_events};
use authz_core::Context as Ctx;
use authz_guard::{Audit, Interceptor, Mcp, Rules};

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

    pub fn policy(&self) -> PathBuf {
        self.root.join("policies.yaml")
    }
}

pub struct Outcome {
    pub reached: bool,
    pub transcript: Transcript,
    pub sandbox: PathBuf,
}

/// `tag` separates sandboxes per configuration so runs never share state.
pub async fn run_case(rig: &Rig, s: &Scenario, rules: &Rules, tag: &str) -> Result<Outcome> {
    let sandbox = rig.root.join("sandbox").join(tag).join(&s.id);
    let _ = fs::remove_dir_all(&sandbox);
    fs::create_dir_all(&sandbox)?;
    let fixtures = rig.root.join("fixtures");
    if !fixtures.is_dir() {
        anyhow::bail!("fixtures/ missing under {}", rig.root.display());
    }

    let mcp = Mcp::spawn(&rig.server, &rig.server_args, &sandbox, &fixtures).await?;
    let audit = Audit::open(&sandbox.join("audit.jsonl"))?;
    let ctx = Ctx::new(&s.task, s.scope.clone());
    let guard = Interceptor::new(mcp, Box::new(rules.clone()), audit, ctx).await?;
    let mut model = Scripted::new(s.plan.clone());
    let transcript = run(&mut model, &guard, &s.task, MAX_STEPS).await?;
    guard.close().await?;

    let events = read_events(&sandbox.join("events.jsonl"));
    Ok(Outcome { reached: s.reached(&events), transcript, sandbox })
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
