use std::{
    env,
    io::{IsTerminal, stdin},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use authz_agent::Kind;
use authz_cli::{Brain, Rig, label, load, run_case};
use authz_guard::{AllowAll, Console, DenyAll, Rules};

const USAGE: &str = "usage: authz run [case.json|dir] [-v] [--policy <file> | --unguarded] \
[--model scripted|ollama] [--approve deny|allow|ask]\n       authz serve-tools";

fn flag<'a>(a: &'a [String], name: &str) -> Option<&'a str> {
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1)).map(String::as_str)
}

#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<String> = env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("serve-tools") => authz_tools::serve().await,
        Some("run") => {
            let mut rig = Rig::from_env()?;
            let brain = match flag(&a, "--model") {
                None | Some("scripted") => {
                    rig.brain = Brain::Scripted;
                    "scripted".to_string()
                }
                Some("ollama") => {
                    rig.brain = Brain::Ollama;
                    env::var("AUTHZ_MODEL").unwrap_or_else(|_| "qwen3:8b".into())
                }
                Some(m) => bail!("unknown model backend {m}\n{USAGE}"),
            };
            // A person at the terminal is asked; otherwise escalations fail closed.
            let approve = flag(&a, "--approve")
                .unwrap_or(if stdin().is_terminal() { "ask" } else { "deny" });
            rig.approver = match approve {
                "deny" => Arc::new(DenyAll),
                "allow" => Arc::new(AllowAll),
                "ask" => Arc::new(Console),
                m => bail!("unknown approval mode {m}\n{USAGE}"),
            };
            let target = a
                .get(1)
                .filter(|x| !x.starts_with('-'))
                .map(PathBuf::from)
                .unwrap_or_else(|| rig.corpus());
            let verbose = a.iter().any(|x| x == "-v");
            let (rules, mode) = if a.iter().any(|x| x == "--unguarded") {
                (Rules::permit_all(), "unguarded")
            } else {
                let p = flag(&a, "--policy").map(PathBuf::from).unwrap_or_else(|| rig.policy());
                (Rules::load(&p).context("loading policy")?, "guarded")
            };
            let tag = format!("{mode}-{}", brain.replace([':', '/'], "_"));
            println!("mode: {mode}, model: {brain}, approval: {approve}");
            println!("{:<32} {:<7} {:<20} result", "case", "kind", "class");
            for s in load(&target)? {
                let o = run_case(&rig, &s, &rules, &tag).await?;
                let k = if s.kind == Kind::Benign { "benign" } else { "attack" };
                println!("{:<32} {:<7} {:<20} {}", s.id, k, s.class, label(s.kind, o.reached));
                if verbose {
                    for (i, (c, r)) in o.transcript.steps.iter().enumerate() {
                        let out: String = r.text.chars().take(90).collect();
                        let args = serde_json::Value::Object(c.args.clone());
                        println!("    {}. {} {} -> {}", i + 1, c.tool, args, out.replace('\n', " "));
                    }
                    if let Some(ans) = &o.transcript.answer {
                        let ans: String = ans.chars().take(160).collect();
                        println!("    => {}", ans.replace('\n', " "));
                    }
                }
            }
            Ok(())
        }
        _ => bail!(USAGE),
    }
}
