use std::{env, path::PathBuf};

use anyhow::{Context, Result, bail};
use authz_agent::Kind;
use authz_cli::{Rig, label, load, run_case};
use authz_guard::Rules;

const USAGE: &str =
    "usage: authz run [case.json|dir] [-v] [--policy <file> | --unguarded]\n       authz serve-tools";

fn flag<'a>(a: &'a [String], name: &str) -> Option<&'a str> {
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1)).map(String::as_str)
}

#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<String> = env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("serve-tools") => authz_tools::serve().await,
        Some("run") => {
            let rig = Rig::from_env()?;
            let target = a
                .get(1)
                .filter(|x| !x.starts_with('-'))
                .map(PathBuf::from)
                .unwrap_or_else(|| rig.corpus());
            let verbose = a.iter().any(|x| x == "-v");
            let (rules, tag) = if a.iter().any(|x| x == "--unguarded") {
                (Rules::permit_all(), "unguarded")
            } else {
                let p = flag(&a, "--policy").map(PathBuf::from).unwrap_or_else(|| rig.policy());
                (Rules::load(&p).context("loading policy")?, "guarded")
            };
            println!("mode: {tag}\n{:<30} {:<7} {:<20} result", "case", "kind", "class");
            for s in load(&target)? {
                let o = run_case(&rig, &s, &rules, tag).await?;
                let k = if s.kind == Kind::Benign { "benign" } else { "attack" };
                println!("{:<30} {:<7} {:<20} {}", s.id, k, s.class, label(s.kind, o.reached));
                if verbose {
                    for (i, (c, r)) in o.transcript.steps.iter().enumerate() {
                        let out: String = r.text.chars().take(90).collect();
                        let args = serde_json::Value::Object(c.args.clone());
                        println!("    {}. {} {} -> {}", i + 1, c.tool, args, out.replace('\n', " "));
                    }
                }
            }
            Ok(())
        }
        _ => bail!(USAGE),
    }
}
