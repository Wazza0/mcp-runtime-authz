use std::{env, path::PathBuf};

use anyhow::{Result, bail};
use authz_agent::Kind;
use authz_cli::{Rig, label, load, run_case};

const USAGE: &str = "usage: authz <run <case.json|dir> [-v] | serve-tools>";

#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<String> = env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("serve-tools") => authz_tools::serve().await,
        Some("run") => {
            let rig = Rig::from_env()?;
            let target = a.get(1).map(PathBuf::from).unwrap_or_else(|| rig.corpus());
            let verbose = a.iter().any(|x| x == "-v");
            println!("{:<30} {:<7} {:<20} result", "case", "kind", "class");
            for s in load(&target)? {
                let o = run_case(&rig, &s).await?;
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
