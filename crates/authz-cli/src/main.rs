use std::{
    env, fs,
    io::{IsTerminal, stdin},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use authz_agent::Kind;
use authz_cli::{Brain, Rig, eval::evaluate, label, load, run_case};
use authz_core::Context as Ctx;
use authz_guard::{AllowAll, Approver, Audit, Console, DenyAll, Mcp, Proxy, Rules};

const USAGE: &str = "usage: authz proxy --policy <file> [--audit <file>] [--approve deny|allow] \
-- <mcp-server-command> [args...]
       authz run [case.json|dir] [-v] [--policy <file> | --unguarded] \
[--model scripted|ollama] [--approve deny|allow|ask]
       authz eval [--model scripted|ollama] [--approve deny|allow] [--policy <file>] [--ablation] [--out <file>]
       authz serve-tools";

fn flag<'a>(a: &'a [String], name: &str) -> Option<&'a str> {
    a.iter().position(|x| x == name).and_then(|i| a.get(i + 1)).map(String::as_str)
}

/// Sets the model on the rig and returns its display name.
fn pick_model(a: &[String], rig: &mut Rig) -> Result<String> {
    Ok(match flag(a, "--model") {
        None | Some("scripted") => {
            rig.brain = Brain::Scripted;
            "scripted".into()
        }
        Some("ollama") => {
            rig.brain = Brain::Ollama;
            env::var("AUTHZ_MODEL").unwrap_or_else(|_| "qwen3:8b".into())
        }
        Some(m) => bail!("unknown model backend {m}\n{USAGE}"),
    })
}

fn slug(s: &str) -> String {
    s.replace([':', '/'], "_")
}

#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<String> = env::args().skip(1).collect();
    let target = || a.get(1).filter(|x| !x.starts_with('-')).map(PathBuf::from);
    match a.first().map(String::as_str) {
        Some("serve-tools") => authz_tools::serve().await,
        Some("proxy") => {
            // Everything after `--` is the downstream server's own command line.
            let split = a.iter().position(|x| x == "--");
            let (opts, cmd) = match split {
                Some(i) if a.len() > i + 1 => (&a[..i], &a[i + 1..]),
                _ => bail!("proxy needs a downstream server after `--`\n{USAGE}"),
            };
            let p = flag(opts, "--policy").map(PathBuf::from).context("proxy needs --policy")?;
            let rules = Rules::load(&p).context("loading policy")?;
            // stdin is the MCP channel here, so a console prompt cannot run.
            let approver: Arc<dyn Approver> = match flag(opts, "--approve").unwrap_or("deny") {
                "deny" => Arc::new(DenyAll),
                "allow" => Arc::new(AllowAll),
                m => bail!("proxy supports --approve deny|allow, not {m} (stdin is the protocol)"),
            };
            let audit = flag(opts, "--audit")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("authz-audit.jsonl"));
            let down = Mcp::connect(&cmd[0], &cmd[1..], &[]).await?;
            // No task text in proxy mode: the policy's `allow` list is the trust anchor.
            let ctx = Ctx::new("", rules.tool_names());
            // stderr only; stdout belongs to the protocol.
            eprintln!("authz proxy: {} -> {}", p.display(), cmd.join(" "));
            Proxy::new(down, Box::new(rules), approver, Audit::open(&audit)?, ctx)
                .await?
                .run()
                .await
        }
        Some("eval") => {
            let mut rig = Rig::from_env()?;
            let model = pick_model(&a, &mut rig)?;
            // Evals never prompt. `allow` bounds what deny rules stop on their own.
            let approve = flag(&a, "--approve").unwrap_or("deny");
            rig.approver = match approve {
                "deny" => Arc::new(DenyAll),
                "allow" => Arc::new(AllowAll),
                m => bail!("eval supports --approve deny|allow, not {m}"),
            };
            let tag = if approve == "allow" {
                format!("{}-allowall", slug(&model))
            } else {
                slug(&model)
            };
            let p = flag(&a, "--policy").map(PathBuf::from).unwrap_or_else(|| rig.policy());
            let rules = Rules::load(&p).context("loading policy")?;
            let cases = load(&target().unwrap_or_else(|| rig.corpus()))?;
            let ev =
                evaluate(&rig, &cases, &rules, &tag, a.iter().any(|x| x == "--ablation")).await?;
            println!("{}", ev.markdown(&format!("{model}, approver: {approve}")));
            let out = flag(&a, "--out").map(PathBuf::from).unwrap_or_else(|| {
                rig.root.join("eval").join("out").join(format!("results-{tag}.json"))
            });
            if let Some(d) = out.parent() {
                fs::create_dir_all(d)?;
            }
            fs::write(&out, serde_json::to_string_pretty(&ev.json(&model))?)?;
            eprintln!("wrote {}", out.display());
            Ok(())
        }
        Some("run") => {
            let mut rig = Rig::from_env()?;
            let model = pick_model(&a, &mut rig)?;
            // A person at the terminal is asked; otherwise escalations fail closed.
            let approve =
                flag(&a, "--approve").unwrap_or(if stdin().is_terminal() { "ask" } else { "deny" });
            rig.approver = match approve {
                "deny" => Arc::new(DenyAll),
                "allow" => Arc::new(AllowAll),
                "ask" => Arc::new(Console),
                m => bail!("unknown approval mode {m}\n{USAGE}"),
            };
            let verbose = a.iter().any(|x| x == "-v");
            let (rules, mode) = if a.iter().any(|x| x == "--unguarded") {
                (Rules::permit_all(), "unguarded")
            } else {
                let p = flag(&a, "--policy").map(PathBuf::from).unwrap_or_else(|| rig.policy());
                (Rules::load(&p).context("loading policy")?, "guarded")
            };
            let tag = format!("{mode}-{}", slug(&model));
            println!("mode: {mode}, model: {model}, approval: {approve}");
            println!("{:<32} {:<7} {:<20} result", "case", "kind", "class");
            for s in load(&target().unwrap_or_else(|| rig.corpus()))? {
                let o = run_case(&rig, &s, &rules, &tag).await?;
                let k = if s.kind == Kind::Benign { "benign" } else { "attack" };
                println!("{:<32} {:<7} {:<20} {}", s.id, k, s.class, label(s.kind, o.reached));
                if verbose {
                    for (i, (c, r)) in o.transcript.steps.iter().enumerate() {
                        let out: String = r.text.chars().take(90).collect();
                        let args = serde_json::Value::Object(c.args.clone());
                        println!(
                            "    {}. {} {} -> {}",
                            i + 1,
                            c.tool,
                            args,
                            out.replace('\n', " ")
                        );
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
