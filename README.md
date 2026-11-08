# mcp-runtime-authz

A firewall for your AI agent's tools. It sits between an MCP client (Claude Code, Claude
Desktop, Cursor, …) and the MCP servers it uses, and checks every tool call against a
least-privilege policy *before* it runs: allow, block, or escalate. It stops secrets and
private data from leaving through tools (even encoded), blocks commands and destinations you
haven't allowed, and logs every decision with its reason. Built in Rust on the official MCP
SDK (`rmcp`).

```
MCP client ──▶ authz proxy (policy + audit log) ──▶ the MCP server you already use
```

## Use it as a proxy

```sh
cargo build --release
authz proxy --policy my-policy.yaml --audit audit.jsonl -- <mcp server command> [args...]
```

Point your client at the proxy instead of the server. In `.mcp.json` (Claude Code), Claude
Desktop's config, or Cursor's:

```json
{
  "mcpServers": {
    "guarded": {
      "command": "/path/to/authz",
      "args": ["proxy", "--policy", "/path/to/my-policy.yaml", "--audit", "/path/to/audit.jsonl",
               "--", "<mcp server command>", "<arg>"]
    }
  }
}
```

Start from [`policies/example-proxy.yaml`](policies/example-proxy.yaml). What to know:

- **The `allow` list is your trust anchor.** The proxy never sees what you typed, so hosts,
  email recipients and shell commands are permitted only if the policy lists them.
- **Tool names come from the server you wrap.** List each one under `tools:` with a risk class;
  anything unlisted falls to `default` (set it to `deny`).
- **Escalations fail closed.** stdin is the MCP channel, so the proxy cannot prompt you. An
  escalated call is refused and logged; `--approve allow` turns escalations into allows instead.
- **The agent learns nothing about the policy.** A refused call returns `BLOCKED` with an audit
  reference; the rule and reason are only in the audit log.
- **One decision path.** The proxy and the bundled test agent use the same `Gate`, so everything
  measured in [the evaluation](report/findings.md) applies to the proxy.

`tests/proxy.rs` drives the proxy with the official MCP SDK client and checks that allowed calls
pass through intact and that refused ones never reach the server.

## Layout

| crate | role |
| --- | --- |
| `authz-core` | `ToolCall`, `Context`, `Decision`, `Executor` |
| `authz-tools` | MCP tool server: `fs_read`, `http_fetch`, `email_send`, `shell_run` (all simulated) |
| `authz-guard` | the `Gate` (single decision path), policy engine, audit log, MCP client, and the two front ends: in-process `Interceptor` and stdio `Proxy` |
| `authz-agent` | agent loop and model backends. **No dependency on the tool client**: it can only act through the `Executor` it is handed |
| `authz-cli` | `authz` binary: wiring, corpus runs, eval |

## The boundary is enforced by the compiler

The handoff rule is that the interceptor is the *only* path to execution. That holds structurally:

1. `authz-agent` has no dependency on the tool client or server (`tests/boundary.rs`).
2. `Mcp::exec` is crate-private, so outside `authz-guard` the only executor is `Interceptor` (`tests/ui/bypass_exec.rs`, E0624).
3. `Mcp::exec` takes an `Authorization` by value. It is bound to one call and single-use. Only `token.rs` can mint one: on a policy `Allow`, or on a human approving an `Escalation` (`tests/ui/forge_token.rs`, E0451).
4. The interceptor writes the decision to `audit.jsonl` *before* executing, and fails closed if the log write fails.

The unguarded baseline is `Rules::permit_all()`: the same code path with an explicit allow-everything policy, still audited.

`fixtures/` holds the offline web pages and files the tools serve. `eval/corpus/` holds
attack and benign cases. Every side effect is appended to `sandbox/<mode>/<case>/events.jsonl` (decisions in `audit.jsonl` beside it)
and nothing is sent, fetched or executed for real.

## Policy

`policies.yaml` is data; the engine (`crates/authz-guard/src/policy.rs`) is generic. Rules can only
`deny` or `escalate`, so no rule can loosen a decision. Every matching rule is evaluated and the
most severe wins, so rule order cannot shadow a deny. Arguments are percent- and base64-decoded
before matching. Entities the user named in the task (recipients, hosts, commands) are the only
ones permitted for sensitive arguments.

MCP tool annotations are treated as untrusted hints that can only tighten a decision. `http_fetch`
is honestly annotated read-only, yet it is the main exfiltration channel.

## Taint tracking

Tools the policy labels (e.g. `fs_read: {taint: private}`) have their output recorded in a session
ledger by the interceptor, never by the model. `carries_taint` holds when an argument, after
decoding, shares a run of at least `min` characters with labeled output. A URL's host counts too
(data can ride in a subdomain), unless the source itself names that host, and a value copied whole
from the source is treated as a reference rather than a leak. `tainted-fetch` denies private data
in a URL to an unnamed host; `tainted-mail` escalates private data mailed to an unnamed recipient.

Limitation: this tracks verbatim and encoded reuse. A model that paraphrases private data defeats
it. Precise information-flow control needs the planner and data to be separated (as in CaMeL).

## Escalation

`escalate` pauses the call for a human: `--approve ask` prompts on the terminal (the default when
one is attached), `deny` fails closed (the default otherwise, e.g. CI), and `allow` approves
everything, which measures what deny rules stop on their own. The audit log records `escalate` and
then `approved` or `denied`, before anything runs.

A human can approve an escalation but never a block: `authorize` returns an unforgeable
`Escalation` (`tests/ui/forge_escalation.rs`, E0451), and only an `Escalation` can be approved into
an `Authorization`. A deny is a different type and has no path to execution.

## Framework mapping

Each attack case carries `refs`: **OWASP Top 10 for Agentic Applications 2026** (ASI, primary),
OWASP Top 10 for LLM Applications 2025, and MITRE ATLAS technique IDs. All three are pinned from
official sources in `eval/frameworks/` (ATLAS v2026.10), and `tests/refs.rs` fails if any case
cites an ID that does not exist.

## Run

```sh
cargo build --workspace
cargo run -p authz-cli --bin authz -- run                # whole corpus, policies.yaml
cargo run -p authz-cli --bin authz -- run --unguarded    # permit-all baseline
cargo run -p authz-cli --bin authz -- run eval/corpus/atk-01-web-exfil.json -v
cargo run -p authz-cli --bin authz -- run --model ollama   # real local model
cargo test --workspace

# evaluation: headline numbers (block rate, FPR), per-case table, JSON in eval/out/
cargo run --release -p authz-cli --bin authz -- eval --ablation
cargo run --release -p authz-cli --bin authz -- eval --model ollama --approve allow
```

## Models

| backend | use |
| --- | --- |
| `scripted` (default) | Deterministic stand-in for a maximally compliant agent. Injected steps fire only if the injected text reached it, so attack success is causal, but the unguarded baseline succeeds by construction. |
| `ollama` | A real local model via Ollama (default `qwen3:8b`). Temperature 0, fixed seed, reasoning off, neutral system prompt. It gives a realistic unguarded baseline. |

Environment: `AUTHZ_MODEL` (Ollama tag), `OLLAMA_HOST` (default `http://127.0.0.1:11434`),
`AUTHZ_THINK=1` to enable reasoning. The agent gets tool *descriptions* from the interceptor as
plain data, so a model backend never gains a path to execution.

## Status

- [x] **M0** bare agent, no guard: benign tasks complete, 3/3 seed attacks reproduce
- [x] **M1** interceptor + allowlist + audit: every execution has a prior logged allow; denying a tool blocks it
- [x] **M2** context-aware policy: 6/6 attacks blocked (3 of them in-scope, caught by argument inspection), 6/6 benign tasks complete
- [x] **M3** escalation: borderline calls pause for a human (approve runs it, deny stops it, both audited); approvals can never override a deny
- [x] **M4** taint tracking: private data read this session cannot ride an egress call to a destination the user didn't name; it stops a codename leak in a URL path that every M2 rule misses
- [x] **M5** eval + report: `authz eval` reproduces the headline numbers; write-up in [report/findings.md](report/findings.md)
