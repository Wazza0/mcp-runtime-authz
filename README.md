# mcp-runtime-authz

Runtime authorization layer between an LLM agent and its MCP tools: every proposed
tool call is checked against least-privilege policy *before* it runs
(allow / block / escalate). Built in Rust on the official MCP SDK (`rmcp`).

## Layout

| crate | role |
| --- | --- |
| `authz-core` | `ToolCall`, `Context`, `Decision`, `Executor` |
| `authz-tools` | MCP tool server: `fs_read`, `http_fetch`, `email_send`, `shell_run` (all simulated) |
| `authz-guard` | MCP client, interceptor, policy engine, audit log |
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
OWASP Top 10 for LLM Applications 2025, and MITRE ATLAS technique IDs. ATLAS IDs are verified
against official release data in M5.

## Run

```sh
cargo build --workspace
cargo run -p authz-cli --bin authz -- run                # whole corpus, policies.yaml
cargo run -p authz-cli --bin authz -- run --unguarded    # permit-all baseline
cargo run -p authz-cli --bin authz -- run eval/corpus/atk-01-web-exfil.json -v
cargo run -p authz-cli --bin authz -- run --model ollama   # real local model
cargo test --workspace
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
- [ ] M4 taint tracking
- [ ] M5 eval + report
