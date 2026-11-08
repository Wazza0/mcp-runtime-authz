# mcp-runtime-authz

Runtime authorization layer between an LLM agent and its MCP tools: every proposed
tool call is checked against least-privilege policy *before* it runs
(allow / block / escalate). Built in Rust on the official MCP SDK (`rmcp`).

## Layout

| crate | role |
| --- | --- |
| `authz-core` | `ToolCall`, `Context`, `Decision`, `Executor` |
| `authz-tools` | MCP tool server: `fs_read`, `http_fetch`, `email_send`, `shell_run` (all simulated) |
| `authz-guard` | MCP client; interceptor + policy + audit (M1+) |
| `authz-agent` | agent loop and model backends. **No dependency on the tool client**: it can only act through the `Executor` it is handed |
| `authz-cli` | `authz` binary: wiring, corpus runs, eval |

`fixtures/` holds the offline web pages and files the tools serve. `eval/corpus/` holds
attack and benign cases. Every side effect is appended to `sandbox/<case>/events.jsonl`
and nothing is sent, fetched or executed for real.

## Run

```sh
cargo build --workspace
cargo run -p authz-cli --bin authz -- run          # whole corpus
cargo run -p authz-cli --bin authz -- run eval/corpus/atk-01-web-exfil.json -v
cargo test --workspace
```

## Status

- [x] **M0** bare agent, no guard: benign tasks complete, 3/3 seed attacks reproduce
- [ ] M1 interceptor + allowlist + audit
- [ ] M2 context-aware policy
- [ ] M3 escalation
- [ ] M4 taint tracking
- [ ] M5 eval + report
