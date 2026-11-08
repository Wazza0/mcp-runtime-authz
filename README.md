# mcp-runtime-authz

[![CI](https://github.com/Wazza0/mcp-runtime-authz/actions/workflows/ci.yml/badge.svg)](https://github.com/Wazza0/mcp-runtime-authz/actions/workflows/ci.yml)

**A firewall for your AI agent's tools.** It sits between an MCP client (Claude Code, Claude
Desktop, Cursor, …) and the MCP servers it uses, and checks every tool call *before* it runs.
Small, auditable Rust, built on the official MCP SDK.

```
MCP client ──▶ authz proxy (policy + audit log) ──▶ the MCP server you already use
```

## What it stops

- **Secrets leaving through tools**, even base64- or percent-encoded, and even when the
  destination looks legitimate.
- **Private files being read** (`.env`, keys, `.ssh`, credential files), including when the path
  is tucked inside a list of other files.
- **Private data you read this session being sent somewhere you didn't allow** (taint tracking),
  whether it rides in a URL, an email body or a subdomain.
- **Code planted to run later:** writes to git hooks, CI workflows, editor tasks, shell rc files.
- **Destinations and commands you never allowed:** hosts, email recipients, shell commands.

Every decision is logged, with its reason, before anything runs. The agent only ever sees
`BLOCKED` plus an audit reference, so it can't learn the rules and work around them.

## Quick start

Download a prebuilt binary for Linux, macOS (Apple silicon) or Windows from
[Releases](https://github.com/Wazza0/mcp-runtime-authz/releases/latest). Each archive includes the
starter policies and a `.sha256` checksum. Or build from source with `cargo build --release`.

```sh
authz proxy --policy policies/filesystem.yaml --audit audit.jsonl \
  -- npx -y @modelcontextprotocol/server-filesystem /path/to/project
```

Point your client at the proxy instead of the server. In `.mcp.json` (Claude Code), or Claude
Desktop's or Cursor's config (on Windows use `npx.cmd`):

```json
{
  "mcpServers": {
    "files": {
      "command": "/path/to/authz",
      "args": ["proxy", "--policy", "/path/to/policies/filesystem.yaml", "--audit", "/path/to/audit.jsonl",
               "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/project"]
    }
  }
}
```

| starter policy | wraps | what it adds |
| --- | --- | --- |
| [`filesystem.yaml`](policies/filesystem.yaml) | the official [filesystem server](https://www.npmjs.com/package/@modelcontextprotocol/server-filesystem) | credential files stay unreadable; secrets can't be written into files; no writes that run code later |
| [`example-proxy.yaml`](policies/example-proxy.yaml) | a template for any server | an `allow` list for hosts, email recipients and shell commands |

## Does it work?

Measured on a small corpus (7 attacks, 6 benign tasks), unguarded vs guarded. Block rate counts
only attacks that succeed without the guard, so the model resisting by itself earns no credit.

| | scripted agent (obeys every injection) | qwen3:8b (real local model) |
| --- | --- | --- |
| attacks that succeed with no guard | 7/7 | 3/7 |
| **attack-block rate** | **100% (7/7)** | **100% (3/3)** |
| **false-positive rate** (benign tasks broken) | **0% (0/6)** | **0% (0/6)** |
| block rate if a human approves every prompt | 86% (6/7) | 67% (2/3) |

Prompts on the 6 benign tasks: zero, in every run. **Read these as a demonstration, not proof of
generality:** the corpus is small and self-written, and the same author wrote the attacks and the
rules. The full write-up, limitations included, is in [report/findings.md](report/findings.md).
CI reproduces the scripted numbers on every push.

## Found and fixed

Four real bypasses in this project's own code, found by testing and review, each fixed and pinned
by a regression test:

1. **A whole private file pasted into an email body** counted as a harmless reference. Found by
   removing rules one at a time.
2. **Text that mentioned a link** had everything before the link ignored, so data placed in front
   of a URL went unchecked.
3. **Refusals named the rule that fired**, giving injected instructions a way to probe the policy
   and retry. Raised in review of related work. The agent now learns nothing.
4. **A denied file hidden in a list** (`read_multiple_files`) was returned while a direct read was
   refused. Found only by testing against the real filesystem server; our own test server never
   takes lists.

## How it works

Every tool call goes through one decision path, the `Gate`, whether it comes from the proxy or
the bundled test agent. Four guarantees hold by construction:

- **Nothing skips the check, and the compiler enforces it.** Running a tool requires a single-use
  token bound to that exact call, and only a policy allow (or a human approving an escalation) can
  mint one. Forging a token or calling the tool client directly is a compile error, pinned by
  tests.
- **Rules can only restrict.** A rule can deny or escalate, never allow, and the most severe match
  wins, so no rule can loosen another.
- **A human can approve a borderline call but never override a deny.** That's in the types, not a
  convention.
- **The log is written first.** If the audit write fails, the call doesn't run.

Arguments are decoded (percent, base64) and searched inside lists and objects before matching.
MCP tool annotations are treated as untrusted hints that can only tighten a decision. Design notes
are [below](#design-notes).

## Writing a policy

Policies are YAML data; the engine is generic. Start from
[`example-proxy.yaml`](policies/example-proxy.yaml):

- **The `allow` list is your trust anchor.** The proxy never sees what you typed, so hosts, email
  recipients and shell commands are permitted only if the policy lists them.
- **List each tool the server exposes** under `tools:` with a risk class (`read`, `write`,
  `egress`, `exec`). Anything unlisted falls to `default`, which should be `deny`.
- **Escalations fail closed in the proxy.** stdin carries the MCP protocol, so the proxy can't
  prompt you; an escalated call is refused and logged. `--approve allow` turns them into allows.
- **Malformed policies are rejected:** duplicate keys, unknown fields, bad patterns, and rules that
  could never fire all fail at load.

## Tests and evaluation

```sh
cargo test --workspace                       # 27 tests: milestone gates, proxy, compile-time guarantees
cargo test -p authz-cli --test proxy_filesystem -- --ignored   # against the real server (needs Node)

cargo run --release -p authz-cli --bin authz -- eval --ablation          # scripted agent + per-rule ablation
cargo run --release -p authz-cli --bin authz -- eval --approve allow     # human approves everything
cargo run --release -p authz-cli --bin authz -- eval --model ollama      # real local model (needs Ollama)
```

`tests/proxy.rs` drives the proxy with the official MCP SDK client and checks that allowed calls
pass through intact and refused ones never reach the server. Attack cases carry references to the
OWASP Top 10 for Agentic Applications 2026, the OWASP LLM Top 10 2025 and MITRE ATLAS v2026.10,
pinned from official sources in `eval/frameworks/` and checked by `tests/refs.rs`.

## Limitations

- Small, self-written corpus; no attacker that adapts to the guard.
- Taint tracking catches data reused verbatim or encoded, not paraphrased.
- Pattern-based secret detection misses formats and encodings it doesn't know.
- In the proxy, the `allow` list must be written by hand; escalations can't prompt.

More in [report/findings.md](report/findings.md#limitations). How this compares to published work
(Progent, CaMeL, FIDES and others) is in [report/related-work.md](report/related-work.md).

## Design notes

**Layout.**

| crate | role |
| --- | --- |
| `authz-core` | shared types: `ToolCall`, `Context`, `Decision`, `Policy`, `Executor` |
| `authz-guard` | the `Gate`, policy engine, inspection, taint, audit log, MCP client, and the two front ends: in-process `Interceptor` and stdio `Proxy` |
| `authz-tools` | a simulated MCP tool server for the evaluation: nothing is sent, fetched or executed |
| `authz-agent` | agent loop and model backends; **no dependency on the tool client**, so it can only act through what it's handed |
| `authz-cli` | the `authz` binary: `proxy`, `run`, `eval`, `serve-tools` |

**The boundary, structurally.** `authz-agent` cannot name the tool client (`tests/boundary.rs`).
Execution is crate-private (`tests/ui/bypass_exec.rs`, E0624) and consumes an `Authorization` that
only `token.rs` can mint (`tests/ui/forge_token.rs`, E0451). `authorize` returns an unforgeable
`Escalation` for human review (`tests/ui/forge_escalation.rs`, E0451); a deny is a different type
with no path to execution. The unguarded baseline is the same path with an allow-everything policy.

**Taint tracking.** Output of tools the policy labels (e.g. `taint: private`) is recorded by the
guard, never the model. A later argument that shares a run of at least `min` characters with it,
after decoding, carries that data. A URL's host counts too, unless the source itself names that
host; a URL copied whole from a source is a link being followed, not a leak.

**Escalation in the bundled agent.** `authz run --approve ask` prompts on the terminal, `deny`
fails closed, `allow` approves everything. The audit log records `escalate`, then `approved` or
`denied`, before anything runs.

**Models for the evaluation.** `scripted` replays each case's plan, with injected steps firing only
if the injected text reached it. `ollama` runs a real local model (default `qwen3:8b`, temperature
0, fixed seed, reasoning off, neutral system prompt); set `AUTHZ_MODEL` and `OLLAMA_HOST`.

**History.** Built in milestones M0 to M5 (bare agent, interceptor, context-aware policy,
escalation, taint tracking, evaluation), then refocused into a proxy for real MCP servers.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
Found a way past the guard? See [SECURITY.md](SECURITY.md).
