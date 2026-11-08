# Contributing

Thanks for helping. Bug reports, policy improvements, new starter policies and code are all
welcome.

## Reporting bugs and requesting features

- **Bugs and feature requests:** open an issue at
  <https://github.com/Wazza0/mcp-runtime-authz/issues>. Include the policy, the tool call (or MCP
  request), what happened, and what you expected.
- **Security issues** (a way past the guard, an audit gap, a refusal that leaks the policy): do
  **not** open a public issue. Report privately as described in [SECURITY.md](SECURITY.md).
- Discussion happens in English, on issues and pull requests.

## How to contribute a change

1. Fork the repository and create a branch from `master`.
2. Make the change, with tests (see the requirements below).
3. Run the same checks CI runs:
   ```sh
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets --locked -- -D warnings
   cargo test --workspace --locked
   cargo deny --locked check          # if you changed dependencies
   ```
4. Open a pull request against `master`, explaining what the change does and why. CI must pass
   before it can be merged.

## Requirements for acceptable contributions

- **Formatting and lints:** code is formatted with `rustfmt` using the repository's
  [`rustfmt.toml`](rustfmt.toml), and passes `clippy` with warnings treated as errors.
- **Tests:** every behaviour change comes with a test. A fix for a bypass comes with a regression
  test that fails before the fix and passes after it.
- **One decision path:** every tool call is decided by the `Gate`
  (`crates/authz-guard/src/gate.rs`). Don't add a second place that allows or refuses calls, and
  keep the compile-time guarantees in `crates/authz-guard/tests/ui` passing.
- **Policies are data:** new protections belong in policy files or as generic conditions in the
  engine, not as hard-coded special cases.
- **Fail closed:** when the guard cannot decide, or cannot record a decision, the call must not run.
- **The agent learns nothing:** refusal messages returned to the agent must not reveal which rule
  fired or why; that detail goes to the audit log.
- **Starter policies** under `policies/` are verified against the real server they wrap, like
  `crates/authz-cli/tests/proxy_filesystem.rs`.
- **Dependencies:** new dependencies must pass `cargo deny` (permissive licenses only, crates.io
  only, no known advisories).
- **Style:** short names and few comments. Comment intent, invariants and security reasoning, not
  what the code obviously does.

## Licensing

By contributing, you agree that your contributions are dual-licensed under
[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at the user's option, the same as the project,
without any additional terms or conditions.
