# Security policy

This project is a security control, so a flaw in it matters more than a flaw in most code.
Reports are very welcome.

## What counts

Anything that breaks a guarantee the project claims, for example:

- A tool call that the policy should refuse but that reaches the downstream server.
- A way to make a refused call, or its reason, disappear from the audit log.
- A path to execution that skips the `Gate`, or a way to mint an `Authorization` or
  `Escalation` outside `token.rs`.
- A human approval that overrides a deny.
- A refusal message that reveals which rule fired or why.
- A policy file that loads but silently weakens a rule (for example a rule that can never fire).

Known limitations listed in [report/findings.md](report/findings.md#limitations), such as
paraphrased data evading taint tracking, are not vulnerabilities on their own, but a concrete
case that shows one is worse than described is still useful.

## How to report

Please report privately through GitHub's private vulnerability reporting:
**https://github.com/Wazza0/mcp-runtime-authz/security/advisories/new**
(or the **Report a vulnerability** button on the Security tab), rather than opening a public
issue. Include the policy, the tool call (or MCP request) and what you expected the guard to do.

## What happens next

This follows coordinated disclosure:

1. The report is acknowledged and reproduced privately.
2. A fix is developed with a regression test that fails before it and passes after.
3. A patched release is published, with a GitHub security advisory describing the issue.
4. Reporters are credited in the advisory and the commit, unless they prefer not to be.

This is a solo project, so please allow some time for a response, and please don't disclose
publicly until a fix is released.

## Supported versions

Only the latest release and `master` receive security fixes.
