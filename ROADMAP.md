# Roadmap

What the project plans to do, and not do, through the end of 2027. Priorities can change; the
reasons will be written on the related issue.

## Planned

1. **One proxy in front of several servers.** Today each server gets its own proxy, so taint cannot
   follow data from one server to another (read with the filesystem server, sent with fetch). A
   multi-server gateway would share one session, policy and taint ledger.
2. **Ask the user inside the client.** Escalations in the proxy fail closed because stdin carries the
   protocol. MCP elicitation would let the proxy ask the person in their own client instead.
3. **Tamper-evident audit log.** Hash-chain the audit records so an edited or truncated log is
   detectable.
4. **More starter policies**, each verified by a test against the real server it wraps, like the
   filesystem, fetch and git policies.
5. **A stronger evaluation.** Run a public agent benchmark through the proxy for comparable numbers,
   add an adaptive attacker, and measure utility under attack.
6. **Poisoned tool descriptions** as an attack class. Pinning catches definitions that change; it
   does not judge a definition that was hostile from the start.
7. **A stable policy format and 1.0.** Until 1.0, the policy format may change between minor
   versions; every change is noted in the release notes with how to update.

## Not planned

- **Allow rules.** Rules will stay restrict-only; it is a core guarantee, not a missing feature.
- **Filtering the model's text.** The guard judges tool calls, not what the model says.
- **Replacing sandboxing.** `authz` decides which calls run; it is not an OS sandbox or container,
  and it should be combined with one.
- **Exact information-flow control.** Catching paraphrased data needs the planner separated from
  untrusted data (as in CaMeL or FIDES), a different architecture from a proxy.
- **A hosted service.** `authz` runs locally, next to your client.
