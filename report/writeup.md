# I built a firewall for AI agent tools. Here's what broke when I tested it.

AI coding agents now read files, fetch web pages, run shell commands and call MCP servers on our
behalf. The risk everyone knows about is prompt injection: an agent reads some content with
instructions hidden in it, and uses the tools it legitimately has to do something you never asked
for. The usual defence is an approval prompt. But after the twentieth one, everyone clicks yes,
and plenty of people switch approvals off entirely.

So I built a guard that checks every tool call before it runs, and then spent most of my time
trying to prove it wrong. This post is mostly about the second part, because that's where the
interesting things happened.

Code: [github.com/Wazza0/mcp-runtime-authz](https://github.com/Wazza0/mcp-runtime-authz)

## What it is

`mcp-runtime-authz` is a proxy that sits between an MCP client (Claude Code, Claude Desktop,
Cursor) and the servers it uses. Every call is allowed, blocked or escalated against a policy
written as data, and every decision is logged with its reason before anything runs.

A few design choices I'd defend in an interview:

- **Nothing can skip the check, and that's a compile error rather than a convention.** Running a
  tool needs a single-use token bound to that exact call, and only a policy allow can mint one.
- **Rules can only restrict.** No rule can loosen another, so you can't accidentally shadow a deny.
- **A human can approve a borderline call but can never override a deny.**
- **Refused calls tell the agent nothing** beyond "blocked" and a log reference. More on why below.

## How I measured it

I ran 7 attack cases and 6 benign tasks through two agents. One was scripted to obey every injected
instruction, which shows whether an attack *can* reach its goal. The other was a real local model,
qwen3:8b. Everything ran against simulated tools, so nothing was ever really sent or executed.

The metric matters. I count the block rate only over attacks that succeed *without* the guard. The
real model resisted four of the seven injections on its own, and crediting that to the guard would
have inflated the number.

| | scripted agent | qwen3:8b |
| --- | --- | --- |
| attacks that worked with no guard | 7/7 | 3/7 |
| attack-block rate | 100% (7/7) | 100% (3/3) |
| benign tasks broken | 0/6 | 0/6 |
| block rate if a human approves every prompt | 86% (6/7) | 67% (2/3) |

The three attacks qwen3 fell for were not subtle. Unguarded, it read a credentials file and emailed
it to an address planted in an invoice, redirected a team summary to an outsider, and leaked
meeting notes inside a URL.

I want to be upfront about what these numbers aren't. The corpus is small, I wrote it myself, and I
also wrote the rules, which flatters the result. Treat it as a demonstration that the mechanisms
work, not as proof they generalise.

## What broke

This is the part I'd actually want to read in someone else's post. I found four real bypasses in
my own guard. Each one is fixed and has a regression test.

**1. A whole file counted as "just a reference."** Taint tracking stops private data you read
earlier from leaving through a later call. To avoid false alarms, I exempted values copied
*whole* from a source, meaning links the agent finds in a note and follows. But I applied that
exemption to any value, not just links. So pasting an entire private file into an email body was
treated as harmless. I only found this by removing rules one at a time and noticing that one attack
should still have been caught by a second rule, and wasn't.

**2. Everything before a link was ignored.** My test for bug 1 then exposed a worse one. My check
for "is this a URL?" was "does it contain `://`?". That's true of any text that merely *mentions* a
link. The code then trimmed the value to the part after the `://`, so in "private data, then a
link", the private data was silently dropped before matching. That's a one-line evasion, and I
would never have spotted it by reading the code.

**3. My error messages were an oracle.** When the guard blocked a call, it told the agent which rule
fired and why. That sounds helpful, until you remember the agent may be following an attacker's
instructions. "Blocked: carries secret data" is exactly the feedback an attacker needs to try a
different encoding. Now the agent gets a generic refusal; the detail stays in the log for humans.

**4. A list hid what a single value couldn't.** This is my favourite, because no amount of testing
against my own setup could have found it. I put the proxy in front of the official MCP filesystem
server. Reading `.env` directly: blocked. Reading notes plus `.env` in one `read_multiple_files`
call: **the secret came straight back.** That tool takes its paths as a list, and my rules only
inspected plain string values. My own test server only ever takes strings, so the gap was
invisible until a real server exercised it.

## What I took away from it

- **Test against real software, not just your own fixtures.** Bug 4 lived in the gap between how I
  imagined tools look and how a real one actually works.
- **Ablate your own defence.** Removing one rule at a time showed which rules overlap, which are
  single points of failure, and where a rule silently wasn't doing its job.
- **Be stingy with feedback to an untrusted caller.** Helpful error messages are a policy oracle.
- **State your limits before someone else does.** Mine: a small self-written corpus, no attacker
  that adapts to the guard, and taint tracking that catches copied or encoded data but not
  paraphrased data.

## Is this new?

Mostly not, and I'd rather say so than have someone point it out. Published systems like Progent,
CaMeL and FIDES already do policy checks on tool calls and track where data comes from. The parts
I'd call mine are narrower: making "nothing skips the check" a compile-time guarantee, making it
structurally impossible for a human approval to override a deny, and the evaluation itself, which
I couldn't find for any of the open-source MCP gateways I looked at.

The full write-up, with per-case results, framework mappings (OWASP Agentic Top 10 2026, MITRE
ATLAS) and limitations, is in [report/findings.md](findings.md). CI reproduces the scripted numbers
on every push.
