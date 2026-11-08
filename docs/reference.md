# Reference

The external interface of `authz`: its commands, the policy file format, and the files it reads
and writes. For an introduction, see the [README](../README.md).

## Commands

### `authz proxy`

```
authz proxy --policy <file> [--audit <file>] [--approve deny|allow] [--pin <tools.lock> [--repin]]
            -- <mcp-server-command> [args...]
```

Runs as an MCP server on stdin/stdout and starts `<mcp-server-command>` as its downstream MCP
server. Every `tools/call` is decided by the policy before it reaches the downstream server.

| option | meaning |
| --- | --- |
| `--policy <file>` | Policy file (required). See [Policy file](#policy-file). |
| `--audit <file>` | Where to append the audit log. Default `authz-audit.jsonl`. |
| `--approve deny\|allow` | What happens to escalated calls. Default `deny`. stdin carries the MCP protocol, so the proxy cannot ask a person. |
| `--pin <file>` | Enable [tool pinning](#pin-file) with this lock file. |
| `--repin` | Accept the server's current tools as the new pins. |

**Input:** MCP requests from the client. **Output:** MCP responses. An allowed call returns the
downstream result unchanged. A refused call returns a tool error whose text is
`BLOCKED: <message> (audit #<n>)`, which never names the rule or the reason. Diagnostics go to
stderr only.

### `authz init`

```
authz init [--out <file>] -- <mcp-server-command> [args...]
```

Connects to the server, reads its tool list, and writes a draft policy to `--out` (or stdout). The
draft is loaded as a policy before it is written; an existing `--out` file is never overwritten.

### `authz audit`

```
authz audit <audit.jsonl>
```

Prints the audit log as a table, one line per decision, then `N calls: R ran, F refused`.

### `authz run` and `authz eval`

```
authz run  [case.json|dir] [-v] [--policy <file> | --unguarded] [--model scripted|ollama] [--approve deny|allow|ask]
authz eval [--model scripted|ollama] [--approve deny|allow] [--policy <file>] [--ablation] [--out <file>]
```

Run the evaluation corpus (`eval/corpus/`) through the bundled agent. `run` prints one line per case.
`eval` prints the headline metrics and per-case results as Markdown and writes JSON to `--out`
(default `eval/out/results-<model>.json`). `--ablation` repeats the guarded run once per rule
with that rule removed. `--model ollama` uses `AUTHZ_MODEL` (default `qwen3:8b`) and `OLLAMA_HOST`.

### `authz serve-tools`

Serves the simulated tools used by the evaluation (`fs_read`, `http_fetch`, `email_send`,
`shell_run`) over MCP stdio. Nothing is sent, fetched or executed; every call is appended to
`$AUTHZ_SANDBOX/events.jsonl`.

## Policy file

YAML. Unknown fields and duplicate keys are rejected.

```yaml
default: deny                 # allow | deny | escalate, for tools not listed under `tools`

allow:                        # destinations permitted in addition to anything the task names
  hosts: [docs.example.com]
  emails: [team@example.com]
  commands: [cargo test]

tools:                        # every tool the server exposes
  read_file:  {action: allow, class: read, taint: private}
  fetch:      {action: allow, class: egress}

patterns:                     # named lists of regular expressions
  secret: ['sk-(live|test|proj)-[A-Za-z0-9_-]{8,}']

rules:                        # can only restrict; see Evaluation
  - id: secret-egress
    action: deny              # deny | escalate (never allow)
    class: egress             # optional selector: only tools of this class
    tool: fetch               # optional selector: only this tool
    when:                     # all conditions must hold; empty = always
      - {any_arg_matches: {set: secret}}
```

### Tool entries

| field | values | meaning |
| --- | --- | --- |
| `action` | `allow`, `deny`, `escalate` | The tool's base verdict before rules. |
| `class` | `read`, `write`, `egress`, `exec` | Risk class used by rule selectors. |
| `taint` | any label (optional) | Record this tool's output under this label for `carries_taint`. |

### Conditions

String values are percent-decoded (twice) and base64-decoded before matching, and arrays and
objects are searched.

| condition | holds when |
| --- | --- |
| `not_in_scope` | The tool is not in the session scope (the task's tools; in the proxy, the policy's `tools`). |
| `{arg_matches: {arg, set}}` | A string in argument `arg` matches a pattern in `set`. |
| `{any_arg_matches: {set}}` | A string in any argument matches a pattern in `set`. |
| `{arg_not_in_task: {arg, kind}}` | Argument `arg` names something not permitted. `kind: email` and `host` compare against entities named in the task plus `allow.emails` / `allow.hosts`; `literal` requires each value to appear in the task or in `allow.commands`. A URL's host is read after any `user:pass@` and before the port; if parsers could disagree, every possible host must be permitted. |
| `{query_longer: {arg, len}}` | The URL in `arg` has a query longer than `len` bytes. |
| `{hint: read_only \| destructive \| open_world}` | The server declares this annotation. Hints are untrusted and, since rules only restrict, can only tighten. |
| `{carries_taint: {label, min, args}}` | An argument (or one of `args`) shares a run of at least `min` characters (`min` ≥ 4) with output recorded under `label` this session. |

### Evaluation

1. A tool not under `tools` gets the `default` action.
2. The tool's own `action` is the starting verdict.
3. Every rule whose selectors match and whose conditions all hold is applied. The most severe
   outcome wins (`deny` beats `escalate`), whatever the rule order.
4. No match leaves the call allowed.

A human may approve an `escalate` (in the bundled agent with `--approve ask`), never a `deny`.

### Load-time checks

A policy is rejected at load if it has duplicate keys, unknown fields, an invalid regular
expression, a rule referring to an unknown pattern set or tool, duplicate rule ids, a
`carries_taint` label that no tool produces, or `carries_taint` with `min` below 4.

## Audit log

JSON Lines, appended, one record per decision, written before the call runs. If a write fails, the
call is refused.

| field | meaning |
| --- | --- |
| `seq` | Sequence number within the session (the `audit #<n>` in refusals). |
| `ts` | Unix time, milliseconds. |
| `tool`, `args` | The call as proposed. |
| `verdict` | `allow`, `block`, `escalate`, then `approved` / `denied` for escalations. |
| `rule` | The deciding rule (`-` for allow; `tools.<name>`, `default`, a rule id, `tool-changed` or `tool-new`). |
| `also` | Other rules that matched. |
| `reason` | Human-readable reason. |
| `note` | `executing`, `not executed`, `awaiting approval`, or `by <approver>`. |

## Pin file

JSON: `{"tools": {"<tool name>": "sha256:<hex>"}}`. The fingerprint covers the tool's name, title,
description, input and output schema, and annotations. On a run with `--pin`, a missing file is
created from the current tools. A tool whose fingerprint differs, or that is not in the file, is
left out of `tools/list` and refused if called, with `rule` `tool-changed` or `tool-new`.
`--repin` rewrites the file from the current tools.
