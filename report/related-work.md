# Related work

Claims were checked against primary sources (arXiv abstract and HTML pages, venue pages) on 2026-11-08, and any I could not verify are flagged where they appear. Several papers changed their title or numbers between versions, so each figure names the version it comes from.

## Prior defenses

**CaMeL** (Debenedetti et al., arXiv 2503.18813; SaTML 2026, [listing][satml]). A privileged LLM turns the user query into a Python plan. A quarantined LLM with no tools parses untrusted data. An interpreter tracks each value's provenance and permitted readers, and checks policies before every tool call ([v2][camel-v2h]). Share of AgentDojo tasks solved with provable security: 67% in v1 ([v1][camel-v1]), and 77% against 84% undefended in v2 ([v2][camel-abs]). The SaTML listing's abstract gives 67%. IEEE Xplore would not load, so I could not confirm which figure the proceedings version prints.

**Progent** (Shi et al., arXiv 2504.11703, preprint). v3 (May 2026) is retitled "Securing AI Agents with Privilege Control" ([abs][progent-abs]). An LLM writes allow/forbid rules over tool names and arguments for each task. Unmatched calls are blocked, and forbid wins. In v3, updates that would widen the policy (checked with Z3) go to an approver, which can be a human ([v3][progent-v3]). v3 with gpt-4o: AgentDojo ASR fell from 39.9% to 1.0% and ASB from 70.3% to 3.9%, and 6% of updates needed approval ([v3][progent-v3]). The v2 abstract claimed 0% ([v2][progent-v2]).

**FIDES** (Costa et al., Microsoft, arXiv 2505.23643, preprint, [abs][fides-abs]). The planner propagates integrity and confidentiality labels and keeps high-label results in hidden variables. Before each call it enforces two policies. Consequential tools run only from a trusted context (P-T), and egress reaches only permitted readers (P-F). On AgentDojo, FIDES had 0 successful injections, excluding two non-attack tasks. It also solved about 16% more tasks than a basic planner running the same checks. Implicit flows are out of scope ([v2][fides-v2]).

**IGAC** (Zhu and Wang, arXiv 2606.22916, preprint, v4 September 2026, [abs][igac-abs]). A server-side gateway derives a short-lived intent certificate from the authenticated user message only. The certificate narrows the tool manifest, the gateway checks payload effects before execution, and IGAC "cannot grant authority outside static policy". Outcomes include deny, clarify, confirm and execute, and the audit log is hash-chained ([html][igac-h]). On the authors' own harness no unsafe execution completed. Some unsafe authority (0.0909–0.2727) was still accepted, but it stayed as drafts that never ran ([abs][igac-abs]).

**AgentFlow / Agenra** (Ammanaghatta Shivakumar et al., arXiv 2608.22868, preprint). The AgentFlow title is v1 only, from 24 Aug 2026 ([v1][af-v1]). v2 (15 Oct 2026) is "Agenra: A Language and Verified Core for Stateful LLM Agent Authorization". It is built around a Lean enforcement core, and its abstract drops the v1 numbers ([v2][af-abs]). v1 labels data by sensitivity, category and trust, and applies allow/deny flow rules (default reject, deny wins) and path rules. It returns ALLOW, DENY or PAUSE at the tool boundary and checks bounded properties with Z3 ([v1 html][af-v1h]). The v1 results are labeled "preliminary". Confirmed compromise fell from 33.0% to 0.0% on 949 AgentDojo cases, and from 73.5% to 0.0% on AgentDyn Daily Life ([v1][af-v1]). That metric is the authors' own classification of traces, and the model is not named ([v1 html][af-v1h]).

## Benchmarks and evaluation method

**AgentDojo** (Debenedetti et al., NeurIPS 2024 Datasets and Benchmarks, [poster][adojo-poster], [proceedings][adojo-proc]). It has 97 user tasks and 629 security cases in four suites, and is designed to take new defenses and adaptive attacks ([abs][adojo-abs]).

**AgentDyn** (Li et al., arXiv 2602.03117, preprint). It has 60 open-ended tasks and 560 injection cases, each with a benign third-party instruction on the task's critical path. Nearly all 10 defenses tested are insecure or over-defend ([abs][adyn-abs], [html][adyn-h]). On GPT-4o, utility / ASR is 53.33% / 37.80% with no defense, 0 / 0 for CaMeL and 6.67% / 1.69% for Progent ([html][adyn-h]).

**AutoDojo** (Ma et al., arXiv 2606.15057, preprint). An LLM attacker refines its injections from success counts ([html][adojo2-h]). Static benchmarks often overestimate defenses, and under-specified tasks are the most exposed ([abs][adojo2-abs]). Against Progent on GPT-4o-mini, AutoDojo reaches 7.7% ASR. The best earlier adaptive attack reached 5.1% ([html][adojo2-h]).

**Adaptive evaluation.** Narisetty et al. (arXiv 2606.26479; they note it is not peer reviewed) call our category *out-of-band*: a deterministic policy, outside the model, that mediates the agent's actions ([abs][oob-abs]). They ran only Progent, on a reduced AgentDojo slice with Qwen2.5-7B. ASR fell from 25.8% to 4.2%, and to 2.6% under their adaptive attack. Utility under attack fell from 45.2% to 27.1%. They leave open whether an attack that stays inside the authorized action space succeeds ([html][oob-h]). Nasr et al. bypassed 12 recent defenses, most at over 90% ASR. Most of those had originally reported near-zero ASR ([abs][nasr]).

**MCP-specific.** MCP-SafetyBench (Zong et al., ICLR 2026) runs on real MCP servers across five domains, with 20 attack types on the server, host and user sides. Every model tested stayed vulnerable ([abs][mcpsb-abs], [ICLR][mcpsb-iclr]). MCPTox (Wang et al., arXiv 2508.14925) poisons tool metadata on 45 live servers and 353 tools. It has 1,312 cases in v1 and 1,348 in v2. o1-mini reached 72.8% ASR, and no agent refused more than 3% ([v1][mcptox-v1], [v2][mcptox-abs]). The arXiv page lists an AAAI-26 DOI, but the AAAI page would not load.

## Comparison

| | Mechanism | Where it sits | Trusts | Guarantees | Measured on |
|---|---|---|---|---|---|
| CaMeL | Plan as code; capabilities on values | Interpreter | User query, planner code | Untrusted data cannot steer control flow; policies checked on provenance | AgentDojo |
| Progent | Allow/forbid rules; LLM-written per-task policy | Tool-call proxy | Policy LLM, approver | Off-policy calls blocked; widening needs approval | AgentDojo, ASB, AgentPoison |
| FIDES | Label propagation; hidden variables | Planner | Tool labels, trusted context | P-T / P-F hold for explicit flows | AgentDojo |
| IGAC | Intent certificate narrows static policy | Server gateway | User message, static policy | Never exceeds static policy | Own harness |
| AgentFlow v1 | Labeled flow and path rules; SMT | Tool-call monitor | Policy, label assignment | Properties hold up to bound k | AgentDojo, AgentDyn, ASB |
| **Ours** | Deny/escalate rules on decoded arguments and task-named entities; verbatim/encoded taint matching; call-bound token | In-process, in front of the MCP client | Task text, per-task tool scope, static tool table | No execution without a logged allow (type-enforced); deny overrides, even a human's approval; taint catches verbatim and encoded reuse only, not paraphrase | 13 self-written cases; scripted agent and qwen3:8b; vs. permit-all |

## What's similar, what's different

Most of our design has precedent:

- **Category.** We are out-of-band in Narisetty et al.'s sense ([html][oob-h]). Progent is the closest system. Like ours, it checks arguments, blocks by default, lets deny win, and returns a "not allowed" message to the agent ([v3][progent-v3]).
- **Task as trust anchor.** CaMeL anchors on the user query ([v2][camel-v2h]), FIDES on a trusted context ([v2][fides-v2]), and IGAC on the user message ([html][igac-h]).
- **Restrict-only rules.** IGAC's certificates can only reduce authority ([html][igac-h]). Progent and AgentFlow let deny win ([v3][progent-v3], [v1 html][af-v1h]).
- **Escalation.** Progent's approver, CaMeL's user confirmation, IGAC's confirm and clarify outcomes, and AgentFlow's PAUSE all came first (same sources).
- **Taint tracking (M4).** CaMeL, FIDES and AgentFlow v1 already do it. M4 adopts prior work rather than contributing anything new.
- **Untrusted annotations.** IGAC treats tool metadata as a threat ([html][igac-h]), and MCPTox shows the attack works ([v2][mcptox-abs]).

Where we differ, stated narrowly:

1. **Mediation is enforced at compile time.** The agent crate cannot reach the tool client. Execution consumes a single-use token bound to one call, and only an allow can mint it. Compile-fail tests check both properties ([README](../README.md)). The papers above enforce mediation through runtime architecture, and none that I read makes a bypass a compile error. This says nothing about whether the policy is correct. Agenra v2's Lean-verified core goes further on that, under its stated assumptions ([v2][af-abs]).
2. **The audit is write-ahead and fails closed.** Unlike IGAC's log, ours is not hash-chained ([html][igac-h]).
3. **Decoding before matching** is needed only because we match values instead of tracking provenance. An encoding we don't decode, or a secret split across calls, still gets through. IFC needs no such step.

A reviewer will find several weaknesses (updated after M4):

- The scope is written by hand for each case, which is close to giving the guard an oracle policy.
- The main agent is scripted. A real local model (qwen3:8b) has since been added, but it is one small model.
- The corpus is 13 cases we wrote ourselves.
- In-scope attacks now exist (atk-04 to atk-07 use tools the task legitimately needs), including a secret sent to a host the user named (atk-06). Wrong *content* sent to a named recipient, with no secret pattern in it, is still uncovered.

## What we should adopt

1. **Score escalations.** Report the escalation rate on benign tasks as the approval burden. Progent reports 6%, and IGAC its clarification rate ([v3][progent-v3], [html][igac-h]). CaMeL warns that users stop reading frequent prompts ([v2][camel-v2h]). Report two bounds: the approver always approves, and the approver always denies. *Done:* `authz eval --approve allow|deny`; see findings.md.
2. **Measure utility under attack.** Add a probe for the user's task to every attack case ([html][adojo-h]).
3. **Take M4's policies from FIDES.** Use P-T and P-F, and label each result with the join of what it read and its arguments ([v2][fides-v2]). *Done in part:* the `BLOCKED` message used to quote argument values and name the firing rule. It is now generic, with an audit reference, so it carries no attacker text and gives no policy oracle (commit `15db363`).
4. **Hash-chain the audit log** ([html][igac-h]).
5. **Add harder cases:**
   - in-scope attacks ([html][oob-h])
   - poisoned tool descriptions ([v2][mcptox-abs])
   - benign tasks with legitimate third-party instructions ([html][adyn-h])
   - an AutoDojo-style attacker loop ([abs][adojo2-abs])
6. **Run one public suite,** for example AgentDojo through an MCP adapter ([abs][adojo-abs]).

## Making our numbers comparable

AgentDojo defines three metrics, each scored by deterministic checks on the environment's state ([html][adojo-h]):

- **Benign utility:** the fraction of user tasks solved with no attack present.
- **Utility under attack:** the fraction of security cases (a user task paired with an injection task) where the user task is solved "without any adversarial side effects".
- **Targeted ASR:** the fraction of security cases where the attacker's goal is met.

AgentDyn and AutoDojo report the same three ([html][adyn-h], [html][adojo2-h]).

How our metrics map:

- **Attack-block rate = 1 − ASR, given hijack.** Our scripted agent always attempts the injected steps. The unguarded run therefore measures whether an attack can reach its goal, not whether a model would fall for it (README: 3/3 seed attacks reproduce at M0). Compute the block rate over the attacks that succeed unguarded. This isolates the guard. It is not comparable to a real-model ASR such as Progent's 1.0%, which also counts the model resisting injections on its own.
- **Benign FPR = 1 − guarded benign utility.** This holds only because every scripted benign case succeeds unguarded. With a live model, report the utility drop against the unguarded baseline instead, because models fail many tasks even with no attack ([abs][adojo-abs]).
- **Utility under attack** is not measured yet (adoption item 2).

Report raw counts and runs. With six cases per side, a single case moves a rate by 16.7 points. AgentFlow's "confirmed compromise" is not AgentDojo's ASR ([v1 html][af-v1h]).

[satml]: https://satml.org/2026/accepted-papers/
[camel-v1]: https://arxiv.org/abs/2503.18813v1
[camel-abs]: https://arxiv.org/abs/2503.18813v2
[camel-v2h]: https://arxiv.org/html/2503.18813v2
[progent-abs]: https://arxiv.org/abs/2504.11703
[progent-v2]: https://arxiv.org/abs/2504.11703v2
[progent-v3]: https://arxiv.org/html/2504.11703v3
[fides-abs]: https://arxiv.org/abs/2505.23643
[fides-v2]: https://arxiv.org/html/2505.23643v2
[igac-abs]: https://arxiv.org/abs/2606.22916
[igac-h]: https://arxiv.org/html/2606.22916
[af-v1]: https://arxiv.org/abs/2608.22868v1
[af-v1h]: https://arxiv.org/html/2608.22868v1
[af-abs]: https://arxiv.org/abs/2608.22868v2
[adojo-abs]: https://arxiv.org/abs/2406.13352
[adojo-h]: https://arxiv.org/html/2406.13352v3
[adojo-poster]: https://neurips.cc/virtual/2024/poster/97522
[adojo-proc]: https://proceedings.neurips.cc/paper_files/paper/2024/hash/97091a5177d8dc64b1da8bf3e1f6fb54-Abstract-Datasets_and_Benchmarks_Track.html
[adyn-abs]: https://arxiv.org/abs/2602.03117
[adyn-h]: https://arxiv.org/html/2602.03117v3
[adojo2-abs]: https://arxiv.org/abs/2606.15057
[adojo2-h]: https://arxiv.org/html/2606.15057
[oob-abs]: https://arxiv.org/abs/2606.26479
[oob-h]: https://arxiv.org/html/2606.26479
[nasr]: https://arxiv.org/abs/2510.09023
[mcpsb-abs]: https://arxiv.org/abs/2512.15163
[mcpsb-iclr]: https://iclr.cc/virtual/2026/poster/10011290
[mcptox-v1]: https://arxiv.org/abs/2508.14925v1
[mcptox-abs]: https://arxiv.org/abs/2508.14925
