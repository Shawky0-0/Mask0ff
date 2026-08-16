---
tags: [security, flash, advisories, api, entry, api9, ai-endpoint, mcp, praisonai]
updated: 2026-08-16
sources:
  - "https://github.com/advisories/GHSA-x8cv-xmq7-p8xp, accessed 2026-08-16"
---

# APIDS-0027, one method call stood up a public agent invocation API, and nobody wrote a route

Related: APIDS-0028 (the sibling defect in the same
product), MTH-API-012,
the ledger.

**The folder's first `API9` improper inventory management as a primary root cause.** That row had
been at zero for four runs. It is also an AI agent framework, so it lands on the fastest growing
row in the coverage table.

```yaml
id: APIDS-0027
component:
  type: library
  ecosystem: pip
  name: praisonaiagents
  version_scope: "AgentTeam.launch(), also exported as Agents.launch()"
affected:
  introduced: ___
  fixed_in: "1.6.59"
  tested_on: ___
identifiers:
  cve: CVE-2026-57118
  ghsa: GHSA-x8cv-xmq7-p8xp
  osv: ___
  vendor_id: ___
class:
  owasp_api: API9 improper inventory management (primary), API5 broken function level authorisation (secondary)
  owasp_2025: ___
  cwe: CWE-306 missing authentication for critical function, CWE-862 missing authorisation
  family: the surface the framework opens that the developer never declared
protocol: rest
auth_required: none
entry_point: "GET /{path}/list, POST /{path}, POST /{path}/{agent_id}, on the FastAPI server started by AgentTeam.launch(), documented as binding 0.0.0.0"
object_graph:
  creates: "the developer's own process, by calling launch(). No request creates these routes; a library call does"
  owns: "the operator running the script"
  should_reach: "whoever the operator intended, which the advisory notes is usually nobody, because launch() reads as a local convenience"
  tested_account_got: "an unauthenticated network client enumerated every agent id and name, then invoked any of them individually or all of them in sequence"
root_cause: >
  `AgentTeam.launch()` in `src/praisonai-agents/praisonaiagents/agents/agents.py` starts a FastAPI
  server and registers three routes, and the handlers call `agent.chat(...)` directly. There is no
  middleware, no dependency, no token comparison and no startup validation. The advisory is explicit
  that a request with no Authorization header is accepted and a request with an obviously wrong
  bearer token is also accepted, which means the token is not merely optional, it is not read at
  all. The missing decision is an authentication gate on the three handlers, and the reason it is
  `API9` rather than only `API5` is that the operator never wrote the routes and so has no reason to
  know they need a gate.
signal: >
  A library method whose name is a verb about running, not about serving: `launch`, `serve`,
  `start`, `deploy`, `run`. Grep the framework for what it binds and what it registers, not the
  application for what it declared. **The route list in the code review is not the route list on
  the wire.** The advisory also notes that sibling surfaces in the same product had already been
  hardened with tokens or loopback binding, so this one was left behind: an incomplete fix reached
  by counting the surfaces rather than the calls.
safe_proof: >
  Entirely static, and that is the point. Read the framework source for the routes `launch()`
  registers, and confirm no dependency or middleware sits on them. If a live check is wanted in a
  lab, call the `list` route with a deliberately wrong bearer token and see the agent inventory
  come back. Stop there. Do not invoke an agent, because invoking is a side effect and on Ahmed's
  fleet it would also be a bill.
controls:
  negative: "call with a correct token, if one can be configured at all. If the response is identical to the no token case, the token is decorative."
  differential: "compare against the sibling surfaces the vendor did harden. If one path demands a token and another does not, the gap is the finding, not the absence of tokens generally."
  false_positive: "the process may in fact be bound to loopback in the deployment even though the documented pattern binds 0.0.0.0. Check the actual bind address before calling it network reachable, and report the code default and the deployment separately."
fix:
  commit: ___
  invariant: >
    Stated from the defect, not read from the patch: every route the framework registers on the
    operator's behalf must be gated by the same authentication the operator would have written for
    a route of their own, and the gate must fail closed when no credential is configured.
hardening: >
  Bind loopback by default and require an explicit opt in for any other interface. Require a token
  at startup rather than at request time, so a missing token stops the process instead of opening
  the door. And publish the route list: a framework that stands up endpoints should be able to print
  them, because an inventory the operator can read is the whole control that `API9` is about.
detection: >
  A listening socket on an interface nobody deployed deliberately. On the wire, requests to a path
  the application's own router does not know. In logs, agent invocations with no preceding
  authentication event.
variant_rule: >
  Every AI and agent framework with a one line serve helper: LangServe, Gradio `launch(share=...)`,
  Streamlit, Flowise, Open WebUI, any MCP server's HTTP transport, Jupyter and its kernels, and the
  debug or metrics servers a framework attaches by default (pprof, Prometheus, a HUD). **On Ahmed's
  fleet the question is not "which routes did we write" but "which processes are listening, on what
  interface, and who stood them up". Nobody has asked that yet.**
lab:
  install: "pip install praisonaiagents<1.6.59 in a disposable venv, call launch() with loopback binding"
  snapshot: "none needed"
  teardown: "delete the venv"
provenance:
  source: "GitHub Security Advisory GHSA-x8cv-xmq7-p8xp"
  accessed: 2026-08-16
  license_note: "advisory text summarised, not reproduced"
```

## What happens

A developer writes a few agents and calls `launch()` to try them out. That one call starts a web
server on every network interface. It publishes three routes. One lists every agent by id and name.
One runs them all. One runs whichever you name.

None of them ask who you are. The advisory is blunt about it: no header is fine, and a wrong token
is also fine.

## Why it works

The developer never wrote a route, so there was nothing to put a check on. The framework wrote the
routes, and it did not put a check on them either. Between the two of them, everybody assumed the
other one had done it.

This is why the class is `API9` and not just `API5`. `API5` is the admin route that forgot its
check. `API9` is the route that is not on anyone's list of routes. You cannot review a check you do
not know exists.

The advisory adds one more detail that is worth more than the bug: other server surfaces in the
same product had already been fixed, with tokens or with loopback binding. Somebody counted the
surfaces they knew about. This one was not on that list either.

## How to reproduce

Read the framework, not the application. Find what `launch()` registers. Confirm there is no
dependency or middleware on the handlers. That is the finding, and it needs no traffic at all.

## The fix, and why the obvious fix would not work

Put a token check on the handlers.

The obvious fix is to tell developers to bind loopback. That does not work, because the documented
pattern is the one that binds `0.0.0.0`, and people copy documented patterns. It also does not
address the real problem, which is that the operator does not know the routes are there. The
durable fix is a framework that fails to start without a credential and prints what it opened. A
door that announces itself can be closed. A door nobody knows about cannot.
</content>
