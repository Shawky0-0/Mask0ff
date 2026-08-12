---
tags: [security, flash, advisories, api, entry, api5, kev, exploited, ai, langflow]
updated: 2026-08-12
sources:
  - "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json, accessed 2026-08-12"
  - "https://www.resecurity.com/blog/article/exploiting-langflows-validatecode-endpoint-for-remote-code-execution, accessed 2026-08-12"
  - "web search results naming the IBM bulletin at support/pages/node/7278927, accessed 2026-08-12"
---

# APIDS-0011: the validation endpoint that executes, and the login endpoint that hands out superuser

**KEV listed and exploited.** Two AI orchestration defects that chain, and the pair is the
clearest worked example this folder has of why endpoints named `validate` deserve suspicion.
Related: MTH-API-006, the validate and preview
endpoints, APIDS-0010,
the ledger.

```yaml
id: APIDS-0011
component:
  type: service
  ecosystem: Python, PyPI package langflow
  name: Langflow and IBM Langflow OSS, the code validation and auto login endpoints
  version_scope: default deployments. The chain is the default configuration, not an edge case
affected:
  introduced: CVE-2026-0770 reported from 0.0.31. CVE-2026-9198 from 1.0.0
  fixed_in: >
    CVE-2026-0770 fixed in 1.10.1 per the Resecurity analysis, via PR 13696 dated 2026-06-18.
    CVE-2026-9198 first fixed release also reported as 1.10.1, inferred by a secondary source
    from the NVD configuration rather than stated by IBM, so treat it as reported not confirmed
  tested_on: not tested. Read only sweep
identifiers:
  cve: CVE-2026-0770 and CVE-2026-9198
  ghsa: ___ for both. The Langflow advisory listing carries 117 advisories and neither of these two numbers appeared in the first page read
  osv: ___
  vendor_id: IBM support node 7278927, "Unauthenticated Remote Code Execution via Auto-Login Bypass and Code Validation"
class:
  owasp_api: API5 broken function level authorisation, primary, for the auto login half. API8 security misconfiguration, secondary. The execution itself is CWE-94 rather than an OWASP API class
  owasp_2025: ___
  cwe: CWE-94 code injection for CVE-2026-9198. CWE-829 inclusion of functionality from an untrusted control sphere for CVE-2026-0770
  family: validation that executes, plus an authentication endpoint that is not bound to loopback
protocol: rest
auth_required: none
entry_point: >
  POST /api/v1/validate/code, the code validation route. And GET or POST /api/v1/auto_login,
  the endpoint that mints a token. In the CVE-2026-9198 chain auto_login is called first to
  obtain a SUPERUSER token, then validate/code is called to execute. For CVE-2026-0770 the
  validation route was reachable with no authentication at all.
object_graph: >
  Thin here, and worth saying so plainly rather than padding it. There is no per object
  ownership question: the object is the running process. What the graph does capture is the
  trust boundary that was assumed and not enforced. auto_login exists to make single user
  local development frictionless, so its implicit owner is "somebody already on this host".
  It was never bound to loopback, so its actual reachable set is "anybody who can route to the
  port". The gap between the assumed owner and the real one is the entire vulnerability.
root_cause: >
  Two distinct missing decisions, which is why they chain so well.
  One: the validation routine called exec() on submitted function definitions. Python
  evaluates default argument expressions and decorators at definition time, so exec() on a
  definition runs the attacker's expression immediately, before anything calls the function.
  Validation became execution without anybody writing an eval call at a call site.
  Two: /api/v1/auto_login enforces no authentication and is not bound to the loopback
  interface, so it mints a SUPERUSER token for any caller that can reach the port.
signal: >
  An endpoint whose name promises that it does not do anything: validate, check, lint, verify,
  preview, dry run, test. Those are the ones that get shipped without an authorisation check,
  because the team reasoned that there was nothing to protect. See MTH-API-006.
safe_proof: >
  Lab only, on an isolated disposable virtual machine with no network route to anything else,
  and this one needs more care than most because the proof is code execution.
  Do not use a shell payload. The safe demonstration is a canary that proves evaluation and
  nothing else: submit a definition whose default argument writes a fixed marker string to a
  file inside the container, then check for the marker. That distinguishes "the expression was
  evaluated" from "the code was merely parsed" without spawning a shell, touching the network
  or changing anything outside the sandbox. Snapshot before, revert after.
  For the auto login half the safe proof is simply that the route answers from a second host
  on the lab network and returns a token, which requires no execution at all.
controls: >
  Negative control: submit a definition that is syntactically valid but whose default argument
  is inert, and confirm no marker appears. That separates execution from ordinary parsing.
  Second negative control: submit syntactically invalid code and confirm the endpoint still
  reports a syntax error on the patched build, because the patched build keeps compile only
  validation and a tester who sees an error may wrongly conclude the endpoint is dead.
  Differential control for auto login: call it from the host itself and from a second machine.
  If both succeed, the loopback binding is genuinely absent rather than the tester having sat
  on the host the whole time. That last one is the easiest mistake to make.
fix:
  commit_url: >
    PR 13696, dated 2026-06-18, named by the Resecurity analysis for CVE-2026-0770. The commit
    itself was not opened by this sweep, so the invariant below is from the analysis, not from
    a diff read directly. Flagged as carried debt.
  invariant: >
    For CVE-2026-0770: validation compiles and does not execute. compile() only, so syntax is
    still checked while no attacker controlled expression is ever evaluated.
    For CVE-2026-9198: ___ . The auth side fix is not documented in anything this sweep read.
hardening: >
  Two controls, one per half. Never evaluate submitted code as part of validating it: parse or
  compile, never exec. And bind development conveniences to loopback and make them refuse to
  start when a production flag is set, rather than relying on operators to disable them.
detection: >
  Requests to /api/v1/auto_login from a source address that is not the loopback interface. That
  is a clean, low noise signal and it needs no payload inspection, which makes it the one to
  give an operations team. Public proof of concept code and a Metasploit module are both
  reported to exist, so scanning traffic for these paths should be assumed.
variant_rule: >
  Any AI orchestration or workflow tool that accepts user authored code, expressions or
  templates: node based automation platforms, notebook servers, template engines with a
  preview route, and rules engines. Also every "developer mode" or "auto login" convenience in
  any product. The transferable shape is any route that validates, previews, or renders
  something the caller supplied; product deployment must be established independently.
lab:
  install: Disposable isolated VM, Langflow pinned in the affected range, no outbound network
  snapshot: Snapshot before first request. This is remote code execution, so treat the VM as burned afterwards
  teardown: Revert the snapshot and destroy the VM. Never run this on the host or on a machine holding the .env keys
provenance:
  source: CISA KEV feed, Resecurity technical analysis, and search results naming the IBM bulletin
  accessed: 2026-08-12
  license_note: Mechanism summarised. No exploit code reproduced, and none was executed
```

## What happens

Langflow lets you build AI workflows out of nodes, and some nodes hold Python. Before saving,
the front end asks the server whether the code is valid. That check lives at
`POST /api/v1/validate/code`.

The check ran the code.

Separately, `/api/v1/auto_login` exists so a developer running Langflow locally is not asked to
log in. It hands out a SUPERUSER token. It was never restricted to the local machine, so it
hands one to anybody who can reach the port.

Chain the two and an unauthenticated stranger gets a superuser token and then runs code as
root. CISA added CVE-2026-9198 to the KEV catalogue on 2026-08-04 with a due date of
2026-08-07, three days later, which is about as loud as that catalogue gets. CVE-2026-0770 was
added on 2026-07-21, due 2026-07-24.

## Why it works

The Python detail is the interesting part and it is worth understanding rather than
memorising, because it generalises.

When Python executes a function **definition**, it evaluates the default values of the
arguments right then, at definition time, not when the function is later called. Same for
decorators. So a definition that never gets called can still run an expression, purely by
being defined.

That means `exec()` on a function definition is not the harmless thing it looks like. The
developer's mental model was "I am checking whether this parses". The language's actual
behaviour was "I am running part of it". Validation and execution were the same operation and
nobody noticed, because the code path contains no call to the function at all.

## How you would reproduce it

Isolated disposable VM, no route to anything else, snapshot first. Prove evaluation with a
marker written to a file rather than a shell command, then check the marker. Run the inert
control to show the marker only appears when the expression is evaluated. For the auto login
half, call the route from a second machine on the lab network: if it returns a token, the
loopback binding is missing, and that half needs no code execution to demonstrate at all.

Treat the VM as burned when finished. This is remote code execution, not an information leak.

## What the fix is, and why the obvious fix would not work

For the validation half the patch drops `exec()` and keeps `compile()`. Syntax is still
checked, nothing is evaluated. The invariant is small and exactly right: validating code means
compiling it, never running it.

The obvious fix is a sandbox or a blocklist of dangerous names, and it is the wrong instinct.
Python sandboxes inside the same interpreter have a long history of being escaped, and a
blocklist has to anticipate every route to the same capability, of which there are many. The
patch is better than a sandbox because it removes the execution rather than trying to contain
it. When somebody proposes a sandbox for this class in review, that is the argument to make.

The auth half's fix is `___`. Nothing this sweep read documents what IBM changed, and it is
not inferred here.

**Deployment relevance must be established per target.** This is filed because it is the first
KEV-listed AI tooling in this folder and because the validate-endpoint shape transfers beyond
the named product.
