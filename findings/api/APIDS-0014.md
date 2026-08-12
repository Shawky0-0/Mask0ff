---
tags: [security, flash, advisories, api, entry, api5, kev, exploited, ai, gateway, litellm, mcp]
updated: 2026-08-12
sources:
  - "https://labs.cloudsecurityalliance.org/research/csa-research-note-litellm-cve-2026-42271-ai-gateway-exploita/, accessed 2026-08-12"
---

# APIDS-0014: the AI gateway test button that spawns a process, and the header bypass in front of it

**The second KEV listed AI item in this run**, and the one that lands closest to how the fleet
actually talks to model providers. Related:
APIDS-0011,
MTH-API-006,
the API folder.

```yaml
id: APIDS-0014
component:
  type: gateway
  ecosystem: Python, PyPI package litellm
  name: LiteLLM AI gateway, the MCP test endpoints
  version_scope: the mcp-rest test routes
affected:
  introduced: 1.74.2
  fixed_in: 1.83.7, released 2026-05-08. Starlette must be upgraded to 1.0.1 or later at the same time to close the chained unauthenticated path
  tested_on: not tested. Read only sweep
identifiers:
  cve: CVE-2026-42271. Chains with CVE-2026-48710 in Starlette
  ghsa: ___
  osv: ___
  vendor_id: ___
class:
  owasp_api: API5 broken function level authorisation, primary, since the route was not restricted to an administrative role. API8 security misconfiguration, secondary
  owasp_2025: ___
  cwe: ___ as published. The mechanism is command injection through unvalidated subprocess parameters
  family: an administrative test route that executes, reachable by a non administrative caller
protocol: rest
auth_required: >
  user, for CVE-2026-42271 on its own: an authenticated caller who is not a proxy administrator.
  none, when chained with CVE-2026-48710, the Starlette Host header bypass, which is how it
  reaches a CVSS of 10.0
entry_point: >
  POST /mcp-rest/test/connection and POST /mcp-rest/test/tools/list. The request body carries an
  MCP server configuration containing command, args and env fields, and those fields describe a
  subprocess to launch.
object_graph: >
  The object is an MCP server configuration, and the ownership question is the wrong question:
  the configuration is not data the gateway stores on behalf of a user, it is an instruction to
  the host. What the graph does capture is the role boundary. Who should reach this route: a
  proxy administrator configuring an integration. Who actually reached it: any authenticated
  caller, and with the Starlette bypass in front, any caller at all. The route was written as
  though the only person who could reach it was the person who deployed the gateway.
root_cause: >
  The endpoints pass the caller supplied command, args and env straight to subprocess
  invocation. The research note names three absent controls together: no allowlist of permitted
  commands, no restriction to an administrative role, and no sandbox isolating the spawned
  process from the host. The missing decision that belongs to this folder is the second one:
  a route that launches a process was not gated on the PROXY_ADMIN role.
signal: >
  A route whose name contains test, connection, health or probe and whose body accepts a
  connection descriptor. A descriptor that names a command rather than a URL is the strong
  signal: it means the feature's whole purpose is to run something, and the only question left
  is who is allowed to ask.
safe_proof: >
  Lab only, isolated disposable VM, and the safe proof is deliberately not code execution.
  Prove the authorisation gap and stop there. Authenticate as a non administrative user and
  send the test route a configuration whose command is inert and observable, for example a
  command that writes a fixed canary marker to a file inside the container. If the marker
  appears, a non administrative caller reached a process spawning route, which is the finding.
  Do not chain the Starlette bypass and do not attempt a shell. The role boundary is the claim
  worth proving and it needs the smallest possible payload.
controls: >
  Negative control: send the same request as a PROXY_ADMIN account on a patched build, 1.83.7 or
  later, and confirm it is accepted, then as a non administrative account and confirm it is
  refused. That pair proves the patch draws the line where you think it does.
  Differential control: this is the important one and it decides which CVE you are looking at.
  Test the role gap while authenticated normally, with no Host header manipulation at all. If it
  succeeds, that is CVE-2026-42271 alone. Only if it also succeeds unauthenticated is the
  Starlette bypass in play, and conflating the two produces a wrong severity in the report.
  Third control: confirm the Starlette version, since the unauthenticated path depends on it and
  a patched Starlette changes the answer entirely.
fix:
  commit_url: ___ . Not located this run
  invariant: >
    From the research note rather than a diff, and flagged as such: the MCP test endpoints are
    restricted to the PROXY_ADMIN role in 1.83.7. Starlette 1.0.1 closes the Host header bypass
    that let the authentication layer be skipped in front of it.
hardening: >
  Any route that can launch a process needs both an explicit administrative role check and an
  allowlist of what may be launched, and neither substitutes for the other. The role check alone
  still gives an administrator arbitrary execution, which may be acceptable, but should be a
  decision somebody made rather than a side effect.
detection: >
  Requests to the mcp-rest test paths from any principal that is not a proxy administrator.
  Process spawns from the gateway account with a parent that is the web process. On the chained
  path, requests whose Host header does not match any configured hostname, which is a cheap
  gateway level check worth having regardless of this CVE.
variant_rule: >
  Every "test this connection" button in every admin panel. They are consistently written as
  harmless because they are read only from the operator's point of view, and consistently
  privileged because testing a connection means making one. Look at webhook test senders, SMTP
  test buttons, database connection testers, and integration probes.
  On Ahmed's surface this is the closest entry so far to how the fleet consumes AI: the EduAi
  .env holds live Anthropic, Groq and ZAI keys, and anything that sits between an application
  and those providers is a gateway of this kind, whether or not it is LiteLLM.
lab:
  install: Disposable isolated VM, LiteLLM pinned in the affected range, no outbound network, no real provider keys
  snapshot: Snapshot before the first request
  teardown: Revert the snapshot. Never place a real Anthropic, Groq or ZAI key in a lab used for this
provenance:
  source: Cloud Security Alliance research note on CVE-2026-42271
  accessed: 2026-08-12
  license_note: Mechanism and versions summarised. No exploit code reproduced, and none was executed
```

## What happens

LiteLLM is a gateway that sits between an application and many model providers, so the
application speaks one API and the gateway handles the rest. It can also connect to MCP
servers, and MCP servers are frequently local programs rather than remote URLs. So the
configuration for one contains a `command`, its `args`, and its `env`.

There are two routes for testing such a configuration before saving it. They took the command
from the request and ran it. They did not check that the caller was an administrator.

CISA added it to the KEV catalogue on 2026-06-08, about five weeks after the patch.

## Why it works

The feature is doing exactly what it was designed to do. Testing an MCP connection means
starting the MCP server, and starting it means running the command. There is no injection
trick, no parser confusion, no encoding problem. The command field is a command field.

The only thing standing between that design and remote code execution is the question of who
may call the route, and that question was never asked.

Then the second half. Starlette, the framework underneath, had a Host header bypass,
CVE-2026-48710, which let the authentication layer be skipped. Put the two together and the
authenticated route with no role check becomes an unauthenticated route with no role check.
That is the difference between the 8.7 and the 10.0.

Two ordinary defects, neither catastrophic alone, composing into a critical one. That is worth
noting because it is how most severe API compromises actually happen, and it is why "requires
authentication" is a weaker mitigation than it sounds when the authentication layer is itself a
dependency.

## How you would reproduce it

Isolated lab, and prove the smaller claim. Authenticate as an ordinary user, send an inert
marker writing command, and check for the marker. If a non administrative account reached a
process spawning route, the finding is established.

Do not chain the Starlette bypass to make the demonstration more impressive. The role gap is
the finding; the chain is a severity multiplier that changes which CVE you are describing, and
running the differential control is what stops the report being wrong.

## What the fix is, and why the obvious fix would not work

1.83.7 restricts the MCP test endpoints to `PROXY_ADMIN`. Starlette 1.0.1 closes the Host
header bypass. Both are needed: patching one leaves the other half of the chain standing.

The obvious fix is to sanitise the command string, and it does not apply here. There is nothing
to sanitise. The field is meant to be a command, and a gateway that strips dangerous characters
out of it has broken the feature without fixing anything. This is a case where input validation
is the wrong tool entirely and the answer is an authorisation decision plus an allowlist of
what may be launched.

The other tempting shortcut is to rely on the route being obscure. Public scanning traffic for
KEV listed paths should be assumed, so an undocumented path is not a control.

**Gate G5.** Whether anything on the fleet runs LiteLLM is Ahmed's call and the repo does not
record it. Filed because the fleet consumes three AI provider APIs with live keys, and because
this is the shape that anything sitting in front of those keys will have.
