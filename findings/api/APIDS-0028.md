---
tags: [security, flash, advisories, api, entry, api8, mcp, ai-endpoint, dns-rebinding, praisonai]
updated: 2026-08-16
sources:
  - "https://github.com/advisories/GHSA-x227-pf99-vffg, accessed 2026-08-16"
---

# APIDS-0028, the security module was written, shipped, and never called

Related: APIDS-0027 (the sibling defect in the same
product), MTH-API-008,
MTH-API-012.

**The third independent sighting of the MTH-API-008 shape: the guard exists and nothing calls it.**
Here it is not one helper with two call sites, it is a whole module with none.

```yaml
id: APIDS-0028
component:
  type: library
  ecosystem: pip
  name: praisonaiagents
  version_scope: "the MCP SSE server, run_sse() and launch_tools_mcp_server()"
affected:
  introduced: ___
  fixed_in: "1.6.59"
  tested_on: ___
identifiers:
  cve: CVE-2026-57123
  ghsa: GHSA-x227-pf99-vffg
  osv: ___
  vendor_id: ___
class:
  owasp_api: API8 security misconfiguration (primary), API5 broken function level authorisation (secondary)
  owasp_2025: ___
  cwe: ___ (the advisory names none; the shape is CWE-306 plus CWE-350 reliance on a name that can be rebound)
  family: dead security code, bind address defaults, DNS rebinding
protocol: other (MCP over Server Sent Events, JSON-RPC over HTTP)
auth_required: none
entry_point: "GET /sse and POST /messages/?session_id=, on the MCP SSE server, bound to 0.0.0.0 by default"
object_graph:
  creates: "the operator's process, by calling launch_tools_mcp_server(transport='sse')"
  owns: "the operator, who usually means this to be a local developer tool"
  should_reach: "the local MCP client only"
  tested_account_got: "any host on the LAN, and any web page in the operator's browser via DNS rebinding, reached the tool execution endpoint with no credential"
root_cause: >
  Two separate misconfigurations in one place. The bind address defaults to `0.0.0.0` in both
  `run_sse()` (line 245) and `launch_tools_mcp_server()` (line 301) with no explicit opt in. And the
  Starlette application is constructed with only `debug` and `routes`, so there is no middleware and
  no per route gate. The advisory then names the part that makes it an entry rather than a note:
  `mcp_security.py` already contains `validate_auth_header()`, `is_valid_origin()` and
  `is_potential_dns_rebinding()`, **and all three are dead code.** The missing decision is not a
  missing function. It is a missing call.
signal: >
  A file named for security that nothing imports. Grep for the module, then grep for its callers,
  and count. Zero callers on a module with three well named functions is a stronger signal than any
  scanner output, because it means somebody understood the threat, wrote the answer, and did not
  wire it in. The second signal is a default bind address of `0.0.0.0` on anything described as a
  developer tool.
safe_proof: >
  Static and complete: read `mcp_security.py`, then search the repository for each function name and
  show that the only occurrence is the definition. That proves the control is absent without sending
  a single packet. For the bind address, read the two default arguments. **Do not run the proof of
  concept curl commands printed in the advisory. They are read, not executed.**
controls:
  negative: "check whether any other transport in the same product does call the security module. If stdio or another path is gated, the finding is scoped to SSE rather than to the product."
  differential: "compare the Starlette construction here with one in the same codebase that does attach middleware. The difference is the finding."
  false_positive: "an operator may run this behind a firewall or in a container with no published port, which hides the defect. Report the code default separately from the deployment, and do not merge them."
fix:
  commit: ___
  invariant: >
    Stated from the defect, not read from the patch: the SSE transport must call the authentication,
    origin and rebinding checks that already exist before dispatching a JSON-RPC method, and must
    bind loopback unless an interface is named explicitly.
hardening: >
  Two controls, and they kill different halves. Bind loopback by default, which removes the LAN
  attacker entirely. Validate the `Origin` header and reject a `Host` that resolves to a private
  address it was not configured with, which removes the browser attacker. Neither one alone is
  enough, because DNS rebinding reaches loopback and a LAN attacker sends no Origin at all.
detection: >
  A JSON-RPC `initialize` or `tools/call` from a source address that is not the local MCP client. In
  the browser case, requests carrying an `Origin` of an unrelated site against a loopback `Host`.
variant_rule: >
  Every MCP server with an HTTP or SSE transport, and this run alone saw three more: the MCP Ruby
  SDK (GHSA-rjr6-rcgv-9m7m, the same missing Host and Origin protection), Token Optimizer MCP, and
  the ContextForge gateway. Also every local agent dashboard, every framework debug server, and
  anything reachable at `127.0.0.1` that a browser can also reach. **On Ahmed's fleet: any MCP
  server or local AI tooling on a developer machine is on the same LAN as everything else in the
  office.**
lab:
  install: "pip install praisonaiagents<1.6.59 in a disposable venv"
  snapshot: "none needed; the static proof needs no running process at all"
  teardown: "delete the venv"
provenance:
  source: "GitHub Security Advisory GHSA-x227-pf99-vffg"
  accessed: 2026-08-16
  license_note: "advisory text and proof of concept summarised, not reproduced and not executed"
```

## What happens

The MCP server runs tools. Tools read files, run code, call other services. The server listens on
every network interface. It asks for no credential and it does not check where the request came
from.

So two different attackers get in. Anyone on the same network can call it directly. And any web
page the operator visits can call it too, by pointing a hostname at `127.0.0.1` after the browser
has already decided that hostname is safe. That second trick is called DNS rebinding.

## Why it works

The developer knew about all of this. The proof is in the repository. There is a file called
`mcp_security.py` and it has a function for checking the Authorization header, a function for
checking the Origin, and a function for spotting a rebinding attempt.

Nothing calls any of them.

The Starlette app is built with two arguments, `debug` and `routes`, and that is the whole story.
The middleware slot where those three functions belong is empty.

## How to reproduce

Open the repository. Read `mcp_security.py`. Then search the whole tree for
`validate_auth_header`, `is_valid_origin` and `is_potential_dns_rebinding`. Each one appears once,
where it is defined. That is the finding, and it took no traffic.

## The fix, and why the obvious fix would not work

Call the functions.

The obvious fix is to add authentication. But authentication alone does not stop the browser
attack: a rebound page runs in the operator's browser and could ride along with whatever the
operator's own client sends, and in any case the tool execution endpoint here has no session to
ride. The Origin check is the control that stops the browser, and the bind address is the control
that stops the LAN. Three controls, three different attackers, and the codebase already had all
three written down.
</content>
