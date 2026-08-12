---
tags: [security, flash, advisories, entry, apids, api, websocket, api5, api9]
updated: 2026-08-12
sources:
  - "https://github.com/advisories/GHSA-279x-mwfv-vcqv accessed 2026-08-12"
---

# APIDS-0007: Nuxt DevTools exposes an unauthenticated RPC channel over the Vite HMR WebSocket

**The first WebSocket entry in this folder, and a clean case of authorisation never happening
after the protocol upgrade.** Related: the API folder,
the ledger,
APIDS-0006.

```yaml
id: APIDS-0007
component:
  type: library
  ecosystem: npm
  name: "@nuxt/devtools"
  version_scope: "the DevTools RPC channel, development servers only"
affected:
  introduced: ___
  fixed_in: "3.3.1"
  tested_on: "___ , not reproduced. Reading only."
  affected_ranges: "< 3.3.1"
identifiers:
  cve: CVE-2026-71319
  ghsa: GHSA-279x-mwfv-vcqv
  osv: ___
  vendor_id: ___
class:
  owasp_api: >
    API5:2023 broken function level authorisation is primary. API9:2023 improper inventory
    management applies too, because the root problem is a development surface reachable from
    somewhere it was never meant to be. API8:2023 covers the bind address side of it.
  owasp_2025: "A01 broken access control, with A05 security misconfiguration alongside"
  cwe: "CWE-306 missing authentication for critical function, and CWE-94 improper control of code generation"
  family: privileged control channel with no authentication after protocol upgrade
protocol: websocket
auth_required: none
entry_point:
  route: "the Vite HMR WebSocket endpoint, carrying the DevTools RPC channel"
  method: "WebSocket upgrade, then RPC method calls"
  parameter: "the RPC methods updateOptions(), clearOptions() and openInEditor()"
  header: "no token, no handshake, no origin check"
object_graph:
  which_request_creates_the_object: >
    The developer's own dev server creates the RPC channel at startup. It is not user data, it
    is a control plane.
  who_owns_it: "the developer running the dev server, locally"
  who_should_reach_it: >
    Only that developer, from that machine. There is no model in which a remote page should
    reach it.
  what_the_tested_account_got: >
    Any client able to reach the HMR endpoint could call RPC methods with no credential at all.
    That includes other hosts on the LAN when the dev server binds to a non loopback address,
    and cross origin WebSocket connections initiated by a malicious website the developer
    merely visits.
root_cause:
  where: "the DevTools RPC channel, riding on Vite's HMR WebSocket"
  the_missing_decision: >
    Quoting the advisory: "the channel has no authentication: any client that can reach the
    Vite HMR endpoint can call RPC methods, with no token, handshake, or origin check before
    the channel is established." Three methods lack enforcement: updateOptions(), clearOptions()
    and openInEditor(). The missing decision is authorisation at the upgrade, and separately an
    origin check, which is the control that would have stopped the cross origin path even
    without a token.
  the_chain: >
    updateOptions('behavior', { openInEditor: '<command>' }) writes an attacker chosen command
    into configuration, then openInEditor() causes the launch-editor package to execute it.
    Configuration write plus configuration execute, neither of them individually looking like
    an execution primitive.
signal: >
  The signal is a WebSocket that carries privileged operations and was authorised, if at all,
  only by the HTTP request that preceded the upgrade. Ask of any socket: what was checked at
  upgrade time, and is anything checked per message afterwards. A second signal, specific to
  developer tooling: any local service that both writes configuration and acts on
  configuration, since that pair is an execution primitive assembled from two innocent halves.
safe_proof: >
  Read only in this sweep. In a disposable lab the safe demonstration stops well short of the
  chain: connect to the HMR WebSocket from a different origin and confirm the channel is
  established and accepts a read only or harmless RPC call. Establishing the channel without a
  credential is the finding. Never write the openInEditor behaviour value and never call
  openInEditor(), because that is command execution and there is nothing to learn from running
  it.
controls:
  negative: >
    Attempt the same connection with an Origin header the server should refuse. If it is
    refused, an origin check exists and this is not reachable cross origin.
  differential: >
    Repeat against 3.3.1.
  false_positive: >
    The main one is scope inflation rather than a wrong observation. This is a development
    surface, and the advisory is explicit that production builds do not run DevTools. Reporting
    it as a production issue would be wrong. Confirm the dev server's bind address before
    claiming LAN reachability, because bound to loopback the LAN path does not exist and only
    the cross origin path remains.
fix:
  commit_url: "___ , not reached this run"
  invariant: "___ , the advisory states the affected methods and the missing controls but not what 3.3.1 implements"
hardening: >
  Three controls, in order of how much they kill. Authenticate the channel at upgrade with a
  token the dev server prints locally, which is the general fix. Check Origin, which
  specifically kills the drive by path where a visited website opens a socket to the
  developer's own machine. Bind development servers to loopback by default, which removes the
  LAN path. The deeper lesson is that a WebSocket upgrade is an authorisation boundary and is
  routinely treated as if the preceding HTTP request settled the question.
detection: >
  WebSocket connections to the HMR port carrying an Origin that is not the dev server itself.
  On a developer machine this is not usually instrumented at all, which is part of why the
  class persists.
variant_rule: >
  Every developer tool that opens a local port: framework devtools, debug bridges, language
  server protocols, notebook kernels, hot reload channels, local model runners and MCP servers
  listening on a port. The recurring shape is "it is only local, so it needs no auth", which
  stops being true the moment a browser can be told to connect to localhost. Also check any
  production WebSocket for the same upgrade time question.
lab:
  snapshot: "not required if the chain is not run, and it should not be"
  teardown: "delete the project"
provenance:
  source: "GitHub Security Advisory"
  accessed: 2026-08-12
  license_note: "summarised from public advisory, one sentence quoted and attributed"
```

## What happens

Nuxt DevTools talks to the browser over the same WebSocket that Vite uses for hot module
reload. That channel exposes RPC methods, and nothing authenticates it. No token is issued, no
handshake happens, and the origin of the connecting client is never checked.

Two of those methods are enough on their own. `updateOptions()` writes into DevTools
configuration, and `openInEditor()` acts on that configuration by handing it to the
`launch-editor` package. Write a command into the `openInEditor` behaviour, then trigger it, and
the command runs.

## Why it works

The channel was assumed to be private because it is local. That assumption fails in two
different directions.

Sideways, if the dev server binds to a non loopback interface, everyone on the network can
reach it. That is the obvious one, and it is the one people guard against.

The other one is the interesting one. A developer visits a website. That page opens a WebSocket
to `localhost` on the HMR port. Browsers do not apply the same origin policy to WebSocket
connections the way people expect, so without an explicit `Origin` check on the server, the
connection succeeds. The victim did nothing but browse.

Neither method looks dangerous alone. One writes a setting, the other opens an editor. Code
execution is assembled from a configuration write plus a configuration read, which is why this
kind of pair keeps slipping through review: reviewers look for an execution sink and there
isn't one, there are two halves of one.

## How you would reproduce it

In a lab, on a disposable project. Connect to the HMR WebSocket from a different origin and see
whether the channel opens without a credential.

That is where to stop. Opening the channel unauthenticated is the entire finding. Writing the
behaviour value and calling `openInEditor()` is running a command on the machine, and it proves
nothing that the open channel has not already proved.

## What the fix is, and why the obvious fix would not work

Upgrade to 3.3.1. The advisory does not state what the patch implements, so the invariant is
recorded as unknown rather than guessed.

The obvious fix is to bind the dev server to loopback only. It is worth doing and it is not
sufficient, which is the point most people miss about this class. Loopback closes the LAN path
and leaves the cross origin path completely open, because the browser making the connection is
already on the machine. The control that closes that one is an `Origin` check at upgrade, and
after that, authentication on the channel.

The second obvious fix, "it is only a dev tool, so it does not matter", is what allowed it. A
developer machine holds source code, credentials and often production access. It is frequently
the softest target in an organisation and the best connected one.
