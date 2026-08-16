---
tags: [security, flash, advisories, api, entry, api8, cors, netty, framework]
updated: 2026-08-16
sources:
  - "https://github.com/advisories/GHSA-6cqp-g7gg-8hr5, accessed 2026-08-16"
---

# APIDS-0029, send `Origin: null` and the CORS gate lets you through to the backend

Related: APIDS-0026 (the other CORS entry of this
run), MTH-API-011,
MTH-API-006.

The value of this one is the precision. The advisory names the class, the method, and the exact
boolean that inverts. It is the cleanest statable invariant in the run.

```yaml
id: APIDS-0029
component:
  type: framework
  ecosystem: Maven
  name: "io.netty:netty-codec-http"
  version_scope: "io.netty.handler.codec.http.cors.CorsHandler"
affected:
  introduced: "the 4.1 line, and >= 4.2.0.Final on the 4.2 line"
  fixed_in: "4.1.136.Final and 4.2.16.Final"
  tested_on: ___
identifiers:
  cve: CVE-2026-56746
  ghsa: GHSA-6cqp-g7gg-8hr5
  osv: ___
  vendor_id: ___
class:
  owasp_api: API8 security misconfiguration
  owasp_2025: ___
  cwe: ___ (the advisory names none; the shape is CWE-346 origin validation error)
  family: origin comparison, the sentinel value that matches everything
protocol: rest
auth_required: none
entry_point: "any request to a Netty HTTP server using CorsHandler with short circuit enabled, carrying the header Origin: null"
object_graph:
  creates: "nothing. This is a gate, not an object"
  owns: "not applicable"
  should_reach: "only origins in the configured allowlist should reach the backend handlers"
  tested_account_got: "an unlisted origin reached the backend handlers by claiming to be null"
root_cause: >
  `CorsHandler#channelRead` runs a short circuit: if the origin is present and no configuration
  matches it, reject before the request reaches application logic. The check is written as
  `!(origin == null || config != null)`. The configuration lookup happens in `getForOrigin`, and
  that method special cases the literal string `null`: when `NULL_ORIGIN.equals(requestOrigin)` is
  true it returns a configuration object **whether or not null origins were actually authorised**.
  So `config` is non null, the short circuit condition is false, and the request proceeds. The
  missing decision lives in `getForOrigin`: it must return a configuration only when the null origin
  was allowed, not merely because the origin was null.
signal: >
  A sentinel value handled by a separate branch in a lookup that returns a config object. The bug is
  not "null is allowed", it is "null is recognised", and recognition was mistaken for permission. In
  any allowlist lookup, ask what the function returns for the special case and whether the caller can
  tell "allowed" apart from "known".
safe_proof: >
  Static: read `getForOrigin` and the short circuit condition and show that the null branch returns
  before the authorisation test. In a lab, send one request carrying `Origin: null` to a marker route
  that logs and returns a canary string, with the allowlist configured to a single unrelated origin.
  If the canary comes back, the gate did not fire. Read only, one route, no state changed.
controls:
  negative: "send Origin: https://not-allowed.example. The short circuit should reject it. If it also passes, the handler is not enabled at all and this is a different finding."
  differential: "configure the allowlist to explicitly permit the null origin, then to explicitly forbid it, and send the same request twice. Identical responses prove the configuration is not consulted."
  false_positive: "an application that does its own authorisation behind the CORS handler is not exploitable through this alone. The advisory scopes the impact precisely: it hits applications that rely on the short circuit to keep unauthorised cross origin requests away from backend logic."
fix:
  commit: "not read this run. The advisory links the release tags netty-4.1.136.Final and netty-4.2.16.Final rather than a commit"
  invariant: >
    Stated from the defect: `getForOrigin` must return a configuration for the null origin only when
    the null origin is authorised, so that the short circuit's `config != null` test means "allowed"
    and not "recognised".
hardening: >
  Never let a lookup return the same value for "permitted" and "understood". Make the allowlist
  answer a three state result, or have the caller ask a separate question. The class dies when the
  authorisation decision is a boolean the gate reads, not an object the gate infers from.
detection: >
  Requests carrying `Origin: null` at all are worth alerting on, because legitimate ones are rare:
  they come from sandboxed iframes, `file://` pages, and some redirect chains. A gateway or WAF can
  key on the literal header value cheaply.
variant_rule: >
  Everywhere `null` is a legal origin: browser sandboxed iframes and `data:` documents send it, so
  every framework's CORS layer has a null branch and each one is worth reading. The wider rule is
  the sentinel: `*`, `null`, the empty string, `0.0.0.0`, `localhost`, `::`, `.` and `..`. Each of
  those is a value some lookup treats specially, and the question is always whether the special case
  short circuits the authorisation test. **This run saw the same shape twice more outside CORS:
  Directus SSRF bypass via `0.0.0.0` (GHSA-j5h6-vqc3-phqh) and Traefik's `..` in
  APIDS-0033.**
lab:
  install: "a minimal Netty HTTP server on an affected version with CorsHandler and short circuit enabled, allowlist set to one origin"
  snapshot: "none needed"
  teardown: "delete the project"
provenance:
  source: "GitHub Security Advisory GHSA-6cqp-g7gg-8hr5"
  accessed: 2026-08-16
  license_note: "advisory text summarised, not reproduced"
```

## What happens

Netty has a CORS handler with a feature called short circuit. Turn it on and a cross origin request
from an origin you did not allow gets rejected right there, before your code ever sees it. People
use it as a wall.

Send the header `Origin: null` and you walk through the wall.

## Why it works

The gate asks one question: did the origin lookup find a configuration? If yes, carry on.

The lookup has a special branch for the literal string `null`, because browsers really do send that
in some situations, so the code has to have an opinion about it. That branch returns a
configuration object. It returns it before checking whether null origins were actually permitted.

So the lookup answers "I know what null is" and the gate hears "null is allowed". The two are not
the same sentence and the code cannot tell them apart.

## How to reproduce

Read the two pieces: the short circuit condition in `channelRead`, and the null branch in
`getForOrigin`. In a lab, one request with `Origin: null` against a canary route with an allowlist
that does not include null. The canary comes back.

## The fix, and why the obvious fix would not work

Make the null branch respect the configuration.

The obvious fix is to block `Origin: null` at the proxy. That is a reasonable stopgap and it is
worth doing, but it does not fix the class. The class is a lookup whose return value conflates
"recognised" with "permitted", and the same conflation will show up next in whatever other sentinel
that lookup handles. The durable fix is a gate that reads an explicit allow decision instead of
inferring one from a non null pointer.
</content>
