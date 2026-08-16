---
tags: [security, flash, advisories, api, entry, api5, gateway, traefik, path-confusion]
updated: 2026-08-16
sources:
  - "https://github.com/advisories/GHSA-8rxv-jg7p-wvg3, accessed 2026-08-16"
  - "https://github.com/traefik/traefik/commit/759515bec1b9f628b21ea8968ef63da853be5e29, accessed 2026-08-16"
---

# APIDS-0033, the gateway rewrote `/api../admin` into `/../admin` and the backend read it as `/admin`

Related: MTH-API-003 (the other entry where a proxy
and a backend disagreed), APIDS-0029 (the sentinel
value shape), APIDS-0002.

**The folder's first API gateway entry.** Everything else here is application code. This one is the
box in front of the application, which is where Ahmed's fleet actually sits.

```yaml
id: APIDS-0033
component:
  type: gateway
  ecosystem: Go
  name: "github.com/traefik/traefik/v3"
  version_scope: "the Kubernetes ingress-nginx provider, RewriteTarget middleware"
affected:
  introduced: "3.7.0"
  fixed_in: "3.7.8"
  tested_on: ___
identifiers:
  cve: CVE-2026-67309
  ghsa: GHSA-8rxv-jg7p-wvg3
  osv: ___
  vendor_id: "commit 759515bec1b9f628b21ea8968ef63da853be5e29"
class:
  owasp_api: API5 broken function level authorisation
  owasp_2025: ___
  cwe: CWE-22 path traversal, CWE-288 authentication bypass using an alternate path or channel
  family: path confusion between two parsers, the proxy and the backend
protocol: rest
auth_required: none
entry_point: "any path matching a rewrite-target ingress whose regex captures a segment adjacent to the matched prefix. The advisory's example is GET /api../admin"
object_graph:
  creates: "not applicable, this is a routing decision"
  owns: "not applicable"
  should_reach: "only requests that pass the /admin router's BasicAuth, DigestAuth or ForwardAuth middleware should reach the admin backend"
  tested_account_got: "an unauthenticated request reached the admin backend, because it was routed as /api and delivered as /admin"
root_cause: >
  Four steps, and each one is individually defensible. The entry point sanitiser leaves `/api../admin`
  alone because `api..` is a single segment and contains no dot segment of its own. The router then
  matches `PathRegexp("(?i)^/api(.*)")`. The RewriteTarget middleware captures `../admin` and builds
  `/../admin`. Nothing normalises or validates the result before forwarding. The backend normalises
  it, as backends do, and serves `/admin`. The missing decision lives in
  `pkg/middlewares/ingressnginx/rewritetarget/rewrite_target.go`: the middleware must not emit a path
  whose normalised form differs from what it wrote. The authorisation was never bypassed as such. The
  request simply never met it, because routing happened on one string and delivery happened on
  another.
signal: >
  Two components that both parse the path, and only one of them normalises. Wherever a routing
  decision and a delivery decision read the same field, ask whether they read it the same way. The
  specific tell is a rewrite rule whose regex capture can reach outside the prefix it matched:
  `^/api(.*)` with a target of `/$1` is the shape, and it is written that way in ingress annotations
  constantly.
safe_proof: >
  In a lab, stand up two routers on one backend: `/api` with a rewrite target, and `/admin` with an
  authentication middleware in front of a canary route that returns a marker string. Send one request
  to `/api../admin` with the path left unencoded. If the marker comes back with a 200 instead of a
  401, it is proved. One request, read only, marker route only, lab only.
controls:
  negative: "send /admin directly. It must return 401. If it does not, the middleware is not attached and this is a different, simpler finding."
  differential: "send /api/legitimate and confirm it routes normally. That proves the rewrite rule works as intended and the traversal is the variable."
  false_positive: "the chain only completes if the backend normalises dot segments before dispatch. Some do not, and then the request 404s instead. The advisory lists that as a prerequisite, so a negative result proves nothing about other backends behind the same gateway."
fix:
  commit: "https://github.com/traefik/traefik/commit/759515bec1b9f628b21ea8968ef63da853be5e29"
  invariant: >
    Read from the patch, not inferred. The middleware calls `req.URL.JoinPath()` to normalise the
    rewritten path and compares it to what it produced. If normalisation changes the path, the request
    is rejected with HTTP 400, before it is forwarded. **The patch rejects rather than normalises**,
    which is the stronger choice: normalising would still leave the router's decision and the delivery
    disagreeing, it would just disagree quietly. The same commit applies the check to the snippet
    action in `pkg/middlewares/ingressnginx/snippet/action.go`, which is the sibling call site.
hardening: >
  One parse, one decision. If the gateway normalises the path once, before routing, and every
  subsequent stage works on that single normalised value, the class cannot occur. Failing that,
  reject any path that is not already in its normal form, at the outermost edge. Do not attempt to
  enumerate bad sequences: `..`, `%2e%2e`, `.%2e`, `..;`, overlong UTF-8 and backslash variants are a
  list that never ends.
detection: >
  A dot segment anywhere in a request path after the gateway has rewritten it. In access logs, the
  gateway's recorded path and the backend's recorded path differing for the same request id is the
  general signature and it catches variants this CVE does not cover.
variant_rule: >
  Every place a path is rewritten between two parsers: nginx `rewrite` and `proxy_pass` with and
  without a trailing slash, Apache `mod_rewrite`, an API gateway stage variable, a CDN path rule, a
  load balancer listener rule, a service mesh route. The advisory names its own sibling,
  GHSA-cxjq-mrr5-89rv, which is the same fix applied to `ReplacePathRegex`. **On Ahmed's fleet: any
  WordPress or Laravel site behind a reverse proxy where the proxy makes the authorisation decision.
  The repo already notes Laravel `throttle` keying behind a proxy as an open question, and this is the
  same family: the gateway and the application do not agree about what the request is.**
lab:
  install: "traefik 3.7.x with the ingress-nginx provider in a local k3s or kind cluster, two ingresses on one canary backend"
  snapshot: "cluster is disposable"
  teardown: "delete the cluster"
provenance:
  source: "GitHub Security Advisory GHSA-8rxv-jg7p-wvg3, and the linked fix commit"
  accessed: 2026-08-16
  license_note: "advisory text and proof of concept summarised, not reproduced and not executed"
```

## What happens

The gateway has two rules. Anything under `/api` gets rewritten and passed through. Anything under
`/admin` needs a password first.

Send a request for `/api../admin`. The gateway decides it is an `/api` request, so no password. Then
it rewrites it and hands the backend `/../admin`. The backend tidies that up to `/admin` and serves
the admin page.

Nobody bypassed the password check. The request never went near it.

## Why it works

Four steps, and every one of them looks fine on its own.

The gateway's front door tidies up paths, but `api..` is one word with two dots on the end of it,
not a `..` segment, so there is nothing to tidy. The router matches `/api` and captures `../admin`.
The rewrite rule pastes the capture onto a slash and produces `/../admin`. And the backend, like
every web server, tidies that up before it serves it.

Routing happened on one string. Delivery happened on a different one. The authorisation was attached
to the second string and the decision was made on the first.

## How to reproduce

Two ingresses on one backend in a lab: one with a rewrite rule, one behind BasicAuth in front of a
marker route. One request to `/api../admin`, sent with the path left exactly as written. A 200 with
the marker instead of a 401 is the finding.

## The fix, and why the obvious fix would not work

The patch normalises the rewritten path and, if normalising changes it, refuses the request with a
400. Read from the commit, not guessed.

The obvious fix is to normalise the path and carry on. That is worse than it looks. Normalising
means the gateway now forwards `/admin` for a request it routed as `/api`, so the two decisions
still disagree, they just stop leaving evidence. Rejecting is right because the disagreement itself
is the bug, and a request that would mean two different things to two different parsers should not
be served at all.
</content>
