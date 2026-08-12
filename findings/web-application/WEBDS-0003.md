---
tags: [security, flash, advisories, entry, web, cache, ssr, nuxt]
updated: 2026-08-12
sources:
  - "https://github.com/nuxt/nuxt/security/advisories/GHSA-wm8w-6qjm-cv43 accessed 2026-08-12"
---

# WEBDS-0003: Nuxt caches the server rendered payload under a path only key, so one user's data is served to the next

Related: the same shape in Hono,
the other Nuxt routing bug.

```yaml
id: WEBDS-0003
component: { type: framework, ecosystem: npm, name: nuxt, version_scope: "the 4.x line" }
affected: { introduced: "4.4.0, when runtime payload extraction landed for cached routes in PR 34410", fixed_in: "4.5.1", tested_on: "not tested, desk research only" }
identifiers: { cve: CVE-2026-71316, ghsa: GHSA-wm8w-6qjm-cv43, osv: ___, snyk: ___, vendor_id: "regression from PR 34410" }
class: { owasp_2025: "broken access control, by way of a caching defect", owasp_api: ___, owasp_llm: not_applicable, cwe: "___, the advisory does not state one", family: "shared cache keyed on too little, cross user disclosure", corpus_directory: 07-protocol-cache-routing }
auth_required: none
entry_point: "GET /<page>/_payload.json for any page carrying a routeRules cache, swr or isr directive"
root_cause: >
  The cache key was the path and nothing else. The renderer stored the server side rendered
  payload in the shared cache under a path only key, with no part of the key derived from the
  session cookie, the user, or the tenant. The missing decision lives in the cache key
  construction inside the renderer, not in the auth code: route middleware and page guards do
  run, but the cached payload is served before they execute, so they never get the chance.
  The 4.x line also removed the import.meta.prerender gate that had confined this to build
  time in 3.x.
signal: >
  A page that is both authenticated and cached. Then check whether a second, machine readable
  representation of the same page exists on a different URL. Here the HTML stays protected and
  only the extracted JSON leaks, which is exactly the sort of asymmetry that survives testing:
  a tester who checks the page and not the payload sees nothing wrong.
safe_proof: >
  In a lab, log in as user A and load a cached protected page so the cache warms with A's data.
  Then, from a clean client with no cookies, request the same path with /_payload.json
  appended. If A's data comes back, that is the finding. Use a canary value in A's profile, for
  example a nonsense display name, so the proof is one unmistakable string rather than a dump
  of real data.
controls:
  - "Negative control: request the payload before the cache is warmed. It must not return A's data, which proves the cache and not the endpoint is the leak."
  - "Differential control: repeat on a page without a cache, swr or isr rule. It must not leak, which proves the cache directive is the variable."
  - "False positive to rule out: your own browser or an intermediate proxy caching the response locally. Prove it from a different client on a different connection."
fix: { commit_url: ___, invariant: "a cached artefact that can contain per user state must have that state in its key, or must not be cached at all. The patch stops storing the authenticated payload in the shared path keyed cache" }
hardening: >
  Two controls, and the second is the one that survives a framework upgrade. First, never
  apply cache directives to routes that render per user data. Second, at the edge, require
  authentication for /**/_payload.json and any other secondary representation of a protected
  page, so a framework regression cannot expose it silently.
detection: >
  Cache hit ratios on _payload.json endpoints, and any 200 on such a path from a client with
  which is why it is worth an explicit rule rather than a general anomaly search.
variant_rule: >
  Look for every alternate representation of a protected page: .json, .rss, .amp, print views,
  ?format= parameters, and the framework specific ones such as Next.js _next/data. Then ask
  the cache key question of each: does the key contain everything the response varies on. The
  same question catches Vary header mistakes, CDN caching of Set-Cookie responses, and
  cache deception through a fake static extension.
lab: { install: "nuxi init on 4.4.x, add an auth protected page, give it routeRules with swr enabled", snapshot: "project directory plus lockfile", teardown: "delete the directory" }
provenance: { source: "https://github.com/nuxt/nuxt/security/advisories/GHSA-wm8w-6qjm-cv43", accessed: 2026-08-12, license_note: "vendor security advisory, public" }
```

## What happens

Nuxt renders a page on the server and also ships the data that page used as a separate JSON
file, so the browser does not refetch it. For pages you tell Nuxt to cache, it puts that JSON
in a shared cache. The key it used was the path. Two different users asking for the same path
therefore share one cache slot. The first authenticated user to load the page fills the slot
with their own data, and everybody afterwards gets it, including someone with no session at
all. The advisory lists profile data, tenant details, billing information and the response of
calls like `/api/me` as the sort of thing that ends up in there. Rated 7.5.

## Why it works

Caching is a correctness problem disguised as a performance feature. The rule is that the key
must contain everything the response varies on. This response varied on who was asking. The
key did not contain who was asking. Everything after that is arithmetic.

The reason it survived review is that the HTML was still protected. The guards work. They just
run after the cache is consulted, and only for the HTML route, so a manual test of the page
looks completely clean.

## How you would reproduce it

Lab only. Log in as a user whose profile carries an obvious canary string. Load the cached
protected page. Open a fresh client with no cookies and request the same path with
`/_payload.json` on the end. The canary comes back.

## What the fix is, and why the obvious fix is not enough

The obvious fix is to turn off `experimental.payloadExtraction`, and the advisory does list it
as a workaround. It is a workaround and not a fix, because it removes the symptom while
leaving the rule broken: the next feature that caches something per user will do the same
thing. The invariant to hold onto is that a cache key must include every input the response
depends on, and a session is an input.
