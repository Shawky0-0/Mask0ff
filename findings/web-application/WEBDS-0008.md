---
tags: [security, flash, advisories, entry, web, cache, ssr, hono]
updated: 2026-08-12
sources:
  - "https://github.com/honojs/hono/security/advisories/GHSA-f23p-vx2j-j53r accessed 2026-08-12"
---

# WEBDS-0008: Hono memo() caches on props alone, so context read during render is invisible to the cache key

Related: the same shape in Nuxt,
the web advisories folder.

```yaml
id: WEBDS-0008
component: { type: framework, ecosystem: npm, name: hono, version_scope: "the hono/jsx server renderer" }
affected: { introduced: "3.8.0", fixed_in: "4.12.34", tested_on: "not tested, desk research only" }
identifiers: { cve: CVE-2026-71850, ghsa: GHSA-f23p-vx2j-j53r, osv: ___, snyk: ___, vendor_id: ___ }
class: { owasp_2025: "broken access control, by way of a caching defect", owasp_api: ___, owasp_llm: not_applicable, cwe: "___, the advisory does not state one", family: "memoisation key omits an implicit input, cross user disclosure", corpus_directory: 07-protocol-cache-routing }
auth_required: none
entry_point: "any server rendered route whose component tree contains a memo() wrapped component that reads request state from context rather than from props"
root_cause: >
  memo() decides whether it can reuse a previous render by comparing props. Values read
  implicitly during rendering do not participate in that comparison: JSX context through
  createContext and useContext, useRequestContext from hono/jsx-renderer, and getContext from
  hono/context-storage. The missing decision is that memoisation must key on every input the
  render depends on, and an ambient read is an input. It lives in memo() itself, but the
  practical trigger is application code that reads the current user from context inside a
signal: >
  Memoisation plus ambient state. Any cache whose key is derived from the explicit arguments
  while the function also reads something the arguments do not mention. The observable signal
  on a running system is a page that occasionally shows the wrong user's name, and
  "occasionally" is the tell: it needs a warm instance and a particular request order, so it
  looks like a flaky bug rather than a security one.
safe_proof: >
  In a lab, give two users unmistakable canary values, for example display names of
  CANARY-ALPHA and CANARY-BRAVO. Render the memoised page as A, then as B against the same warm
  process, with props that compare equal. Look for A's canary in B's response. Read only, and
  the canary makes the proof one string rather than a pile of real user data.
controls:
  - "Negative control: repeat against 4.12.34. The canary must not cross."
  - "Differential control: pass the user value through props instead of context. It must not leak, which proves the ambient read is the variable rather than memo() as such."
  - "False positive to rule out: your own client caching, or a CDN in the path. Prove it against the origin from two separate clients. Also confirm the process is genuinely warm and shared, because a fresh worker per request hides the bug entirely."
fix: { commit_url: ___, invariant: "a memoised render must be invalidated by, or keyed on, the ambient request state it consumed. The fix is in 4.12.34" }
hardening: >
  The rule that kills the class: request scoped values must be passed explicitly, never read
  from ambient storage inside anything cacheable. If a component needs to know who the user is,
  it takes the user as a prop. That is also the version that is easy to review, because the
  dependency is visible in the signature.
detection: >
  Very hard from logs, which is the point worth recording. There is no anomalous request. The
  response is a valid 200 containing the wrong person's data, and the only reliable detector is
  a test that renders as two users against one warm process and diffs the output. Build that
  test rather than hoping to catch it in production.
variant_rule: >
  Hunt every cache whose key is narrower than its inputs. React and Vue memoisation reading
  context, PHP static properties or singletons holding request state in a long lived worker
  such as Laravel Octane or Swoole, Python module level globals under a threaded server,
  connection pooled objects retaining the last user, and template fragment caches keyed on an
  ID but rendering permission dependent content. This is the same defect as WEBDS-0003 at a
  different layer, which is why both are worth having.
lab: { install: "a minimal Hono app on an affected version using hono/jsx server rendering, one memo() wrapped component reading the user from useRequestContext", snapshot: "project directory plus lockfile", teardown: "delete the directory" }
provenance: { source: "https://github.com/honojs/hono/security/advisories/GHSA-f23p-vx2j-j53r", accessed: 2026-08-12, license_note: "vendor security advisory, public" }
```

## What happens

`memo()` is a performance wrapper: it remembers what a component rendered last time and skips
the work if the props have not changed. The comparison only looks at props. If the component
also reached out and read the current user from context while rendering, that read is not in
the comparison, so a component rendered for user A can be handed back unchanged to user B whose
props happen to match. The advisory lists profile data, request scoped secrets such as CSRF
tokens, and role restricted content as what can cross. Rated 4.8.

## Why it works

Memoisation is a bet that the output is a pure function of the inputs you named. Context reads
are inputs you did not name. Both halves are idiomatic on their own: context exists precisely
so you do not have to thread the user through every component, and memoisation exists precisely
so you do not re render unchanged subtrees. Using both together silently breaks the assumption
each one relies on.

It is also nearly invisible in testing. It needs a warm process, several requests, and props
that compare equal in the right order. On a developer machine with one user and a restart on
every save, it never fires.

## How you would reproduce it

Lab only. Two users with canary display names, one warm server process, render the memoised
page as each in turn with equal props, and look for the first canary in the second response.

## What the fix is, and why the obvious fix is not enough

The obvious fix is to stop using `memo()`, which is a real option and costs performance for a
reason nobody will remember in six months. The better rule is the one that generalises: pass
request scoped values as props. Then the memo comparison sees them, the dependency is visible in
the component signature, and the next person to add caching cannot reintroduce it by accident.
