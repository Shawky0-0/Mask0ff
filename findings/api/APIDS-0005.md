---
tags: [security, flash, advisories, entry, apids, api, ssr, data-disclosure]
updated: 2026-08-12
sources:
  - "https://github.com/advisories/GHSA-f23p-vx2j-j53r accessed 2026-08-12"
  - "https://github.com/honojs/hono/commit/0c45036 accessed 2026-08-12"
---

# APIDS-0005: Hono memo() serves one user's rendered output to another

**The cross user disclosure shape, caused by a cache key that ignores half its inputs.**
Related: the API folder,
the ledger,
MTH-API-001, the object graph.

```yaml
id: APIDS-0005
component:
  type: framework
  ecosystem: npm
  name: hono, the hono/jsx renderer
  version_scope: "server side rendering with memo()"
affected:
  introduced: "3.8.0"
  fixed_in: "4.12.34"
  tested_on: "___ , not reproduced. Reading only."
  affected_ranges: ">= 3.8.0, < 4.12.34"
identifiers:
  cve: CVE-2026-71850
  ghsa: GHSA-f23p-vx2j-j53r
  osv: ___
  vendor_id: "hono release v4.12.34"
class:
  owasp_api: >
    API3:2023 broken object property level authorisation is the closest fit, since the defect
    is over exposure of data in a response. It is arguably API1:2023 as well, because what
    leaks is another user's object. Recorded as API3 primary.
  owasp_2025: "A01 broken access control"
  cwe: "CWE-488 exposure of data element to wrong session"
  family: cache key omits a request scoped input
protocol: rest
auth_required: none
entry_point:
  route: "any server rendered route using a component wrapped in memo()"
  method: GET
  parameter: "none. The trigger is two requests whose props match while their ambient context differs."
  header: n/a
object_graph:
  which_request_creates_the_object: >
    The victim's own request creates the rendered output, legitimately, as part of their
    authenticated page render.
  who_owns_it: "the user whose request produced it. The output is request scoped by nature."
  who_should_reach_it: "that user and nobody else, for that one response"
  what_the_tested_account_got: >
    A second user, whose component props happened to match, received the first user's cached
    render, including whatever was read from ambient context rather than passed as props.
root_cause:
  where: "memo() in src/jsx/base.ts"
  the_missing_decision: >
    memo() compared components by props alone and cached the result across requests. Values
    read implicitly during rendering did not participate in that comparison: JSX Context via
    createContext() and useContext(), useRequestContext() from hono/jsx-renderer, and
    getContext() from hono/context-storage. So the cache key covered the explicit inputs and
    ignored the ambient ones, while the cached value depended on both. The missing decision is
    that anything a render reads must be part of what identifies that render.
signal: >
  The general signal, and it is worth memorising: a cache whose key is narrower than the set of
  inputs its value depends on. In review, look for memoisation added around a component or
  function that also reads from ambient state (context, thread local, async local storage,
  globals, a request object pulled from a module). In testing, the signal is a response that
  is correct for the wrong person, and it usually appears intermittently under concurrency
  rather than reliably.
safe_proof: >
  Read only in this sweep. In a disposable lab: two sessions for two users, both hitting the
  same route, where the memoised component reads a per user value from context but takes
  matching props. Put a canary string in each user's context value. The proof is user B's
  response containing user A's canary. No writes, no third party.
controls:
  negative: >
    Make the props differ between the two users. If the leak persists when props differ, this
    is not the memo key defect and something else is caching.
  differential: >
    Repeat on 4.12.34 and confirm the canary no longer crosses.
  false_positive: >
    Two controls matter here. First, a shared CDN or reverse proxy cache produces exactly the
    same observable and is far more common; test with caching disabled at every layer above
    the application before blaming the framework. Second, an intermittent result is not a
    finding until it is reproduced deliberately, because concurrency bugs invite confirmation
    bias. Reproduce it on demand, or record it as unconfirmed.
fix:
  commit_url: "https://github.com/honojs/hono/commit/0c45036"
  invariant: >
    The fix does not repair the cache key, it removes the cache. In src/jsx/base.ts the
    computed and prevProps state and the propsAreEqual comparison were deleted, and the
    wrapper became a plain pass through that calls the component. Server side memo() no longer
    memoises at all; memoisation is delegated to the DOM renderer, where the state is per
    client rather than shared across requests. The tests were renamed to match, including one
    called "does not reuse the result of a previous render" and a new test asserting that
    context values do not carry over between renders.
hardening: >
  Two levels. Locally: never cache across requests inside a server process unless the cache key
  provably includes every input the value depends on, ambient ones included. Structurally, and
  this is what the maintainers chose: put the cache where the tenancy boundary already is. A
  per client cache cannot leak across users, so it does not need a perfect key.
detection: >
  Hard to see from logs, which is part of why this class survives. What shows up is user
  reports of seeing someone else's data, and CSRF token mismatches, because request scoped
  secrets rendered into HTML are among the things the advisory names as exposed.
variant_rule: >
  Every memoisation, deduplication or "compute once" wrapper in a server process. React
  ecosystem SSR caches, template fragment caches, resolver level dataloaders in GraphQL,
  ORM identity maps kept beyond a request, and any module scope variable assigned during a
  request. The question is always the same: what does this value depend on that the key does
  not mention.
lab:
  snapshot: "not required, read only proof"
  teardown: "delete the install"
provenance:
  source: "GitHub Security Advisory, and the fix commit read directly"
  accessed: 2026-08-12
  license_note: "summarised from public advisory and public commit"
```

## What happens

`memo()` is a performance wrapper. You put it around a component and it remembers the last
render, so if the same props come in again it returns the stored output instead of rendering
again.

The trouble is what "the same" means. `memo()` compared props, and only props. But a component
can read things it was never passed: values pulled from context, the current request, the
logged in user. Those did not take part in the comparison, and the cache lived longer than one
request.

So two users hit the same route. Their props match. The second one is handed the first one's
HTML, including whatever that HTML was built from.

## Why it works

A cache is a promise that the key determines the value. Here the key was the props and the
value depended on the props plus everything ambient the render happened to read. The promise
was false, and the gap was exactly the request scoped data, which is precisely the data that
must not cross users.

The advisory names what can leak: account and profile data, request scoped secrets such as
CSRF tokens rendered into the HTML, and role specific content shown to someone without the
role. The last one is worth pausing on, because it means this can be an authorisation failure
and not just a privacy failure.

## How you would reproduce it

In a lab. Two users, matching props, different context values, each carrying a canary string.
Request as user A, then as user B, and look for A's canary in B's response.

Before believing it, turn off every cache above the application. A CDN or a reverse proxy
caching an authenticated response produces an identical symptom and is a far more common cause.
That control is not optional here.

## What the fix is, and why the obvious fix would not work

The maintainers deleted the memoisation. The commit strips the `computed` and `prevProps` state
and the `propsAreEqual` comparison out of `src/jsx/base.ts`, leaving a wrapper that just calls
the component. Memoisation now happens only in the DOM renderer, on the client.

The obvious fix is to widen the cache key: include the context values, and compare those too.
It sounds right and it does not work. There is no way to enumerate what a component read,
because context is read implicitly during the render, and the read happens after the point
where you would need the key. You would be trying to build a key from information you only
learn by doing the thing the key was supposed to let you skip. And any value missed reopens the
whole defect silently.

So the maintainers moved the cache to where the boundary already exists. On the client there is
only one user, so a stale cache is a correctness annoyance rather than a disclosure. **That
move, putting the cache inside the tenancy boundary instead of trying to encode the boundary in
the key, is the transferable lesson.**
