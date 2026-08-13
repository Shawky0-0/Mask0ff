---
tags: [security, flash, advisories, api, entry, api3, cache-key, directus, authz-bypass]
updated: 2026-08-13
sources:
  - "https://github.com/advisories/GHSA-c6w9-5g5j-jh2p, accessed 2026-08-13"
---

# APIDS-0024: the cache key knew who you were and not what you were allowed

**The same defect as APIDS-0005, the Hono `memo()`
entry, in an unrelated product.** Second confirmed instance, so the cache key question earns a
permanent place in the checklist. Related:
APIDS-0021, the other Directus entry,
MTH-API-001.

```yaml
id: APIDS-0024
component:
  type: framework
  ecosystem: npm
  name: directus
  version_scope: "< 12.0.0"
affected:
  introduced: ___
  fixed_in: 12.0.0
  tested_on: not tested, reading only
identifiers:
  cve: CVE-2026-61836
  ghsa: GHSA-c6w9-5g5j-jh2p
  osv: ___
  vendor_id: ___
class:
  owasp_api: API3:2023 broken object property level authorisation, named as such on the advisory
  owasp_2025: ___
  cwe: CWE-524, CWE-639
  family: the cache key is narrower than the authorisation that produced the value
protocol: rest
auth_required: >
  **none for the attacker.** A legitimate share request must populate the cache first, then an
  unauthenticated request to the same URL is served the cached result
entry_point:
  file: api/src/utils/get-cache-key.ts
  key_contains: version, path, query, accountability.user, and conditionally ip
  key_omits: share, role, roles, admin, app, policies
  precondition: CACHE_ENABLED=true, which is off by default, plus at least one row in
    directus_shares
object_graph:
  creates_the_object: an editor creates a share, a scoped and possibly password protected view
    of some data, and Directus filters responses according to the share's policies
  owns_it: the share's creator, with the share token as the credential
  should_reach_it: whoever holds that specific share token, and only within its scope
  tested_account_got: >
    another share's filtered response, or the share scoped data with no token at all. The
    advisory's sharpest case: **once any share populates the cache, a password protected share's
    content is served to anonymous callers**, because the password was checked when producing
    the value and is not part of the key that retrieves it
root_cause: >
  The missing decision is in key derivation. The advisory: "The cache-key derivation includes
  only version, path, query, and accountability.user (plus a conditional ip). Authorization
  context beyond user is not part of the key." Share authentication compounds it: the share flow
  issues JWTs with no id claim, so accountability.user stays null. Every share token and every
  anonymous caller therefore produce an identical key for the same URL and query.
signal: >
  For any cache, write down what goes into the key and what the value depends on. If the value
  depends on anything the key omits, one caller's value will be served to another. The
  authorisation context is the field most often left out, because a cache is written as a
  performance feature and permissions are somebody else's concern.
  **The tell here is the null:** an authentication path that produces no user identifier will
  collapse into whatever the key's default is, so ask what the key looks like for the least
  identified caller the system accepts.
safe_proof: >
  Lab only. Disposable Directus below 12.0.0 with CACHE_ENABLED=true. Create two shares, A and B,
  with different scopes, and put a distinct canary in the data only A can see. Request the URL
  as A so the cache fills. Then request the identical URL and query as B, and again with no
  token. **The proof is A's canary appearing in B's response and in the anonymous response.**
  Read only throughout.
controls:
  negative: >
    run the same sequence with CACHE_ENABLED=false. B and anonymous must both be refused or
    served their own scope. That is what proves the cache is the mechanism rather than a
    separate authorisation bug
  differential: >
    vary the query string by one character for B's request. It should miss the cache and be
    handled correctly. A hit that depends on exact URL and query equality is the signature of a
    cache key problem, and it distinguishes this from a plain broken access control finding
  attribution: >
    the canary must be data that only A's scope contains. Overlapping scopes make the result
    unreadable as evidence
fix:
  commit_url: https://github.com/directus/directus/commit/7ba4efb97525d3af33570537c76e44baea767f13
    and pull request 27707, referenced in the advisory, not opened by this sweep
  invariant: >
    Not read from the diff. Stated from the defect: the cache key must include every input the
    authorisation decision used, that is share, role, roles, admin, app and policies, and not
    only the user identifier. General form: **the key must be at least as specific as the
    authorisation that produced the value.**
hardening: >
  Derive the key from the full accountability object rather than from selected fields, so a
  field added to the authorisation model tomorrow is included automatically. Selecting fields by
  hand means the key drifts behind the permission system every time the permission system grows.
  Where a response depends on a secret such as a share password, the safest answer is not to
  cache it at all.
detection: >
  Identical response bodies served to callers holding different tokens. Harder than it sounds to
  spot in logs, because from the server's side everything looks like a normal cache hit. The
  CACHE_TTL window, typically 5 to 30 minutes, bounds each exposure, and Redis backed
  deployments carry it across restarts.
variant_rule: >
  Every cache between the authorisation decision and the response. Application caches, HTTP
  caches, CDN rules, reverse proxy caches, memoisation helpers, and anything keyed on the URL.
  Read across to APIDS-0005, where Hono's memo() served one user's rendered output to another
  for the same reason.
  **Ahmed's fleet: this is the sharpest read across in the run.** WordPress page and object
  caching plugins sit in front of REST responses, and any cache keyed on the URL alone will
  serve a logged in user's response to the next caller. The question to ask of every fleet site
  running a cache plugin is what the key contains and whether authenticated REST responses are
  excluded from it.
lab:
  install: disposable Directus below 12.0.0, CACHE_ENABLED=true, at least one share configured
  snapshot: before
  teardown: destroy
provenance:
  source: https://github.com/advisories/GHSA-c6w9-5g5j-jh2p
  accessed: 2026-08-13
  license_note: short quoted fragments for the technical description only
  credit: reported by @tr4ce-ju
```

## What happens

Directus can cache responses so it does not redo work. To cache, it needs a label for each
stored response, so it knows which stored answer belongs to which request. That label is the
cache key.

Directus built the key out of the version, the path, the query string, and the user. Sensible,
except that a user is not the only thing that decides what the response contains. Roles,
policies, admin status and shares all shape it too, and none of those were in the key.

Shares make it much worse. A share is a link giving scoped access to some data, sometimes behind
a password. The share login issues a token with no user id in it, so the user part of the key is
empty. Two different shares, and an anonymous visitor, all produce the same key for the same URL.

First one to ask fills the cache. Everyone after gets that answer, whoever they are.

## Why it works

The response was filtered correctly. Permissions did their job when the value was produced.

Then the value was filed under a label that did not record which permissions produced it, and
handed to the next person whose request had the same URL.

The password protected share case is the one to carry away. The password was checked, once,
when generating the response. Retrieving the cached copy does not go anywhere near the password.
**A control that runs when the value is made, and not when it is served, is a control that runs
once for everybody.**

## How you would reproduce it

Two shares with different scopes, a canary in one of them, caching on. Fill the cache as A, ask
as B, ask as nobody. When A's canary comes back both times, that is the finding. Then turn
caching off and show it stops, which is what makes the mechanism provable rather than asserted.

## What the fix is, and why the obvious fix would not work

The obvious fix is to add the share id to the key. It fixes the share collision and leaves
roles, policies and admin out. The next permission dimension anyone adds will be left out too.

The fix is to key on the whole authorisation context, so the key is at least as specific as the
decision that produced the value. Anything less means two different decisions can share one
label, and that is the bug regardless of which field happens to be missing this year.

## Why this is the second sighting and what that means

APIDS-0005 is Hono's `memo()` serving one user's
render to another because the cache key was narrower than the value. Different language,
different project, different layer of the stack, same sentence describes both.

Two independent instances is the threshold where this stops being trivia and becomes something
to ask on every review: **show me the cache key, and show me everything the response depends
on.** The gap between those two lists is the finding, and it is a question that takes thirty
seconds and does not require running anything.
