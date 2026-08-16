---
tags: [security, flash, advisories, appsec, authentication, jwt, oauth, webds]
updated: 2026-08-16
sources:
  - "https://github.com/ether/etherpad-lite/security/advisories/GHSA-qfmh-fph3-mw8q, accessed 2026-08-16"
  - "https://github.com/advisories?query=sort%3Apublished-desc+ecosystem%3Anpm, accessed 2026-08-16"
---

# WEBDS-0026: Etherpad asks whether the admin claim exists, never whether it is true

```yaml
id: WEBDS-0026
component:
  type: package
  ecosystem: npm
  name: ep_etherpad-lite
  version_scope: "the HTTP API authentication path, when authenticationMethod is anything other than apikey"
affected:
  introduced: "2.1.0, released 2024-05-22"
  fixed_in: "3.1.0"
  tested_on: "___, not installed by this sweep"
identifiers:
  cve: CVE-2026-55089
  ghsa: GHSA-qfmh-fph3-mw8q
  osv: "___, the OSV record was not fetched for this id"
  snyk: ___
  vendor_id: "PR 7784, fix commit 8c6104c"
class:
  owasp_2025: "broken access control, and authentication failures"
  owasp_api: "API5, broken function level authorization"
  owasp_llm: n/a
  cwe: CWE-863, incorrect authorization
  family: authentication and token validation
  corpus_directory: 03-authentication-session-oauth-jwt/
auth_required: user
entry_point: "every route under /api/2/, called with an OAuth issued bearer token, for example POST /api/2/pads/text"
root_cause: >
  The API guard passes requiredClaims: ["admin"] to the jose JWT verification call.
  The advisory states that jose's requiredClaims option verifies that a claim is present
  and does not compare its value. A non admin OAuth user is issued a token carrying
  {"admin": false}. The claim is present, so the check passes, and the request runs with
  full API rights. The missing decision is the comparison itself: nowhere in the guard is
  the value of the claim read.
signal: >
  A guard that names a privileged claim but never contains a comparison operator against
  it. Read the authentication middleware and look for the claim name appearing exactly
  once, inside a configuration list rather than inside an if. Second signal: the product
  supports two authentication methods and only one of them is exercised by the test suite.
safe_proof: >
  On a lab instance only. Create a second user with is_admin false, obtain a token through
  the normal OAuth flow, and call a read only API endpoint that should return 401. The
  canary is the status code, not the data: a 200 where a 401 belongs proves the guard.
  Do not write, delete or move a pad to demonstrate it.
controls: >
  Negative control: repeat the identical request with the admin claim removed from the
  token entirely. If that also returns 200, the guard is not running at all and the finding
  is a different, larger bug. Differential control: repeat with authenticationMethod set to
  apikey, which the advisory says is not affected, and confirm the 401 comes back. If the
  401 never appears in either configuration, the instance is misconfigured and the presence
  only check is not what you are looking at.
fix:
  commit_url: "https://github.com/ether/etherpad-lite/commit/8c6104c, referenced in the advisory as the fix for pull request 7784. Commit page not opened this run"
  invariant: >
    The patch quoted in the advisory replaces the configuration level check with an explicit
    value test: if (verified.admin !== true) throw Unauthorized. The invariant is that
    authorisation is decided by comparing the claim value to true with a strict comparison,
    not by the claim's existence. Strict matters: "false" as a string, 0, and null are all
    present and all not true.
hardening: >
  Never let a library option stand in for an authorisation decision. Any claim that grants
  privilege gets read out of the token and compared in application code, in one function
  that every route calls. The class dies when there is exactly one place in the codebase
  where the word admin is compared to a value.
detection: >
  Access logs show a low privilege principal calling administrative endpoints and receiving
  2xx. A WAF sees nothing: the request is well formed, the token is validly signed, and the
  only thing wrong is the meaning of a field inside it. This is a bug no signature catches.
variant_rule: >
  Look for the same shape wherever a library offers a "required" list. jose requiredClaims,
  PHP isset() and array_key_exists() used as a permission test, JavaScript
  Object.hasOwn(claims, "admin"), Python "admin" in claims, and any JSON Schema "required"
  array being read as if it were a value constraint. Same shape again in JWT header
  handling: checking that alg is present rather than that it is in an allow list.
lab:
  install: "docker run of an ep_etherpad-lite image at 3.0.0, with an OAuth provider configured and two users, one is_admin true and one is_admin false"
  snapshot: "container snapshot before creating the second user"
  teardown: "remove the container and its volume. No third party, no network target outside the lab"
provenance:
  source: "https://github.com/ether/etherpad-lite/security/advisories/GHSA-qfmh-fph3-mw8q"
  accessed: 2026-08-16
  license_note: "GitHub advisory text, read only, quoted in short fragments"
```

## What happens

Etherpad lets you log in through OAuth. When you log in, the server hands you a token. Inside
that token is a small list of facts about you. One of those facts is called `admin`.

The server checks your token before it lets you call the API. The check asks one question:
is there an `admin` fact in this token? It never asks what that fact says.

An ordinary user gets a token that says `admin: false`. The fact is there. So the check
passes. That user can now call every administrative endpoint in the product.

## Why it works

The check is not written by hand. It is a setting handed to a library. The setting is called
`requiredClaims`, and the advisory says the library's own documentation is clear that it
tests presence and not value.

So the bug is a reading mistake, not a coding mistake. Somebody read `requiredClaims: ["admin"]`
and heard "require admin". The library heard "require that the word admin appears". Both
readings are reasonable in English. Only one of them is what the code does.

This is why the class is worth learning rather than the bug. The same misreading is available
in every language. `isset($claims['admin'])` in PHP is the same sentence.

## How you would reproduce it

Two users on a lab instance, one admin and one not. Log in as the one who is not. Call an API
endpoint that should refuse you. If it returns 200 instead of 401, you have it.

The proof is the status code. There is no need to write anything, delete anything, or touch
another user's data to show the guard is not working.

## What the fix is, and why the obvious fix would not work

The patch reads the claim and compares it: `if (verified.admin !== true) throw`.

The obvious fix, and the wrong one, is to make the token issuer stop putting `admin: false`
into non admin tokens. That would close today's path and leave the class open. The check would
still be a presence test, and it would still pass for any token that carries the field for any
reason: a future feature, a different identity provider, a cached token from an older version.
A guard that depends on nobody ever setting a field is not a guard.

Note the strictness too. `!==` rather than `!=` matters here, because a string `"false"` is
truthy in JavaScript. A loose comparison would have fixed the reported case and left a second
one open.

Related: MTH-WEB-010, the guard that checks
presence and not value, which is the general form of this bug.
WEBDS-0027 and
WEBDS-0028 come from the same audit batch.
