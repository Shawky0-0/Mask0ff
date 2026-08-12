---
tags: [security, flash, advisories, entry, apids, api, wordpress, kev, exploited]
updated: 2026-08-12
sources:
  - "https://github.com/advisories/GHSA-ff9f-jf42-662q accessed 2026-08-12"
  - "https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137 accessed 2026-08-12"
  - "https://hadrian.io/blog/wp2shell-a-pre-authentication-rce-in-wordpress-cores-rest-batch-api accessed 2026-08-12"
  - "https://blog.securelayer7.net/cve-2026-63030-cve-2026-60137-wp2shell-pre-auth-rce-in-wordpress-core-via-rest-batch-route-confusion-and-sql-injection/ accessed 2026-08-12"
  - "https://www.picussecurity.com/resource/blog/cve-2026-63030-and-cve-2026-60137-wp2shell-wordpress-rce-explained accessed 2026-08-12"
  - "CISA KEV catalogue JSON feed accessed 2026-08-12"
---

# APIDS-0002: WordPress REST batch endpoint dispatches sub requests against the wrong handler

the API folder, the ledger,
MTH-API-002, the parallel array desync method,
APIDS-0003, the injection it chains into.

```yaml
id: APIDS-0002
component:
  type: framework
  ecosystem: WordPress core, PHP
  name: WordPress
  version_scope: core, default install, no plugin required
affected:
  introduced: "___ , sources name the batch/v1 controller as the location but none state the introducing changeset"
  fixed_in: "6.9.5 and 7.0.2, both released 2026-07-17"
  tested_on: "___ , not reproduced. This sweep reads only."
  affected_ranges: "6.9.0 through 6.9.4, and 7.0.0 through 7.0.1"
identifiers:
  cve: CVE-2026-63030
  ghsa: GHSA-ff9f-jf42-662q
  osv: ___
  vendor_id: "WordPress 6.9.5 and 7.0.2 security release, 2026-07-17"
  nickname: wp2shell
class:
  owasp_api: "API5:2023 broken function level authorisation, with API1:2023 reached as a consequence"
  owasp_2025: "A01 broken access control"
  cwe: "___ , no source stated a CWE. Sources describe a confused deputy condition, which is the CWE-441 shape, so that is a label applied here and not a quoted classification."
  family: permission check bypass through index desynchronisation
protocol: rest
auth_required: none
entry_point:
  route: "/wp-json/batch/v1 , and the equivalent /?rest_route=/batch/v1"
  method: POST
  parameter: "the requests array in the JSON body"
  header: n/a
object_graph:
  which_request_creates_the_object: >
    controller once per sub request during the validation pass.
  who_owns_it: >
    The REST server. Each sub request should own exactly the route and permission callback
    matched for that sub request, and no other.
  who_should_reach_it: >
    Only a sub request whose own permission callback passed. An anonymous caller should reach
    no privileged handler at all.
  what_the_tested_account_got: >
    An anonymous caller reached the handler belonging to a later sub request in the same
    batch, and so executed under that sub request's matched route rather than its own.
root_cause:
  where: "WP_REST_Server::serve_batch_request_v1()"
  the_missing_decision: >
    The controller keeps three parallel lists, $requests, $validation and $matches, and relies
    on them staying aligned by index while it iterates. When a sub request fails early
    parsing, the code appends the error to $validation and continues, but never appends a
    placeholder to $matches. From that point $matches is one element shorter than $requests
    and $validation. The dispatch loop still reads $matches[$i] by the request's own index, so
    every sub request after the deliberately broken one is dispatched against the route and
    handler belonging to the next sub request in the batch. The missing decision is to keep
    the three lists aligned, or better, to stop using position as the join key.
signal: >
  A batch whose first member is deliberately malformed changes the errors the later members
  return. Hadrian's published probe sends three sub requests with a malformed first entry and
  compares the answers: a vulnerable server returns block_cannot_read, which is the wrong
  handler's permission error, and a patched server returns rest_term_invalid. The tell is an
  error belonging to a route the tester did not address.
safe_proof: >
  Read only in this sweep. In a disposable lab: send a three member batch where member one is
  malformed and members two and three address routes whose permission failures produce
  distinct, recognisable error codes. The proof is the mismatch between the route addressed
  and the error returned. Nothing is created and nothing is written, so no canary is needed;
  the observable is an error string. Never send the chained injection payload, see APIDS-0003.
controls:
  negative: >
    The same batch with member one well formed. If every error now lines up with the route
    that member addressed, there is no desync.
  differential: >
    The same batch against a patched 6.9.5 or 7.0.2 instance. The error must track the route
    addressed.
  false_positive: >
    A generic 403 on every member proves nothing at all. The finding requires the returned
    error to belong to a different route than the one that member addressed, so first call
    both routes alone and confirm they produce different error codes. A batch endpoint that
    returns errors in a different order than requested is also not this bug; check the
    response ordering contract before claiming a mismatch.
fix:
  commit_url: "___ , the WordPress changeset number was not stated by any source reached this run"
  invariant: >
    Per the Hadrian analysis, two changes. First, append to $matches on the parse failure path
    too, so all three lists stay the same length and the index join stays valid. Second, a re
    entrancy guard so a sub request cannot begin a fresh top level REST dispatch part way
    through batch processing.
hardening: >
  The control that kills the class is not the alignment fix. It is refusing to join by index
  at all: carry the matched route on the sub request object itself so a handler can never be
  read from a position. Operationally, what an affected deployment can do today is block or authenticate
  /wp-json/batch/v1 at the edge, because almost no site actually uses it.
detection: >
  Unauthenticated POST requests to /wp-json/batch/v1 or /?rest_route=/batch/v1 from addresses
  with no prior authenticated session, especially bodies carrying unusually large or malformed
  request arrays, or sub requests referencing post and author query parameters. Per
  securelayer7.
variant_rule: >
  Every batch, bulk or multi operation endpoint that validates a whole list in one pass and
  executes it in a second pass, joined by position, with a skip on one side. GraphQL batched
  queries and aliases, JSON:API bulk operations, and any custom bulk import route are the same
  shape. See MTH-API-002.
lab:
  snapshot: "snapshot first, because the full published chain writes to the database"
  teardown: "restore the snapshot"
provenance:
  source: "GitHub Security Advisory, Wiz, Hadrian, SecureLayer7, Picus, CISA KEV feed"
  accessed: 2026-08-12
  license_note: "summarised, not reproduced. No exploit code copied into this vault."
```

## What happens

WordPress core ships a batch endpoint so a client can bundle several REST calls into one
request. The controller handles the bundle in two passes: first it parses and validates every
member, then it dispatches them.

Both passes walk the same list, and they find each other by position. Position is the only
thing joining them. When a member fails to parse, the controller writes the error into the
validation list and moves on, but writes nothing into the list holding matched routes and
handlers. The two lists are now different lengths, and every position after the failure points
one slot off.

The dispatch pass never notices. It asks for the handler at position two and receives the
handler belonging to position three. A sub request then runs under a route it never asked for,
and under that route's permission callback rather than its own.

## Why it works

Because the permission check is real, and it passes. Nothing is skipped. The check runs, on
the wrong pair. The caller supplies a sub request that would be refused, and the controller
hands it a decision that was made about a different sub request. That is why the sources call
it a confused deputy.

The attacker controls the offset, because the attacker controls where in the batch the
malformed member sits and how many members follow it.

## How you would reproduce it

In a lab, on a disposable 7.0.1 install. Build a batch of three. Make member one malformed so
it fails parsing. Point members two and three at two routes whose permission failures produce
different, recognisable errors. Send it anonymously and read the errors. If member two comes
back carrying member three's error, the lists are desynchronised.

That is the whole proof, and it writes nothing. Stop there. The published chain continues into
SQL injection and then code execution, and there is no reason to run that.

## What the fix is, and why the obvious fix would not work

The patch appends a placeholder on the failure path so the lists stay the same length, plus a
guard against re entrant dispatch.

The obvious fix is to validate harder, or to reject any batch containing a malformed member.
Neither works, and the reason is worth holding on to. Rejecting the whole batch on one bad
member changes documented behaviour, because partial failure is the entire point of a batch
endpoint. And validating harder does not touch the defect, because the defect is not in
validation. Validation was correct. The defect is that a correct result was filed at an index
that later meant something else. Any fix that leaves position as the join key leaves the class
alive, and the next skip on either side reopens it.
