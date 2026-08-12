---
tags: [security, flash, advisories, entry, apids, api, wordpress, kev, injection]
updated: 2026-08-12
sources:
  - "https://blog.securelayer7.net/cve-2026-63030-cve-2026-60137-wp2shell-pre-auth-rce-in-wordpress-core-via-rest-batch-route-confusion-and-sql-injection/ accessed 2026-08-12"
  - "https://www.wiz.io/blog/wp2shell-cve-2026-63030-cve-2026-60137 accessed 2026-08-12"
  - "https://www.picussecurity.com/resource/blog/cve-2026-63030-and-cve-2026-60137-wp2shell-wordpress-rce-explained accessed 2026-08-12"
  - "CISA KEV catalogue JSON feed accessed 2026-08-12"
---

# APIDS-0003: WP_Query author__not_in loses its integer casting when passed a string

**The second half of the wp2shell chain.** Related:
APIDS-0002, the batch route confusion that delivers it,
the API folder, the ledger.

```yaml
id: APIDS-0003
component:
  type: framework
  ecosystem: WordPress core, PHP
  name: WordPress, WP_Query
  version_scope: core query layer, reachable through any route that forwards query vars
affected:
  introduced: ___
  fixed_in: "6.8.6, 6.9.5 and 7.0.2 . Sources state 6.8.0 through 6.8.5 are affected by the injection alone; the fixed 6.8 branch version is inferred from that range and is marked ___ until confirmed."
  tested_on: "___ , not reproduced. Reading only."
  affected_ranges: "6.8.0 through 6.8.5 for the injection alone, plus 6.9.0 through 6.9.4 and 7.0.0 through 7.0.1 where it is reachable pre authentication through the batch chain"
identifiers:
  cve: CVE-2026-60137
  ghsa: ___
  osv: ___
  vendor_id: "WordPress 6.9.5 and 7.0.2 security release, 2026-07-17"
class:
  owasp_api: >
    Not cleanly an OWASP API Top 10 class. It is an injection defect in the data layer that
    the API reaches. Filed here because API5 (APIDS-0002) is what makes it reachable, and the
    pair only makes sense read together.
  owasp_2025: "A03 injection"
  cwe: "CWE-89 SQL injection"
  family: type confusion defeating a sanitiser
protocol: rest
auth_required: >
  none when chained through the batch endpoint on 6.9.x and 7.0.x. On 6.8.x, sources state no
  unauthenticated path on a default install reaches the parameter directly, which is why it
  rates only moderate alone.
entry_point:
  route: "any route that forwards query vars into WP_Query. In the published chain, the posts handler reached through /wp-json/batch/v1"
  method: POST
  parameter: "author__not_in , supplied as a string rather than an array"
  header: n/a
object_graph:
  which_request_creates_the_object: >
    No object is created. The abused thing is a query variable that the caller supplies and
    the query builder trusts after a type check that only fires on one branch.
  who_owns_it: "WP_Query owns the construction of the SQL clause"
  who_should_reach_it: >
    Only a sanitised array of integers should ever reach the clause builder, whatever the
    caller sent.
  what_the_tested_account_got: >
    An anonymous caller placed a raw string into the generated SQL, because the branch that
    casts each element to an integer only runs when the value arrives as an array.
root_cause:
  where: "WP_Query, the handling of the ID list query vars post__in, post__not_in, author__in and author__not_in"
  the_missing_decision: >
    WP_Query normally enforces that these parameters are arrays of integers, casting every
    element with absint() before building the SQL clause. That casting lives on the array
    branch only. When the value arrives as a scalar string, the per element casting is skipped
    and the value flows into the generated SQL unsanitised. The missing decision is to
    normalise the type before deciding how to sanitise, rather than making sanitisation
    conditional on the type that happened to arrive.
signal: >
  In code review the signal is a sanitiser that sits inside a type branch. Any function shaped
  like "if it is an array, clean every element, otherwise use it" is this defect waiting to
  happen. In black box testing the signal is a parameter documented as a list that does not
  error when sent as a bare string.
safe_proof: >
  Read only in this sweep. In a disposable lab, the safe demonstration is a syntactically
  provable but harmless marker: send the parameter as a string containing something that would
  change the SQL shape and observe whether the result set or the error changes versus the same
  value sent as a single element array. Never send a payload that reads, writes or times the
  database. The difference between the two request forms is the whole proof.
controls:
  negative: >
    Send the identical value as a one element array. If the behaviour is the same, the casting
    is not branch dependent and there is nothing here.
  differential: >
    Repeat on a patched instance, where both forms should behave identically.
  false_positive: >
    A changed result set alone is not injection. The parameter legitimately changes the result
    set, that is its job. The claim requires evidence that the value altered the SQL structure
    rather than the SQL inputs, and on a lab install that is best shown from the query log
    rather than inferred from the response.
fix:
  commit_url: ___
  invariant: >
    Normalise the parameter to an array first, then cast every element, so the sanitiser is
    unconditional. Stated from the root cause description; no source reached this run showed
    the patched code.
hardening: >
  The class killer is that sanitisation must never be reachable only on one branch of a type
  check. Coerce to the expected type at the boundary, then sanitise once, with no branch. A
  parameterised query for the clause would also remove it, but the coercion is what stops the
  next parameter of the same shape.
detection: >
  Requests carrying post__in, post__not_in, author__in or author__not_in as a scalar rather
  than an array. In the chained form, the batch endpoint indicators in APIDS-0002 apply first.
variant_rule: >
  Look at the other three ID list query vars named above, since they share the pattern. More
  broadly, any codebase with a sanitise helper called from inside an is_array() test. This
  shape recurs wherever an API accepts "a value or a list of values" for convenience.
lab:
  snapshot: "snapshot first"
  teardown: "restore the snapshot"
provenance:
  source: "SecureLayer7, Wiz, Picus, CISA KEV feed"
  accessed: 2026-08-12
  license_note: "summarised, not reproduced. No exploit code copied into this vault."
```

## What happens

`WP_Query` accepts a set of parameters that are meant to be lists of IDs. `author__not_in` is
one of them. The query builder protects itself by walking the list and casting every element to
a non negative integer before it builds the SQL.

That protection lives on the array branch. Send the parameter as a plain string instead of an
array and the walk never runs, because there are no elements to walk. The string goes into the
generated SQL as it arrived.

## Why it works

The sanitiser was written as part of the code that handles arrays, rather than as part of the
code that handles the parameter. So the protection is conditional on a shape the caller
chooses. The caller simply declines to send that shape.

This is why the two CVEs matter as a pair rather than separately. On its own the injection is
rated moderate, because on a default install nothing anonymous reaches that parameter. The
batch route confusion in APIDS-0002 is what
delivers an unvalidated, attacker shaped request into the posts handler, which is how a
moderate injection becomes a pre authentication path to code execution.

## How you would reproduce it

In a lab. Send the parameter twice against the same route: once as a one element array, once
as a bare string with the same content. Compare. On an affected version the two requests do
not behave the same way, and the query log shows why.

Stop at the shape difference. Do not extract data and do not run the published chain.

## What the fix is, and why the obvious fix would not work

Normalise first, sanitise once, no branch.

The obvious fix is to add sanitisation to the string branch as well. That closes this
parameter and leaves the class open, because the defect is the branch itself. Every future
parameter that accepts "a value or a list" grows the same hole, and the next developer who
adds a convenience shorthand will not know that the sanitiser is branch bound. Coercing the
type at the boundary means there is only ever one branch to protect.
