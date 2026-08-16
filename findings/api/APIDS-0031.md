---
tags: [security, flash, advisories, api, entry, api3, directus, field-permissions]
updated: 2026-08-16
sources:
  - "https://github.com/advisories/GHSA-38hg-ww64-rrwc, accessed 2026-08-16"
---

# APIDS-0031, the field was masked in the row and not in the `min` of the same field

Related: APIDS-0032 (the same product, the same
class, a different derived path), MTH-API-010,
APIDS-0024.

A mechanism this folder had nothing on: **an aggregate function as a route past field level
permissions.** Carried debt for two runs, closed here.

```yaml
id: APIDS-0031
component:
  type: service
  ecosystem: npm
  name: directus
  version_scope: "the items API aggregate path, min and max functions"
affected:
  introduced: ___
  fixed_in: "11.17.0"
  tested_on: ___
identifiers:
  cve: CVE-2026-35442
  ghsa: GHSA-38hg-ww64-rrwc
  osv: ___
  vendor_id: ___
class:
  owasp_api: API3 broken object property level authorisation
  owasp_2025: ___
  cwe: ___ (the advisory names none; the shape is CWE-200 exposure of sensitive information)
  family: the masking pipeline that runs on one response shape and not on another
protocol: rest
auth_required: user (any authenticated account with read access to the collection)
entry_point: "the items endpoint with aggregate[min] or aggregate[max] naming a concealed field, combined with groupBy"
object_graph:
  creates: "the row was created by whoever owns it, including administrators and the directus_users collection itself"
  owns: "each user owns their own token and TOTP seed"
  should_reach: "nobody should read a concealed field's raw value, that is what conceal means"
  tested_account_got: "any authenticated user with collection read access recovered raw values of concealed fields, including static API tokens for every user and TOTP seeds from directus_users"
root_cause: >
  A field marked with the `conceal` special is masked by payload processing on read, which replaces
  the value with a placeholder. That processing keys on flat field names in the response. An
  aggregate response nests results under the function name instead, so `min` of a concealed field
  does not look like that field to the masking code, and the code silently skips it. The missing
  decision is the field permission check on the aggregate query path. It never runs there, so the
  raw value is returned.
signal: >
  A response shape the security layer was not written against. The masking works on rows because
  rows are what the author had in mind. Any endpoint that returns something other than a row is
  worth checking: aggregates, counts, group headers, facets, exports, search hit highlights. **The
  discovery question is not "is this field protected" but "is this field protected in every shape
  the API can return it in".**
safe_proof: >
  Create a canary record in a lab whose concealed field holds a known marker such as
  `canary-apids-0031`. As a low privilege user, request the collection normally and confirm the
  masked placeholder. Then request `aggregate[min]` on that field with a `groupBy`. If the marker
  comes back, it is proved. **Use a marker, never a real token, and never point this at anything
  outside the lab.** With `groupBy` and `min` or `max` an attacker can walk a value out character by
  character, so the class is full recovery, not a single leak.
controls:
  negative: "run the same aggregate against a field that is not concealed. It should return the value in both shapes, which shows the aggregate path itself is not the anomaly."
  differential: "run the row query and the aggregate query as the same user in the same session. One masks, one does not. Same user, same permission set, two answers, and that difference is the entire finding."
  false_positive: "concealment is a display control in some products rather than an access control. Check whether the vendor documents conceal as security. Directus's own advisory treats it as one, and the impact section (API tokens and TOTP seeds) settles it."
fix:
  commit: "not read this run. The advisory links no commit or pull request"
  invariant: >
    Stated from the defect: the field permission and masking check must run on the aggregate query
    path, keyed on the field the function was applied to rather than on the shape of the response.
hardening: >
  Apply the field policy where the field is selected, not where the response is serialised. If the
  query planner refuses to place a concealed column into any projection, aggregate or otherwise, no
  new response shape can leak it. The serialisation layer is the wrong place for an access decision
  because there is always another way to serialise.
detection: >
  Aggregate queries naming sensitive columns. A `min` or `max` on a token, secret, hash or seed
  column has no legitimate use, so it is a clean alert. A run of such queries with a moving
  `groupBy` or filter is the character by character extraction and is louder still.
variant_rule: >
  Every function that reads a column without returning it as itself: `min`, `max`, `count
  distinct`, `sum`, sorting by the column, filtering with a comparison on it, full text search over
  it, and a uniqueness error message that tells you the value already exists. Directus's own
  CVE-2025-64748 is the search variant of exactly this: concealed fields were searchable. **On
  Ahmed's fleet: any WordPress or Laravel endpoint that lets the caller choose an `orderby`, a
  filter operator, or an aggregate over a column the response does not include.**
lab:
  install: "directus < 11.17.0 in docker, one collection with a concealed field, one low privilege user"
  snapshot: "container snapshot before, discard after"
  teardown: "docker rm"
provenance:
  source: "GitHub Security Advisory GHSA-38hg-ww64-rrwc"
  accessed: 2026-08-16
  license_note: "advisory text summarised, not reproduced"
```

## What happens

Some fields are concealed. Ask for the row and you get stars instead of the value. That is the
control.

Ask for the smallest value of that same field instead, and you get the value. Not stars. The real
thing.

## Why it works

The masking code looks at the response and finds fields by name, then swaps their values out. In a
normal response the field is a key at the top of the row, so the code finds it.

An aggregate response is shaped differently. The result sits nested under the name of the function,
`min`, rather than under the name of the field. The masking code walks the response, does not see a
key it recognises, and moves on. Nothing errors. Nothing logs. The raw value ships.

And because you can combine this with grouping and filtering, you are not limited to one peek. Ask
for the smallest value greater than "a", then greater than "b", and you can walk a secret out one
step at a time.

The impact section is worth reading twice: the concealed fields in question include every user's
static API token and the seeds behind their two factor codes. So this is not information disclosure
in the abstract. It is logging in as the administrator.

## How to reproduce

In a lab, put a marker string in a concealed field. As a normal user, read the row and see the
mask. Then ask for `min` of that field with a `groupBy`. The marker comes back.

## The fix, and why the obvious fix would not work

Run the permission check on the aggregate path.

The obvious fix is to teach the masking code about nested aggregate keys. That closes this hole and
leaves the class open, because the next response shape somebody adds will have keys the masking
code does not recognise either. The check has to move upstream, to the point where the query
decides it may read that column at all. A control that lives in the serialiser is a control that
every new serialiser has to be told about.
</content>
