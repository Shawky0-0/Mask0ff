---
tags: [security, flash, advisories, api, entry, api9, api8, graphql, introspection, directus]
updated: 2026-08-16
sources:
  - "https://github.com/advisories/GHSA-wxwm-3fxv-mrvx, accessed 2026-08-16"
---

# APIDS-0030, introspection was switched off and a second resolver handed out the same schema

Related: MTH-API-009,
MTH-API-008,
APIDS-0027 (the other `API9` of this run).

**Carried debt for four runs, closed here.** It also fills the GraphQL introspection gap that
MTH-API-009 named explicitly as something it did not cover.

```yaml
id: APIDS-0030
component:
  type: service
  ecosystem: npm
  name: directus
  version_scope: "the /graphql/system endpoint, server_specs_graphql resolver"
affected:
  introduced: ___
  fixed_in: "11.16.1"
  tested_on: ___
identifiers:
  cve: CVE-2026-35413
  ghsa: GHSA-wxwm-3fxv-mrvx
  osv: ___
  vendor_id: ___
class:
  owasp_api: API9 improper inventory management (primary), API8 security misconfiguration (secondary)
  owasp_2025: ___
  cwe: ___ (the advisory names none; the shape is CWE-200 exposure of sensitive information)
  family: the second route to the same data, past the switch that was supposed to close the first
protocol: graphql
auth_required: none for the public permission level; an authenticated caller gets whatever their level permits
entry_point: "POST /graphql/system, the server_specs_graphql resolver"
object_graph:
  creates: "nothing; the schema is metadata about everything else"
  owns: "the operator"
  should_reach: "whoever the operator decided, which by setting GRAPHQL_INTROSPECTION=false they decided was nobody"
  tested_account_got: "collection names, field names, types and relationships, as SDL, with no authentication"
root_cause: >
  `GRAPHQL_INTROSPECTION=false` blocks the standard introspection queries `__schema` and `__type`.
  It does not reach `server_specs_graphql`, a resolver on `/graphql/system` that returns an
  equivalent SDL representation of the same schema. The restriction and the second resolver were
  written by different hands and the restriction was never extended. The missing decision is the
  introspection check inside `server_specs_graphql`, and the reason it is `API9` is that the
  operator believed they had one schema exposure surface and they had two.
signal: >
  Any setting whose name is a switch, in a product that has more than one route to the thing the
  switch governs. The question is never "does the switch work". It is "how many code paths reach
  this data, and does the switch sit on all of them". A spec, docs, schema, SDL, OpenAPI or
  `.well-known` route is the usual second path, because it is written as documentation and reviewed
  as documentation rather than as data access.
safe_proof: >
  Static: read the introspection guard and show which resolvers it wraps, then show
  `server_specs_graphql` outside it. In a lab, set `GRAPHQL_INTROSPECTION=false`, send `__schema`
  and confirm it is refused, then call the spec resolver and confirm the SDL comes back. Two
  requests, both read only, both against a lab instance.
controls:
  negative: "with GRAPHQL_INTROSPECTION unset, both paths should answer. That establishes the baseline and proves the switch is the variable."
  differential: "compare the SDL returned by the spec resolver against the schema returned by __schema when introspection is on. If the SDL is a strict subset that omits nothing sensitive, the finding is weaker; the advisory says it is equivalent."
  false_positive: "an operator may have set the switch for performance rather than for secrecy, in which case the exposure is intentional. Ask what the switch was set for before calling it a control that failed."
fix:
  commit: "not read this run"
  invariant: >
    Stated from the defect: every code path that can reconstruct the schema must be behind the same
    introspection setting, so that the setting names a property of the server rather than a property
    of one resolver.
hardening: >
  Stop treating introspection as a switch and treat schema exposure as a permission. Then the check
  lives with the data and any new route that reads it inherits the check. The version of this that
  scales is a single accessor for the schema, with the authorisation inside it, and no resolver
  allowed to build SDL any other way. That is the same control as
  MTH-API-008: one guard, and every path forced
  through it.
detection: >
  Requests to `/graphql/system` naming the spec resolver, from unauthenticated callers. Also worth
  alerting on: any single request that returns the full field list of many collections at once,
  regardless of which route produced it.
variant_rule: >
  The second path to the schema exists in nearly every API product. GraphQL: `__schema`, SDL
  endpoints, persisted query manifests, Apollo schema reporting. REST: `/openapi.json`,
  `/swagger.json`, `/api-docs`, `/.well-known/`, a WordPress `/wp-json/` root discovery document,
  Directus's own OpenAPI spec which leaked the exact version in CVE-2025-53887. **On Ahmed's fleet:
  the `/wp-json/` root document lists every registered route on a WordPress site, and nobody has
  read the one EduAi serves. It is a WordPress product so the entry would be the WordPress sweep's,
  but the surface is on this lane's table and the reading is free.**
lab:
  install: "directus < 11.16.1 in docker with GRAPHQL_INTROSPECTION=false"
  snapshot: "container snapshot before, discard after"
  teardown: "docker rm"
provenance:
  source: "GitHub Security Advisory GHSA-wxwm-3fxv-mrvx"
  accessed: 2026-08-16
  license_note: "advisory text summarised, not reproduced"
```

## What happens

An operator turns off GraphQL introspection. That is the setting that stops a stranger asking the
API to describe itself. They now believe the shape of their data is private.

There is a second resolver that describes the schema a different way, as SDL. The setting does not
touch it. A stranger asks that one instead and gets the collection names, the field names, the types
and the relationships.

## Why it works

The switch was written against the standard queries, `__schema` and `__type`. Those are the ones
everybody knows about. The spec resolver was written as a documentation feature, and documentation
does not feel like data, so nobody put an access check on it.

The result is worse than having no switch at all. With no switch, the operator knows the schema is
public. With a switch that only covers one of two paths, the operator believes it is private. The
advisory names that directly: they gained false protection.

## How to reproduce

Set the switch off in a lab. Send `__schema` and watch it get refused. Call the spec resolver and
watch the same information come back.

## The fix, and why the obvious fix would not work

Extend the check to the spec resolver.

The obvious fix is exactly that, and it is what the vendor shipped, and it will be wrong again the
next time somebody adds a third way to read the schema. The class only dies when the check moves
from the resolvers to the schema itself: one accessor, one permission, and no other way in. A
switch you have to remember to apply to each new route is a switch that will be forgotten, and this
CVE is the receipt.
</content>
