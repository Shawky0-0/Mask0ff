---
tags: [security, flash, advisories, entry, web, api, type-confusion, symfony, api-platform]
updated: 2026-08-12
sources:
  - "https://github.com/api-platform/core/security/advisories/GHSA-9rjg-x2p2-h68h accessed 2026-08-12"
---

# WEBDS-0009: API Platform accepts a relation IRI pointing at the wrong resource type

Related: the Nuxt authorisation bypass,
the web advisories folder.

```yaml
id: WEBDS-0009
component: { type: library, ecosystem: composer, name: api-platform/core, version_scope: "the 4.1, 4.2 and 4.3 lines. Sits on Symfony components" }
affected: { introduced: ___, fixed_in: "4.1.30, 4.2.26 and 4.3.12", tested_on: "not tested, desk research only" }
identifiers: { cve: CVE-2026-54164, ghsa: GHSA-9rjg-x2p2-h68h, osv: ___, snyk: ___, vendor_id: ___ }
class: { owasp_2025: "broken access control, through data integrity", owasp_api: "API3, broken object property level authorization is the closest fit", owasp_llm: not_applicable, cwe: "CWE-843, type confusion", family: "an identifier is resolved without checking what it points at", corpus_directory: 04-api-graphql-websocket-cors }
auth_required: "user. The attacker needs write access, POST PUT or PATCH, to an endpoint with a writable relation"
entry_point: "any writable relation property in a request body, where the value is an IRI such as /api/users/7 or /api/invoices/7"
root_cause: >
  AbstractItemNormalizer resolves a relation IRI by calling IriConverter::getResourceFromIri()
  without passing an operation context. Without that context the is_a type guard is skipped, so
  the object that comes back is never checked against the relation's declared class. The
  missing decision is the type check at IRI resolution time. Note the partial mitigation the
  advisory records: modern PHP 8.x typed properties are rejected by Symfony's PropertyAccessor,
  so the wrong object only persists on untyped properties carrying legacy @var annotations.
  That makes exposure a function of how old the entity code is.
signal: >
  Any API that accepts a reference by identifier. The question to ask is not "can I read this
  ID" but "does the server check what type the ID points at". IRIs make this visible because
  the type is right there in the path, so swapping /api/categories/3 for /api/users/3 is a one
  character experiment. Where the API takes bare integers instead, the same bug exists and is
  simply harder to see.
safe_proof: >
  In a lab, create two resources of different types. PATCH a writable relation with the IRI of
  the wrong type. A vulnerable build accepts it and stores it. A patched build returns 400. The
  observation is the status code, so nothing destructive is required, and it should be done on
  a throwaway record.
controls:
  - "Negative control: the same request against 4.3.12 or the other patched versions must return 400."
  - "Differential control: try the same swap against a relation declared on a typed PHP 8 property. It should be rejected by PropertyAccessor even on a vulnerable build, which confirms the untyped property is the variable and stops the finding being overstated."
  - "False positive to rule out: a 200 that did not actually persist anything. Read the resource back and confirm the wrong typed relation is really stored."
fix: { commit_url: "___, the advisory names the test rather than the commit: tests/Functional/Security/TypeConfusionRelationIriTest.php in the patched branches", invariant: "an is_a guard inside AbstractItemNormalizer::getResourceFromIri(), returning 400 Bad Request for a cross type IRI instead of assigning silently" }
hardening: >
  Type every entity property. That single change turns this from a silent corruption into a
  rejection, because Symfony's PropertyAccessor then refuses the mismatch. More generally:
  validate the type of anything resolved from an identifier at the moment of resolution, not
  at the moment of use, because by the time it is used the code that would have caught it has
  already assumed it is correct.
detection: >
  Relation columns holding IDs that do not exist in the expected table, which is a query you
  can run rather than a log you have to watch. There is no request signature: the payload is
  well formed JSON with a valid IRI in it.
variant_rule: >
  Every place an identifier crosses a trust boundary without its type: GraphQL global IDs where
  the type is base64 encoded into the ID, polymorphic relations keyed on a type column the
  client can set, Rails style ActiveRecord polymorphic associations, MongoDB document
  references, and any endpoint taking a bare integer ID for a relation. The diagnostic question
  is constant: after resolving this identifier, does anything confirm it is the kind of thing
  we asked for.
lab: { install: "a Symfony app with api-platform/core pinned below the fix, two resource types and one untyped relation property", snapshot: "project directory, composer.lock and a database dump", teardown: "drop the database and delete the directory" }
provenance: { source: "https://github.com/api-platform/core/security/advisories/GHSA-9rjg-x2p2-h68h", accessed: 2026-08-12, license_note: "vendor security advisory, public" }
```

## What happens

In an API Platform API you refer to a related record by its IRI, a path like `/api/authors/12`.
When you send that in a write request the serializer looks it up and assigns it. It never
checked that the thing it found was the type the relation actually declares. So a field meant
to hold an Author can be made to hold an Invoice, or a User, as long as you send the right path.
Rated 6.5.

## Why it works

The type is present in the request the whole time, sitting in the IRI, which makes this easy to
miss: it feels like the type has already been established. It has not been checked, only
transported. The guard that would have checked it does exist in the codebase, and it was
skipped because the operation context that switches it on was not passed down. That is the
common shape of this bug: the check is written, and one call site does not reach it.

## The detail that keeps this honest

Modern PHP typed properties save you. If the entity declares `private Author $author`, Symfony's
PropertyAccessor refuses the wrong object and nothing is stored. The vulnerability only lands on
untyped properties documented with a legacy `@var` annotation. So the real exposure question is
how old the entity code is, not what version of the library is installed. That is worth
recording precisely because it is the sort of qualifier a summary drops, and dropping it turns a
conditional finding into an overstated one.

## What this teaches beyond this library

Data integrity bugs get triaged as low severity and then turn into access control bugs one
layer later. If an Invoice can be stored where an Author belongs, everything downstream that
loads that relation and trusts its type is now operating on an object it did not expect,
including any permission check that reads a property off it.

## What the fix is, and why the obvious fix is not enough

The obvious fix is validation in the application: check the type in a controller or a validator.
It works for the endpoints you remember. The library fix is the right layer, an `is_a` guard at
resolution time returning 400, because it applies to every relation on every resource without
identifier becomes an object, not where the object gets used.
