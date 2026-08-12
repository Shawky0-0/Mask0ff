---
tags: [security, flash, advisories, entry, web, graphql, access-control]
updated: 2026-08-12
sources:
  - "https://www.sentinelone.com/vulnerability-database/cve-2026-41856/ accessed 2026-08-12"
---

# WEBDS-0001: Spring GraphQL, authorisation annotation silently not applied

**Chosen over the newer Laravel items deliberately.** The Laravel advisories are in today's
run file as one liners and carried into the backfill, because this one teaches a class that

```yaml
id: WEBDS-0001
component: { type: framework, ecosystem: other, name: Spring GraphQL, version_scope: "fixed across all supported branches" }
affected: { introduced: ___, fixed_in: "released across all supported branches, exact numbers ___", tested_on: not tested, desk research only }
identifiers: { cve: CVE-2026-41856, ghsa: ___, osv: ___, vendor_id: "Spring Security advisory" }
class: { owasp_2025: A01, owasp_api: API5, owasp_llm: not_applicable, cwe: CWE-862, family: missing-function-level-authorisation, corpus_directory: 02-access-control-bac-idor }
auth_required: none
entry_point: "any GraphQL resolver whose controller method overrides a parent class method"
root_cause: >
  Authorisation is declared with an annotation. When a controller method overrides a method
  on a parent class, the annotation resolver may fail to find the annotation on the
  supertype. The runtime then resolves the method, finds no security annotation, and
  executes the resolver with no permission check at all. The protection is not bypassed; it
  is never located.
signal: >
  Declarative authorisation (annotations, attributes, decorators, middleware by convention)
  combined with inheritance or overriding. The check is invisible in the method body, so
  nothing in the code you are reading shows it is missing.
safe_proof: >
  Call the overriding resolver as an unauthorised account and observe whether it executes.
  Compare against the parent method, which is still protected. A read only field is enough.
controls: >
  Confirm the account is genuinely unauthorised on the parent method. Confirm the resolver
  actually ran rather than returning a cached or default value. Confirm the field is not
  intentionally public.
fix: { commit: ___, invariant: "resolve annotations across the whole type hierarchy, not just the declaring class" }
hardening: >
  Deny by default at the transport layer. If a resolver has no explicit authorisation
  decision recorded, it should fail closed rather than run. Declarative authorisation that
  fails open is the whole problem here.
detection: "resolvers executing for principals with no matching grant"
variant_rule: >
  Every framework with declarative authorisation and inheritance. Check what happens to the
  annotation on an override, a trait, a mixin, an interface default method, or a
  dynamically generated proxy.
lab: { install: ___, snapshot: ___, teardown: ___ }
provenance: { source: "SentinelOne vulnerability database, referencing the Spring Security advisory", accessed: 2026-08-12, license_note: "public vulnerability database" }
```

## What happens

A GraphQL resolver that is supposed to require a permission runs without one. The developer
wrote the annotation. It is right there in the code. It simply never gets found.

## Why it works

The security annotation sits on a method in a parent class. A child controller overrides
that method. When the runtime asks "does this method have a security annotation", it looks
at the overriding method, does not find one, does not walk up to the supertype, and
concludes there is no requirement.

**Nothing threw an error. Nothing logged a warning. The resolver just ran.**

## Why this class matters more than the specific CVE

authorisation**, because Laravel middleware, WordPress capability checks wired through
hooks, and every attribute or decorator based system share the property that makes this
dangerous:

**the protection is not visible in the code you are reading.**

When authorisation lives in the method body, a missing check is a missing line you can see.
When it lives in an annotation, a middleware group, or a hook registration, a missing check
looks exactly like a working one. You have to go and confirm it actually applied.

## The question this turns into, for any codebase

Do not ask "is there an authorisation check". Ask **"can I prove the check ran for this
specific request"**.

On WordPress that means confirming the capability check is in the callback that actually
executes, not in a parent or a sibling. On Laravel it means confirming the route is in the
middleware group you think it is, and that the middleware was not skipped by a route
override or a group ordering.

## The fix, and why the obvious one is wrong

The obvious fix is to re add the annotation on every override. That works until the next
override, and it makes correctness depend on every developer remembering.

**The invariant is: resolve annotations across the whole type hierarchy.** And the hardening
that kills the class regardless of framework: **fail closed.** A resolver with no
authorisation decision on record should refuse, not run.
