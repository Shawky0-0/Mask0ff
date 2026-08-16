---
tags: [security, flash, advisories, appsec, graphql, api, missing-authentication, billing, webds]
updated: 2026-08-16
sources:
  - "https://github.com/advisories/GHSA-8wp4-ghqw-4g3h, accessed 2026-08-16"
  - "https://github.com/advisories?query=graphql, accessed 2026-08-16"
---

# WEBDS-0033: Chaskiq's Stripe mutation is one of the ones nobody put behind the door

```yaml
id: WEBDS-0033
component:
  type: service
  ecosystem: other
  name: "Chaskiq, the open source customer messaging platform. Ruby on Rails, GraphQL API"
  version_scope: "the GraphQL mutation surface"
affected:
  introduced: "___"
  fixed_in: "___. The advisory says the flaw exists through commit 46dfdd1 and names no fixed release"
  tested_on: "___, not installed by this sweep"
identifiers:
  cve: CVE-2026-72536
  ghsa: GHSA-8wp4-ghqw-4g3h
  osv: "___, api.osv.dev returned 404 for this id on 2026-08-16"
  snyk: ___
  vendor_id: ___
class:
  owasp_2025: "broken access control"
  owasp_api: "API5, broken function level authorization"
  owasp_llm: n/a
  cwe: CWE-306, missing authentication for critical function
  family: one mutation missing from the guard list
  corpus_directory: 04-api-graphql-websocket-cors/
auth_required: none
entry_point: "the stripeCreateIntent GraphQL mutation"
root_cause: >
  The mutation performs a billing action against any tenant's Stripe subscription and no
  authentication runs before it. The advisory text, quoted: unauthenticated remote attackers
  can "manipulate any tenant Stripe subscription via the stripeCreateIntent GraphQL mutation".
  The missing decision is an authentication check on this one resolver. In a GraphQL API every
  mutation is its own entry point behind one URL, so a guard applied per resolver has as many
  chances to be forgotten as there are resolvers, and forgetting one is invisible from the
  outside of the schema.
signal: >
  A single URL hiding many operations. That is the shape that makes per operation guards go
  missing: a route table shows you every route on one screen, a GraphQL schema does not show
  you which resolvers are guarded. The specific signal here is a mutation whose name contains
  a payment provider, because those are usually added later, by whoever was integrating the
  provider, and often sit outside the module the authorisation work was done in. Second
  signal: a tenant identifier accepted as a mutation argument rather than derived from the
  session.
safe_proof: >
  Lab instance only, with a Stripe test mode key that belongs to the lab. Send the mutation
  with no credential at all and take the response shape as the canary: a validation error
  naming a required argument proves the resolver ran, which is the finding, whereas an
  authentication error proves it did not. Stop there. Do not create an intent, do not modify a
  subscription, and never point this at a live billing account under any circumstances.
controls: >
  Negative control: send a mutation name that does not exist. That must produce a schema error
  rather than a validation error, which is how you tell "the resolver ran and disliked my
  arguments" from "GraphQL disliked my query". Differential control: send a mutation you know
  is guarded and confirm it returns an authentication error, which proves a guard exists in
  the product and this one resolver is missing it. Without that second control you may be
  looking at an instance with authentication turned off entirely.
fix:
  commit_url: "___, none named"
  invariant: "___, no fixed release and no diff. This entry documents a defect whose remediation state is unknown"
hardening: >
  Deny by default at the schema boundary, not at the resolver. One piece of middleware that
  refuses every mutation unless it appears on an explicit allow list of public operations.
  That inverts the failure mode: forgetting to annotate a resolver makes it inaccessible
  rather than making it public, and a broken deployment is a support ticket while a public
  billing mutation is an incident.
detection: >
  POST bodies naming a billing mutation with no Authorization header or session cookie.
  Stripe side, payment intents created with no corresponding application audit record. That
  second one is the reliable signal, because it does not depend on the application logging
  something the application does not know went wrong.
variant_rule: >
  Enumerate the guard, not the schema. Get the list of every mutation, from introspection if
  it is on and from the client side JavaScript bundle if it is not, then check each one for a
  guard rather than sampling. The bugs live in the ones added last: payment, webhook,
  export, admin tooling, impersonation, and anything added during an integration sprint. The
  same shape appears outside GraphQL wherever many operations share a URL: JSON-RPC method
  names, a single dispatcher endpoint taking an action parameter, WordPress admin-ajax
  actions, and Rails routes declared outside the authenticated block.
lab:
  install: "chaskiq at the vulnerable commit in docker, with Stripe test mode keys created for the lab"
  snapshot: "compose snapshot before the first request"
  teardown: "remove the containers, the database volume and the Stripe test keys"
provenance:
  source: "https://github.com/advisories/GHSA-8wp4-ghqw-4g3h"
  accessed: 2026-08-16
  license_note: >
    GitHub advisory, marked Unreviewed, which means GitHub has not verified the affected
    ranges. Detail is thin and this entry says so rather than filling the gaps
```

## What happens

Chaskiq exposes a GraphQL mutation called `stripeCreateIntent`. It changes a customer's billing.

It has no authentication on it. Anyone who can reach the GraphQL endpoint can call it, against
any tenant on the installation.

A sibling advisory, `CVE-2026-72535`, was published on the same day for a second missing
authentication issue in the same product. That pairing is the useful part.

## Why it works

In a normal web application every action has its own URL, and the list of URLs is a file you can
read. Miss a guard and it tends to show up, because somebody looks at the route file.

GraphQL puts everything behind one URL. The operations are names inside the request body. There
is no route file to read, and there is no screen anywhere that shows you which resolvers are
guarded and which are not. So a guard that is applied resolver by resolver has one chance to be
forgotten per resolver, and forgetting is invisible.

Payment code is the classic place for it to happen. It gets added later, usually by whoever was
doing the payment integration, often in its own file, and often after whoever set up the
authorisation pattern has moved on.

Two missing authentication findings in one product on one day is not two mistakes. It is one
missing structural control showing up twice.

## How you would reproduce it

In a lab, with test mode keys. Send the mutation with no credentials and look at what comes
back. A complaint about your arguments means the resolver ran, which is the whole finding. An
authentication error means it did not.

Stop at that point. You do not need to actually create a payment intent to show the door is
open, and creating one touches money.

## What the fix is, and why the obvious fix would not work

No fixed release and no commit is named, so this entry records a defect whose remediation state
is unknown. That is recorded honestly rather than assumed.

The obvious fix is to add the missing check to this resolver, and to the one in the sibling
advisory. That fixes two resolvers on a schema that probably has a hundred, using the same
pattern that already failed twice.

The fix that ends it is to invert the default. Refuse everything at the schema boundary, and
keep a short explicit list of operations that are allowed to be public. Then a forgotten
annotation produces a broken feature, which somebody reports on the first day, rather than a
public billing endpoint, which nobody reports at all.

**Two limits on this entry, stated rather than smoothed over.** The advisory is marked
Unreviewed, so GitHub has not checked the affected ranges, and the version fields here are `___`
because there is nothing to put in them. And the CVSS of 8.6 quoted on the advisory page is the
publisher's, not a figure this sweep verified.

Related: WEBDS-0029 and
WEBDS-0030, the other two GraphQL entries from
this run, and WEBDS-0001, a GraphQL authorisation
annotation that was silently not applied, which is the same failure with the guard present but
inert.
