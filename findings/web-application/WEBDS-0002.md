---
tags: [security, flash, advisories, entry, web, access-control, routing, nuxt]
updated: 2026-08-12
sources:
  - "https://github.com/nuxt/nuxt/security/advisories/GHSA-hxvh-4h3w-prp9 accessed 2026-08-12"
---

# WEBDS-0002: Nuxt drops route rules for mixed case paths, so the auth gate never runs

Related: the sibling payload cache bug,
the web advisories folder.

```yaml
id: WEBDS-0002
component: { type: framework, ecosystem: npm, name: nuxt, version_scope: "the 3.x and 4.x lines" }
affected: { introduced: "4.4.7 and 3.21.7, the releases carrying the incomplete fix for CVE-2026-53721", fixed_in: "4.5.1 and 3.21.10", tested_on: "not tested, desk research only" }
identifiers: { cve: CVE-2026-71315, ghsa: GHSA-hxvh-4h3w-prp9, osv: ___, snyk: ___, vendor_id: "incomplete fix for CVE-2026-53721" }
class: { owasp_2025: "broken access control", owasp_api: ___, owasp_llm: not_applicable, cwe: "CWE-178, CWE-863", family: "routing normalisation disagreement producing an authorisation bypass", corpus_directory: 02-access-control-bac-idor }
auth_required: none
entry_point: "any route whose configured rule key contains an uppercase letter, for example /Admin, /Dashboard/**, or a rule derived from a PascalCase page file"
root_cause: >
  Two halves of one comparison were normalised differently. Nuxt matches route rules case
  insensitively by default, following vue-router. The earlier patch lowercased the incoming
  lookup path. It did not lowercase the compiled route rule keys. So the lookup asks for
  "/admin" while the table still holds "/Admin", the lookup misses, and a missing rule is
  treated as no rule rather than as an error. The missing decision lives in route rule
  compilation, not in the auth middleware, which is why nothing in the auth code looks wrong.
signal: >
  A protected page renders for a logged out client when you change the case of one letter in
  the path. The tell is that /admin redirects and /Admin does not, on a server that otherwise
  treats the two as the same page. Any behaviour difference between two spellings of one
  route is worth a hypothesis.
safe_proof: >
  Request the protected path twice on a lab build, once lowercase and once with one letter
  uppercased, with no session cookie. Compare the status code and whether the protected markup
  is present. Nothing is written and nothing is read that an anonymous user could not already
  ask for.
controls:
  - "Negative control: the same request pair on 4.5.1 or 3.21.10 must behave identically."
  - "Differential control: a route whose rule key is already all lowercase must not differ between spellings. That proves the case of the rule key is the variable, not the path."
  - "False positive to rule out: a CDN or proxy in front that normalises the path itself, which hides the bug in one environment and shows it in another. Test the origin directly."
fix: { commit_url: ___, invariant: "key folding and lookup folding must be symmetric. The patch normalises rule keys at compile time with the same rule applied to the lookup path, and honours router.options.sensitive so a project wanting case sensitive routing gets it on both sides" }
hardening: >
  Never let a failed lookup mean "allow". The control that kills the class is a default deny
  route table: an unmatched path gets the most restrictive rule rather than none. A case
  folding bug then costs a 403, not a data leak.
detection: >
  Access logs showing 200 responses on protected paths with unusual capitalisation and no
  session cookie. There is no payload, so a WAF signature is useless here. The signal is the
  path shape.
variant_rule: >
  The general shape is "two sides of a comparison normalised differently", and it is
  everywhere: case folding, Unicode normalisation, trailing slash, percent decoding, dot
  segment collapsing, and the proxy versus origin disagreement behind cache poisoning.
  Second variant rule, from the fact that this was an incomplete fix: after any normalisation
  patch, check whether both sides were changed or only one.
lab: { install: "nuxi init on a pinned vulnerable version, add a route rule with an uppercase key and an auth middleware behind it", snapshot: "the project directory plus the lockfile", teardown: "delete the directory, nothing persists" }
provenance: { source: "https://github.com/nuxt/nuxt/security/advisories/GHSA-hxvh-4h3w-prp9", accessed: 2026-08-12, license_note: "vendor security advisory, public" }
```

## What happens

Nuxt lets you attach rules to routes: this path needs the auth middleware, that path is
prerendered, this one is client only. The rules live in a lookup table keyed by path. When a
request arrives Nuxt lowercases the path before looking it up, because route matching is case
insensitive by default. Nobody lowercased the keys. A rule written as `/Admin` sits under a
key the lookup can never produce, the lookup returns nothing, and Nuxt carries on as if the
rule was never written. The auth middleware is not bypassed. It is never scheduled.

Rated 8.2. It also drops `appLayout`, client redirect middleware, `ssr: false` and
`prerender` for the same paths, so the blast radius is wider than the auth gate alone.

## Why it works

The failure is silent and it sits on the safe looking side of the code. Nothing throws, the
page renders, and if you test `/admin` you get a redirect and conclude the gate works, because
for that spelling it does. The rule key is often not something anyone typed either: rules
derived from a PascalCase page file get an uppercase key automatically, so a project can carry
this bug without an uppercase path appearing anywhere in the source.

## How you would reproduce it

Build a Nuxt app on an affected version with a rule keyed `/Admin` and an auth middleware
attached. Log out. Request `/admin`, then `/Admin`. One redirects. The other serves the
protected page and its server rendered data.

## What the fix is, and why the obvious fix is not enough

The obvious fix is to rename every route to lowercase. It works, and it is not a fix: it makes
correctness depend on every future developer knowing the rule, and it does not help the rules
Nuxt generates for you. The real fix normalises both sides at compile time. The deeper fix,
security table must never mean "permitted".
