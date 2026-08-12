---
tags: [security, flash, advisories, entry, web, ssti, rce, nuxt]
updated: 2026-08-12
sources:
  - "https://github.com/nuxt/nuxt/security/advisories/GHSA-9473-5f9j-94wq accessed 2026-08-12"
---

# WEBDS-0004: Nuxt server islands accept a template key in props, and the runtime compiler executes it

Related: the Nuxt routing bug,
the web advisories folder.

```yaml
id: WEBDS-0004
component: { type: framework, ecosystem: npm, name: nuxt, version_scope: "3.x from 3.4.0, and all 4.x before the fix" }
affected: { introduced: "3.4.0", fixed_in: "3.21.10 and 4.5.1", tested_on: "not tested, desk research only" }
identifiers: { cve: CVE-2026-71320, ghsa: GHSA-9473-5f9j-94wq, osv: ___, snyk: ___, vendor_id: ___ }
class: { owasp_2025: "injection", owasp_api: ___, owasp_llm: not_applicable, cwe: "___, the advisory does not state one. Server side template injection, CWE-1336 is the usual mapping", family: "server side template injection through a prop that reaches a dynamic component", corpus_directory: 06-server-side-injection-file-data }
auth_required: none
entry_point: "POST or GET to /__nuxt_island/<component>_<hash>, with a props object carrying a template key, for example {\"as\": {\"template\": \"<payload>\"}}"
root_cause: >
  Props arriving from the network were passed into Vue's dynamic component resolution without
  being constrained to a component name. Vue treats an object with a template key as a
  component definition, so the runtime compiler compiles and runs it. The missing decision is
  a type and shape check between the island prop deserialiser and the dynamic component sink,
  which are component :is, resolveDynamicComponent, h, and polymorphic as or asChild props.
  Two things have to be true for it to fire: vue.runtimeCompiler must be true, which is not
  the default, and some island component must forward props into one of those sinks.
signal: >
  Any endpoint that takes structured data from the network and hands it to something that can
  resolve a name into code. The specific tell here is a polymorphic prop, the as or asChild
  pattern popular in component libraries such as @nuxt/ui, because undeclared props fall
  through into it without the component author ever writing the forwarding by hand.
  Second signal: the island URL hash is a deterministic unsalted content hash, so it is
  computable rather than secret, and an attacker does not need to be shown the endpoint.
safe_proof: >
  In a lab with the runtime compiler on, send a props object whose template renders a fixed
  canary string, for example a template that outputs the literal WEBDS0004CANARY. Confirm the
  string appears in the response body. That proves compilation of attacker controlled template
  text without executing anything that touches the filesystem, the network, or any data.
controls:
  - "Negative control: send the same props with vue.runtimeCompiler false. It must not compile, which proves the compiler flag is the precondition."
  - "False positive to rule out: the canary appearing because it was echoed rather than evaluated. Make the canary the result of an expression, so plain reflection cannot produce it."
fix: { commit_url: ___, invariant: "island props must not be usable as a component definition. The value reaching a dynamic component sink has to be constrained to a resolvable component name rather than an arbitrary object" }
hardening: >
  Leave vue.runtimeCompiler off, which is the default and removes the sink entirely. Beyond
  this framework: never let network data supply the thing that decides which code runs, only
  which of a fixed known set runs. An allow list of component names kills the class regardless
  of the framework.
detection: >
  Requests to /__nuxt_island/ carrying template or render keys in the props. That is a clean
  signature and the advisory itself suggests a WAF rule on it as a stopgap. In application
  logs, look for island renders whose component resolution came from a value rather than a
  name.
variant_rule: >
  The shape is "attacker data reaches a code resolution point". Look for it in every dynamic
  dispatch: Vue component :is, React createElement with a variable type, PHP variable
  functions and class names, Python getattr on request data, Laravel's dynamic view name in
  view($request->input('page')), and any template engine that will render a string handed to
  it at runtime. Second variant: any endpoint whose obscurity depends on a hash, since a
  content hash without a secret salt is derivable and not a control.
lab: { install: "nuxi init on an affected version, set vue.runtimeCompiler true, add a server island component that forwards props to a polymorphic as prop", snapshot: "project directory plus lockfile", teardown: "delete the directory" }
provenance: { source: "https://github.com/nuxt/nuxt/security/advisories/GHSA-9473-5f9j-94wq", accessed: 2026-08-12, license_note: "vendor security advisory, public" }
```

## What happens

Server islands are a Nuxt feature for rendering one component on the server on demand, with
its props sent in the request. Vue is flexible about what counts as a component: a name, or an
object that describes one. An object with a `template` key is a description, and when the
runtime compiler is enabled Vue will compile that template and run it. Nothing between the
network and that point checked that the prop was a name. So a prop of
`{"as": {"template": "..."}}` becomes running code inside the Nitro server process. Rated 8.1.

## Why it works

feature. Component libraries forwarding undeclared props into a polymorphic `as` prop is a
convenience. Neither is a bug on its own. The vulnerability is in the gap between them, which
is why neither codebase looks wrong when you read it in isolation, and why the fix has to sit
at the boundary rather than in either component.

The URL hash deserves its own note. It looks like a secret and it is not: it is a deterministic
content hash with no salt, so anyone with the component source can compute it. Treating a
derivable value as an access control is a mistake worth recognising on its own.

## How you would reproduce it

Lab only, and the runtime compiler has to be switched on, which is not the default and is the
reason this is 8.1 rather than a 10. Build an island component that passes its props through
to a polymorphic component. Post props containing a `template` that renders a canary. The
canary comes back in the response.

## What the fix is, and why the obvious fix is not enough

The obvious fix is a WAF rule blocking `template` and `render` keys on the island endpoint, and
the advisory does offer it as a stopgap. It is a stopgap because it is a deny list on encodings
you thought of: a deny list on JSON keys has to survive alternate encodings, nesting, and
whatever the next Vue release decides is a valid component definition. The invariant is on the
other side: constrain what reaches the sink to a known set of names.
