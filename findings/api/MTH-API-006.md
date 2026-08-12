---
tags: [security, flash, advisories, api, method, api5, api8, validate, preview, ai]
updated: 2026-08-12
sources:
  - "https://www.resecurity.com/blog/article/exploiting-langflows-validatecode-endpoint-for-remote-code-execution, accessed 2026-08-12"
  - "https://labs.cloudsecurityalliance.org/research/csa-research-note-litellm-cve-2026-42271-ai-gateway-exploita/, accessed 2026-08-12"
---

# MTH-API-006: the endpoints that promise to do nothing are the ones with no check

**Extracted from two independent KEV listed AI tooling cases in the same run**, which is the
repetition signal worth acting on. Related:
APIDS-0011,
APIDS-0014,
the API folder.

## The technique in one line

Enumerate every route whose name promises it has no effect, then check whether anybody guarded
it, because the name is usually why nobody did.

## The discovery signal

**A route named after a non action.** `validate`, `check`, `verify`, `lint`, `parse`, `preview`,
`render`, `test`, `dry-run`, `simulate`, `estimate`, `probe`, `health`.

The signal is the name itself, and the reason it works is a chain of reasoning that happens in
almost every team:

1. This endpoint does not change anything.
2. Therefore there is nothing to protect.
3. Therefore it does not need an authorisation check.

Step 1 is the assumption, and it is usually false. The name describes the **intent** of the
feature. It does not describe what the code does to satisfy that intent.

* To validate code, Langflow ran it.
* To test a connection, LiteLLM started a process.
* To preview a template, a renderer evaluates the template.
* To estimate a cost, a system may query the very data it is meant to be protecting.

The gap between "what this endpoint is for" and "what this endpoint does in order to be for
that" is where the class lives.

**A second, sharper signal:** a request body that names a *capability* rather than *data*. A
field called `command`, `args`, `env`, `code`, `template`, `expression`, `query`, `url` or
`callback` is not data being submitted for storage, it is an instruction. Any route accepting
one of those, under a name that sounds harmless, deserves the check.

## The mechanism

There are two distinct failures and they are worth keeping apart, because the fixes differ.

**One: the operation is stronger than the name.** Langflow's validation called `exec()` on
submitted function definitions. Python evaluates default argument expressions and decorators at
definition time, so `exec()` on a definition runs the attacker's expression immediately, without
anything ever calling the function. Validation and execution were the same operation. Nobody
wrote an eval at a call site, and nobody had to.

**Two: the caller is broader than intended.** LiteLLM's MCP test routes were written for the
administrator configuring an integration, and were reachable by any authenticated caller. The
feature was correct. The set of people who could invoke it was not.

Both cases had a third ingredient that made them critical rather than awkward, and it is the
same ingredient in both: a convenience left reachable. Langflow's `/api/v1/auto_login` exists so
local development skips the login screen, and it was never bound to loopback, so it minted a
SUPERUSER token for anybody who could reach the port. LiteLLM's route sat behind an
authentication layer that had its own Host header bypass.

**That is the pattern to carry away.** A harmless sounding route with a missing check is a
finding. A harmless sounding route with a missing check, plus a development convenience that was
never restricted to the developer's machine, is a critical one. Both KEV listed cases in this
run had exactly that shape.

## Which OWASP API class

`API5` broken function level authorisation, primary in both cases: a function reachable by
callers who should not reach it. `API8` security misconfiguration, secondary, for the
development convenience left enabled and unbound. `API9` improper inventory management where the
route is undocumented, which these frequently are, because a route built for the product's own
front end rarely appears in the published API surface.

## Which protocols

REST most obviously. GraphQL has its own version in field resolvers that perform side effects
while being reachable through queries rather than mutations, and in introspection, which is
itself a "this only describes things" feature. Also applies to admin panels of every kind and to
gRPC reflection.

## Transferability to web and API targets

**Apply this by shape rather than by product.** Establish the target's actual components before
testing, then prioritize:

* **LMS and CMS preview routes.** Previewing a lesson, quiz, certificate, email template, or
  enrolment code sounds passive but may render, compile, fetch, or execute.
* **Model-provider integration routes.** A route that tests a provider connection can spend
  money and disclose whether a credential works, whoever calls it.
* **WordPress specifically:** the concrete version of this check is to grep for
  `register_rest_route` and read the `permission_callback` of every route whose name sounds
  passive. `__return_true` on a route called `preview` or `validate` is the exact finding.

## A safe way to test for it

1. **Enumerate first, without sending anything.** Read the source, the route registrations, the
   JavaScript bundle the front end ships. `/wp-json/` lists routes on a WordPress install. This
   step is reading and carries no authorisation question at all.
2. **Sort by name.** Anything passive sounding goes to the top of the list.
3. **For each, read what it actually does** before testing it. If the handler compiles, renders,
   spawns, connects or fetches, the name was a lie and it needs a check.
4. **Prove the authorisation gap, not the payload.** The finding is that the wrong caller reached
   the route. Demonstrate that with the smallest observable effect: a canary marker written to a
   file, a request arriving at a listener you control inside the lab, a distinctive string in a
   response. Never a shell.
5. Lab only, isolated disposable VM, snapshot before, revert after. If the route executes code,
   treat the VM as burned.

## The control that catches a false positive

**Establish who you actually are.** This is the control that matters and it fails constantly.

A lingering session cookie, a browser logged in as administrator in another tab, an API token in
an environment variable, or testing from the host itself when the route is bound to loopback,
will all make a properly guarded route look wide open. Every one of those has produced a wrong
report somewhere.

The control: from the same client, in the same session state, request a route that **must**
reject you. If it rejects you, your anonymity or your low privilege is established and the
passive route's answer means something. If it does not, stop and fix the test rig.

For the loopback case specifically, the differential is physical: call the route from the host,
then from a second machine on the lab network. If only the host works, the binding is correct
and there is no finding.

Second control, for the execution half: submit something syntactically valid but inert and
confirm no marker appears. That separates "the endpoint evaluated my expression" from "the
endpoint parsed my input", which are very different findings.

## Where else this shape appears

* Every "test connection" button in every admin panel: SMTP testers, database connection
  testers, webhook test senders, integration probes. They are written as harmless because from
  the operator's chair they are, and they are privileged because testing a connection means
  making one.
* Import and export previews, report builders, CSV mapping previews.
* Template and expression preview in any CMS, mail builder or rules engine.
* Health and debug endpoints, which are the same reasoning applied to observability, and which
  tend to be the least documented routes in any product.
* Development conveniences generally: auto login, seeded accounts, debug toolbars, verbose error
  pages. Ask of each not "is it disabled in production" but "what happens if somebody reaches it
  anyway, and is it bound to the machine that needs it".

## Provenance

Resecurity's analysis of the Langflow `validate_code()` endpoint and the Cloud Security Alliance
research note on LiteLLM CVE-2026-42271, both accessed 2026-08-12. Two independent sources
reaching the same shape in one run, which is the repetition signal the sweep is told to weight
above all others. No exploit code was reproduced and none was executed.
