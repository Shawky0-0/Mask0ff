---
tags: [security, flash, advisories, appsec, graphql, api, information-disclosure, webds]
updated: 2026-08-16
sources:
  - "https://api.osv.dev/v1/vulns/CVE-2026-66008, accessed 2026-08-16"
  - "https://github.com/advisories?query=graphql, accessed 2026-08-16"
---

# WEBDS-0030: Parse Server turns introspection off and the error messages answer anyway

```yaml
id: WEBDS-0030
component:
  type: framework
  ecosystem: npm
  name: parse-server
  version_scope: "the GraphQL API, validation and input coercion error paths, when public schema introspection is disabled"
affected:
  introduced: "8.2.2 on the 8 branch, 9.0.0 on the 9 branch"
  fixed_in: "8.6.87 and 9.10.0-alpha.6"
  tested_on: "___, not installed by this sweep"
identifiers:
  cve: CVE-2026-66008
  ghsa: GHSA-r2g6-4f6j-f6rf
  osv: CVE-2026-66008
  snyk: ___
  vendor_id: ___
class:
  owasp_2025: "security misconfiguration, and information disclosure"
  owasp_api: "API3, broken object property level authorization, reached through metadata"
  owasp_llm: n/a
  cwe: CWE-209, information exposure through an error message
  family: schema disclosure through a side channel
  corpus_directory: 04-api-graphql-websocket-cors/
auth_required: none
entry_point: "the GraphQL endpoint, with only the public application id, sending queries that reference Pointer or Relation fields"
root_cause: >
  Turning introspection off removes one way of reading the schema and leaves the validator
  and the input coercer talking. Per the OSV record, the validation and input coercion error
  messages name the target class of a Pointer or a Relation field. The missing decision is
  that the error path was never treated as an output channel subject to the same
  authorisation as the query result. Someone decided who may read the schema, then wrote
  errors that describe the schema, and never connected the two.
signal: >
  Any control described as "hiding" something rather than denying access to it. Hiding is a
  claim about one route; the question is always how many routes there are. For GraphQL
  specifically: introspection disabled is a strong invitation, because it is usually the
  only schema control a team applies and it is the only one they test. Send a deliberately
  wrong query and read what the error tells you that the schema would have.
safe_proof: >
  Lab instance only. Send a query naming a field that exists with an argument of the wrong
  type, and record the error text. The canary is a class name in the error that does not
  appear anywhere in your query. Compare against a run with introspection enabled, where
  the same name is available legitimately, to show the error is reproducing schema data.
  Nothing needs to be written and no object data is touched.
controls: >
  Negative control: a query for a field that genuinely does not exist, which should produce
  an error naming nothing. If both cases leak a name, the leak is broader than the advisory
  describes. Differential control: run the same query against a patched build at 8.6.87 and
  diff the error strings, so you are measuring the change rather than guessing. False
  positive to rule out: many deployments run a development configuration that returns
  verbose errors by default, so confirm the instance has introspection actually disabled
  before calling anything a bypass.
fix:
  commit_url: "___, no commit was located this run. The advisory page github.com/parse-community/parse-server/security/advisories/GHSA-r2g6-4f6j-f6rf was not opened"
  invariant: "___, not read"
hardening: >
  Errors returned to an unauthenticated caller should be a fixed small set of strings chosen
  in advance, with the detailed version written to the log and referenced by an id. That one
  rule closes this class everywhere, not just in GraphQL, and it costs nothing operationally
  because the detail still exists where the developers can read it.
detection: >
  A burst of malformed GraphQL requests from one client with a high error rate and no
  successful queries. That pattern is enumeration and it looks nothing like normal use, where
  errors are rare and interleaved with successes.
variant_rule: >
  Every side channel that answers a question the main channel refuses. Login forms that say
  "no such user" versus "wrong password". Password reset that confirms an address exists.
  Response timing that differs between a missing record and a forbidden one. HTTP status
  codes: a 403 where a 404 was intended tells you the object is real. And in GraphQL
  specifically: field suggestion messages ("Did you mean ...?"), which rebuild a schema one
  typo at a time even with introspection off.
lab:
  install: "parse-server 9.0.0 in docker with introspection disabled in the GraphQL configuration"
  snapshot: "container snapshot before the first query"
  teardown: "remove the container and its database volume"
provenance:
  source: "https://api.osv.dev/v1/vulns/CVE-2026-66008"
  accessed: 2026-08-16
  license_note: "OSV record, open data, read only"
```

## What happens

GraphQL has a built in way to ask a server what its schema looks like, called introspection.
Teams that do not want the world reading their schema turn it off.

Parse Server lets you turn it off. But when you send a query that touches a Pointer or a
Relation field and get it slightly wrong, the error message names the class that field points at.
So you can rebuild the hidden part of the schema out of error messages, with nothing but the
public application id.

No object data leaks. Only the map.

## Why it works

Turning introspection off is a control on one door. The schema is not secret to the server; it is
just not published on that route. Every other route that has to talk about the schema, in order
to explain what you did wrong, still knows all of it.

The validator has to say what type it expected. The input coercer has to say what it could not
convert. Both of those sentences contain schema facts, by necessity. Nobody wrote them as a
disclosure; they wrote them as help for a developer, back when the schema was public anyway.

That is the general shape and it is worth naming: **a control that hides a thing from one route
does not make the thing secret.** Secrecy is a property of the data, and it has to be enforced
everywhere the data can be spoken about, including in apologies.

## How you would reproduce it

Ask for a Pointer field with a wrong argument type. Read the error. If it names a class you never
mentioned, the error is quoting the schema at you.

Do the control too: ask for a field that genuinely does not exist. That error should tell you
nothing. If it does tell you something, the problem is bigger than the advisory says.

## What the fix is, and why the obvious fix would not work

The patch was not read, so the invariant is `___` and recorded as debt.

The obvious fix is to edit those two error strings so they stop naming the class. That is a
patch for the reported route and not for the class. The next release adds a new resolver with a
new error message and the same fact escapes again, because nothing in the codebase says
"error text going to an unauthenticated caller is public output".

The rule that ends it is structural: unauthenticated callers get a short fixed list of errors
and a reference id. Everything else goes in the log.

Worth noting how small this finding looks and how useful it is. CVSS 4.0 rates it 4.0, low
confidentiality impact, no data touched. But a schema is a target map, and every later attack
against this server is cheaper because of it. Severity scores measure the single bug. They do
not measure what the bug buys.

Related: WEBDS-0029, the other GraphQL entry from
this run, and WEBDS-0009, API Platform accepting a
relation pointing at the wrong resource type, which is the same Pointer and Relation machinery
failing in the other direction.
