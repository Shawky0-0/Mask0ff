---
tags: [security, flash, advisories, api, entry, api4, graphql, alias-amplification, directus]
updated: 2026-08-13
sources:
  - "https://github.com/advisories/GHSA-ph52-67fq-75wj, accessed 2026-08-13"
  - "https://github.com/advisories/GHSA-6q22-g298-grjh, accessed 2026-08-13"
---

# APIDS-0021: one GraphQL request, the same expensive query a thousand times, because aliases are free

**The folder's first genuine `API4` primary, and the first entry on GraphQL query cost.**
Related: MTH-API-009, the method this produced,
MTH-API-004, which named aliasing as a way past
one time flow guards and is now confirmed from a second direction,
APIDS-0024, the other Directus entry.

```yaml
id: APIDS-0021
component:
  type: framework
  ecosystem: npm
  name: directus
  version_scope: "< 11.17.0"
affected:
  introduced: ___
  fixed_in: 11.17.0
  tested_on: not tested, reading only
identifiers:
  cve: CVE-2026-35441
  ghsa: GHSA-ph52-67fq-75wj
  sibling_ghsa: GHSA-6q22-g298-grjh, no CVE assigned, the unauthenticated variant, same fix and
    same fixed version. Documented in this entry rather than given its own number, because one
    patch closes both
  osv: ___
  vendor_id: ___
class:
  owasp_api: API4:2023 unrestricted resource consumption
  owasp_2025: ___
  cwe: CWE-400, CWE-770
  family: request multiplier, where one request buys many units of server work
protocol: graphql
auth_required: >
  user for CVE-2026-35441, read only authenticated is enough. **none for the sibling
  GHSA-6q22-g298-grjh**, which reaches the health check resolver on the system endpoint with no
  authentication at all
entry_point:
  routes: /graphql and /graphql/system
  parameter: GraphQL aliases in the query document
  resolvers: any expensive relational read for the authenticated variant. The health check
    resolver for the unauthenticated variant, which runs the database, cache, storage and SMTP
    checks on every single invocation
object_graph:
  creates_the_object: not an object access bug. The unit being consumed is server work, not data
  owns_it: the deployment's CPU, memory, database connection pool and I/O
  should_reach_it: a caller should be able to buy work roughly in proportion to what they ask for
  tested_account_got: work multiplied by the alias count, from a single request of ordinary size
root_cause: >
  Two missing decisions, and the second is the interesting one. First, no resolver
  deduplication: the GraphQL specification lets one query name the same field many times using
  aliases, and "each alias resolved independently by default", so Directus executed each one.
  Second, the limits that did exist were counting the wrong unit. The advisory is precise:
  "the existing token limit on GraphQL queries still permitted enough aliases for significant
  resource exhaustion, while the relational depth limit applied per alias without reducing the
  total number executed." A depth limit per alias multiplied by unlimited aliases is not a
  limit. Rate limiting is also off by default, so nothing else caught it.
signal: >
  A single endpoint where the client writes the shape of the work. Ask what the server's cost
  is proportional to, and what the limit is proportional to. When those two answers differ, the
  gap between them is the multiplier. Aliases are the cleanest example because they are pure
  repetition with no depth and no nesting, so every depth based defence walks straight past them.
safe_proof: >
  Lab only, and this one needs care because the safe proof is the smallest one that shows the
  slope, not the one that takes the server down. Disposable Directus below 11.17.0. Send a query
  with one alias and record the response time. Send the same query with ten. Then twenty. Plot
  the three points. **Linear growth in server time against alias count is the entire finding,**
  and it is proven at twenty. Going to a thousand proves nothing further and is a denial of
  service you performed on purpose.
controls:
  negative: >
    send twenty aliases of a trivial field with no relational work. Time should stay flat. If it
    grows, the cost is coming from parsing rather than from the resolver, which is a different
    and much less serious finding
  differential: >
    send twenty separate HTTP requests each carrying one alias. If the total server time is the
    same, the server is not being amplified, it is just doing twenty requests worth of work and
    a normal rate limit would cover it. The finding depends on the work being bought inside one
    request that any per request control counts as one
  attribution: >
    measure server side, not by wall clock at the client. Network variance at twenty requests is
    easily mistaken for server load
fix:
  commit_url: ___ (advisory references the Directus repository, specific commit not opened)
  invariant: >
    Stated by the advisory: "a request-scoped resolver deduplication mechanism was introduced
    and applied broadly across all GraphQL read resolvers, both system and items endpoints",
    such that identical resolver calls with matching arguments execute once per request and
    later aliases reuse the cached result. The invariant: within one request, identical work is
    performed once.
hardening: >
  Deduplication fixes repetition. It does not fix cost generally, because a thousand *different*
  expensive queries in one document are all distinct and all execute. The control that kills the
  class is a query cost budget: assign each field a weight, sum the document before executing
  anything, and refuse over budget. Note the ordering requirement, the same one behind
  APIDS-0006: the budget has to be computed and enforced before the work starts, not while it
  runs.
detection: >
  POST bodies to a GraphQL endpoint containing many aliases of one field name. In practice, an
  unusual ratio of response time to request size. An edge rule that counts requests sees one
  request and reports nothing, which is the point.
variant_rule: >
  Every GraphQL endpoint, since aliasing is a specification feature and not a Directus bug.
  Also: batched GraphQL, where an array of queries arrives in one POST, and fragment expansion.
  Beyond GraphQL, any endpoint accepting a list of work items in one request, which is the
  same multiplier in a different syntax and connects to APIDS-0020.
  **Ahmed's fleet: WPGraphQL is a WordPress plugin and belongs to the WordPress sweep, but if
  any fleet site exposes GraphQL, alias amplification applies to it by default and is not
  something the plugin has to have got wrong.**
lab:
  install: disposable Directus below 11.17.0, isolated, resources capped so a mistake cannot
    escape the container
  snapshot: before
  teardown: destroy
provenance:
  source: https://github.com/advisories/GHSA-ph52-67fq-75wj and
    https://github.com/advisories/GHSA-6q22-g298-grjh
  accessed: 2026-08-13
  license_note: short quoted fragments for the technical description only
  credit: CVE-2026-35441 reported by liyander. GHSA-6q22-g298-grjh reported by bugbunny.ai
```

## What happens

GraphQL lets you ask for the same field more than once in one query by giving each copy a
different label. That is called an alias, and it is a normal, documented feature.

The server, by default, treats each labelled copy as a separate job. Ask for one expensive
thing a hundred times under a hundred labels, and the server does the expensive thing a hundred
times, for one request.

Directus had limits. It capped how many tokens a query could contain, and it capped how deep the
relations could go. Neither one counted the thing that was growing.

The unauthenticated version is worse in a specific way. The system endpoint exposes a health
check resolver, and every call to it tests the database, the cache, the storage and the SMTP
server. No login needed. Aliased a few hundred times, one request makes the server run several
hundred full infrastructure checks.

## Why it works

Because the two limits were measuring the wrong quantity.

The token limit says your query cannot be too long as text. Aliases are short. You fit plenty.

The depth limit says your query cannot nest too deeply. It applied per alias. So each of your
hundred aliases obeyed the depth limit individually, and the total was a hundred times the
allowance. A per item limit with no cap on item count does not bound anything.

And rate limiting, which would have caught someone sending a hundred requests, is off by
default and would not have helped anyway, because this is one request.

## How you would reproduce it

One alias, ten aliases, twenty aliases. Time each. If the line goes up straight, you are done.

**Stop at twenty.** The temptation with a resource exhaustion bug is to prove it by exhausting
the resource, and that is not a proof, it is an outage you caused. The slope is the finding.
Anyone reading the report can extrapolate, and nobody needs you to have done it.

## What the fix is, and why the obvious fix would not work

The obvious fix is to lower the token limit so fewer aliases fit. It buys a small constant
factor and loses legitimate queries. The attacker just uses shorter alias names.

The next obvious fix is to cap the number of aliases. Better, and still counting the wrong
thing, because ten aliases on a cheap field and ten on a catastrophically expensive one are the
same number and nothing like the same cost.

Directus deduplicates identical resolver calls within a request, which is a clean fix for
repetition specifically. The general answer is a cost budget: price each field, add up the
document, refuse it before running any of it. That is the only control that survives an
attacker who varies their queries instead of repeating them.

## What this closes

GraphQL depth, meaning introspection, batching, alias abuse and complexity limits, has been
listed as untouched in the ledger for **three consecutive runs**. This entry takes alias abuse
and complexity limits. Introspection and batching remain untouched, and
MTH-API-009 carries them forward as named
targets rather than as a vague gap.
