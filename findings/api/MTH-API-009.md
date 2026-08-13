---
tags: [security, flash, advisories, api, method, graphql, api4, alias-amplification]
updated: 2026-08-13
sources:
  - "https://github.com/advisories/GHSA-ph52-67fq-75wj, accessed 2026-08-13"
  - "https://github.com/advisories/GHSA-6q22-g298-grjh, accessed 2026-08-13"
  - "https://github.com/advisories/GHSA-m4gp-5xh5-xhq4, accessed 2026-08-13"
  - "https://github.com/advisories?query=graphql, accessed 2026-08-13"
---

# MTH-API-009: in GraphQL the client writes the workload, so count what the server counts

Related: APIDS-0021,
APIDS-0022,
MTH-API-004, which named aliasing first,
MTH-API-007, the keying method,
the API folder.

## The technique in one line

One GraphQL request is not one unit of anything, so find the unit the server's defences count
and multiply everything else.

## The discovery signal

**A single URL that accepts arbitrary work.** With REST, a route is a rough proxy for an
operation, so per route limits and per request limits and path based edge rules all approximately
work. GraphQL breaks that: every request goes to `/graphql`, and the body decides what happens.

The specific signal for amplification: **the server has limits, and they measure something other
than cost.** Directus had a token limit, so a query could not be too long as text, and a
relational depth limit, so it could not nest too deep. Neither counted how many times a field
was resolved. The advisory says it plainly: the depth limit "applied per alias without reducing
the total number executed". A per item limit with no cap on item count bounds nothing.

The signal for the authorisation half: **a field that returns something derived from a protected
object.** Every resolver enforces its own permissions, so a check on one field is not inherited
by the field beside it.

## The mechanism

Two families, one root cause: the request is a program, and defences written for documents do
not bound programs.

**Amplification by alias.** The specification lets one query name the same field repeatedly under
different labels, and each is resolved independently by default. Ask for one expensive relational
read a hundred times under a hundred labels and the server does it a hundred times, for one
request. Directus CVE-2026-35441, authenticated read only privileges were enough.

The unauthenticated sibling, GHSA-6q22-g298-grjh, is the sharper illustration. Directus exposes a
health check resolver that runs the database, cache, storage and SMTP checks **on every
invocation**. No login required. Aliasing turns one request into hundreds of full infrastructure
checks. **The most expensive resolver in the system was the one that needed no authentication**,
which is a coincidence worth looking for on every product: health, status, version and
diagnostics endpoints are built to be reachable and are rarely priced.

Note what does not save you. Rate limiting counts requests and this is one request. Depth limits
count nesting and aliases add none. Token limits count characters and alias names are short.
Every standard defence measures the wrong axis.

**Authorisation by field.** AFFiNE CVE-2026-59262. Documents were access controlled. The
`histories` field, which returns the edit timeline of a document by GUID, never checked
`Doc.Read`. Any workspace member could read the history of any document, getting editor
identities, email addresses and timestamps. The body was protected, the derivative was not.

## Which OWASP API class

Amplification is `API4:2023`, unrestricted resource consumption. Field level authorisation is
`API1:2023` or `API5:2023` depending on whether the missing check is per object or per operation.

Introspection left enabled, which this run did **not** find an instance of, is `API9:2023`,
improper inventory management: it publishes the whole surface.

## Which protocols

GraphQL primarily, and the amplification idea generalises to anything where one request carries
a list of work: batch REST endpoints (see
APIDS-0020), JSON-RPC batches, bulk import, and
webhook fan out.

## Whether it reaches Ahmed's surface, and how

**Partly, and the honest answer is less than the other two cards this run.**

* **WPGraphQL** is present in the WordPress ecosystem and there is a live advisory for it,
  CVE-2026-54768, user existence enumeration via a deprecated field. **That is a WordPress plugin
  and belongs to the WordPress sweep** under the 2026-08-12 scope decision. Noted, not written.
* **Whether any fleet site exposes GraphQL at all is `___`.** The ledger's surface table lists
  the WordPress REST API, EduAi's seven routes, Tutor LMS routes, GoHighLevel, WhatsApp, the AI
  providers and Laravel API routes. **No GraphQL endpoint is recorded on the fleet.** So this
  card is currently preparation rather than an active surface, and it should be read that way.
* The transferable half is the reasoning, not the syntax: *what does the server's limit count,
  and what does the client actually control*. That applies to the REST fleet today.

If a GraphQL endpoint is ever found on the fleet, alias amplification applies to it **by
default**, with nobody having made a mistake, because it is a specification feature. That makes
it worth asking about at the point a GraphQL endpoint appears, not after.

## A safe way to test for it

**Amplification, and this is the one where restraint is the skill.** In a lab, on a disposable
instance with capped resources. One alias, ten, twenty. Time each, measured server side. Linear
growth against alias count is the finding.

**Stop at twenty.** The whole proof is the slope. Going to a thousand demonstrates nothing extra
and is a denial of service you chose to perform. Anyone reading the report can extrapolate a
straight line.

**Field level authorisation.** Two accounts, one object only the first can see, a canary inside
it. Query the protected field as the second account. Read only, nothing modified.

**Introspection**, which this run did not reach: send an introspection query and see whether the
schema comes back. Read only and harmless in a lab. In production it is still probing and it
sits behind the authorisation gate.

## The control that catches a false positive

For amplification, the **differential** control decides it. Send twenty aliases in one request,
then twenty separate requests each with one alias. If total server time is the same, there is no
amplification: the server is doing twenty requests worth of work and a normal rate limit covers
it. The finding only exists because the work is bought inside a single request that every per
request control counts as one.

The **negative** control: twenty aliases of a trivial field must stay flat. If it does not, the
cost is in parsing rather than in resolvers, which is a different and smaller finding.

For field level authorisation, the second account must be **refused on the object itself** in the
same session. That is what proves the object was protected and only the derived field was not.
Without it there is no finding, just a user reading something they may well be entitled to.

## Where else this shape appears

Every derived read path around a protected object: history, versions, revisions, audit log,
comments, attachments, previews, thumbnails, exports, share links, activity feeds, search
indexes. Each is a resolver or route somebody wrote later, and each needs the check written again
by hand. This is the same enumeration MTH-API-008 asks for, applied to reads instead of sinks.

**On Ahmed's fleet the read across target is Tutor LMS**, which has submissions, grades,
attempts, certificates and progress records, all derived from an enrolment boundary, all separate
routes, and none ever reviewed. **Four of the nine method cards now point at Tutor LMS.**

## What this card does not cover, named so it is not mistaken for done

**Introspection and query batching remain untouched**, three runs and now four. This card takes
alias amplification and complexity limits, and field level authorisation. It does not take:

* introspection left enabled in production, `API9`;
* batched GraphQL, an array of query documents in one POST, which multiplies again on top of
  aliasing;
* fragment expansion as an amplifier, which is aliasing's quieter relative;
* field level authorisation on **mutations** rather than reads, which is the version that writes.
