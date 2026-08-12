---
tags: [security, flash, advisories, entry, apids, api, laravel, oauth, authentication]
updated: 2026-08-12
sources:
  - "https://github.com/advisories/GHSA-349c-2h2f-mxf6 accessed 2026-08-12"
  - "https://www.sentinelone.com/vulnerability-database/cve-2026-39976/ accessed 2026-08-12"
  - "https://security.snyk.io/vuln/SNYK-PHP-LARAVELPASSPORT-15965921 accessed 2026-08-12"
---

# APIDS-0004: Laravel Passport resolves a client credentials token into a real user account

the API folder, the ledger,
MTH-API-001, the object graph.

```yaml
id: APIDS-0004
component:
  type: library
  ecosystem: composer
  name: laravel/passport
  version_scope: "the token guard, when the client_credentials grant is enabled"
affected:
  introduced: "13.0.0"
  fixed_in: "13.7.1"
  tested_on: "___ , not reproduced. Reading only."
  affected_ranges: ">= 13.0.0, < 13.7.1"
identifiers:
  cve: CVE-2026-39976
  ghsa: GHSA-349c-2h2f-mxf6
  osv: ___
  vendor_id: ___
class:
  owasp_api: "API2:2023 broken authentication"
  owasp_2025: "A07 identification and authentication failures"
  cwe: "CWE-287 improper authentication"
  family: identifier namespace collision across two kinds of principal
protocol: rest
auth_required: >
  A valid client_credentials token. That is machine to machine credentials, which a partner
  integration or any component holding a client secret would legitimately have.
entry_point:
  route: "any route behind the Passport token guard"
  method: any
  parameter: n/a
  header: "Authorization: Bearer, carrying a client_credentials token"
object_graph:
  which_request_creates_the_object: >
    A client_credentials grant request creates the token. There is no user in that flow at
    all, which is exactly the point: the token represents a machine, not a person.
  who_owns_it: "the OAuth client. The token is client bound, not user bound."
  who_should_reach_it: >
    Only client scoped resources. A machine token should resolve to no user, and any code
    asking "who is the authenticated user" should get nothing.
  what_the_tested_account_got: >
    The token resolved to a real user account: whichever user's primary key happened to equal
    the client identifier. That user's privileges then applied to the request.
root_cause:
  where: "the Passport token guard, where it resolves the authenticated entity from the JWT"
  the_missing_decision: >
    The league/oauth2-server library sets the JWT sub claim to the client identifier when
    there is no user, which is correct for that flow. The token guard then passes that value
    straight to retrieveById() without first asking whether the token is user bound or client
    bound. Two different namespaces, users and clients, are read through one lookup. The
    missing decision is to branch on the kind of principal before resolving it, and to resolve
    a client token to no user at all.
  aggravating_condition: >
    Passport::$clientUuids set to false, so client IDs are sequential integers and collide
    with real user IDs. With UUIDs the collision is not practically reachable.
signal: >
  In code review the signal is a single lookup serving two identifier namespaces, with the
  discriminator dropped somewhere upstream. Ask of any auth guard: can two different kinds of
  principal produce the same sub claim, and does anything downstream tell them apart. In black
  box testing the signal is a machine to machine token that returns a populated user object
  from a "who am I" route.
safe_proof: >
  Read only in this sweep. In a disposable lab: issue a client_credentials token for a client
  whose integer ID matches an existing low value test user, then call a route that echoes the
  authenticated user identity. The proof is that a user is returned at all. Read only, no
  writes, no privileged action needed to demonstrate it.
controls:
  negative: >
    Issue a client_credentials token for a client whose ID matches no user. If a user is still
    returned, the finding is something else and needs re examining.
  differential: >
    The same test with Passport::$clientUuids set to true, where the collision should not be
    reachable, and again on 13.7.1.
  false_positive: >
    The big one: an application that deliberately maps machine clients to service user
    accounts. That is a real and common design, and there "a client token resolved to a user"
    is the intended behaviour, not a finding. Confirm from the application's own configuration
    that no such mapping was configured before claiming anything. This is the T1 question, what
    the product actually promises.
fix:
  commit_url: "___ , not reached this run"
  invariant: >
    Do not resolve a sub claim to a user unless the token is user bound. Stated from the
    advisory's root cause description rather than from the patch, which this sweep did not
    read.
hardening: >
  Two controls, and the second is the one that kills the class. First, keep client and user
  identifiers in namespaces that cannot collide, which is what clientUuids does. Second, and
  more general: never let one lookup serve two kinds of principal. Carry the principal type
  with the token and branch on it before any resolution, so a collision is not merely unlikely
  but meaningless.
detection: >
  Requests authenticated by a client_credentials token that then perform user scoped actions.
  In application logs, a token whose client identifier and resolved user identifier are equal
  is the direct signature.
variant_rule: >
  Any OAuth or token implementation where the subject claim carries more than one kind of
  identity: service accounts versus users, tenants versus users, impersonation tokens,
  delegated access tokens. Also worth checking wherever an application has both API keys and
  user sessions resolving through a shared guard.
lab:
  snapshot: "not required, the proof is read only"
  teardown: "delete the install"
provenance:
  source: "GitHub Security Advisory, SentinelOne vulnerability database, Snyk"
  accessed: 2026-08-12
  license_note: "summarised from public advisory text"
```

## What happens

OAuth has a grant type for machines talking to machines, called `client_credentials`. There is
no user in it. A background job, a partner integration or a CRM connector asks for a token
using a client ID and secret, and gets a token that represents the client.

The token's `sub` claim has to hold something, and the underlying OAuth library puts the client
identifier there, which is reasonable because there is no user to name. Passport's token guard
then takes whatever is in `sub` and looks it up in the users table.

If a user exists whose ID matches that number, that user is returned, and the request proceeds
authenticated as that person.

## Why it works

Two separate lists of things, clients and users, are numbered from the same counter and read
through the same lookup. Nothing in between records which list the number came from.

By default Passport can be configured to use UUIDs for clients, which makes the collision
practically impossible. The advisory calls out `Passport::$clientUuids` being `false` as the
condition that makes this reachable, because then client IDs are small sequential integers and
so are user IDs. Client 3 finds user 3.

Note what the attacker does not need. No token forgery, no signature bypass, no stolen user
credential. A legitimately issued machine token is enough, which means the people positioned to
exploit it are integration partners and anyone who has obtained a client secret.

## How you would reproduce it

In a lab. Create a client whose integer ID matches an existing test user. Request a token
through the `client_credentials` grant. Call a route that reports the authenticated identity.
On an affected version it reports the user.

The proof needs nothing privileged, so there is no reason to go further than the identity
echo.

## What the fix is, and why the obvious fix would not work

Upgrade to 13.7.1. The stated interim workaround is to disallow the `client_credentials` grant
entirely.

The obvious fix is to turn on `clientUuids` so the identifier spaces stop overlapping. That
does stop this becoming reachable, and it is worth doing, but it is a probability fix rather
than a correctness fix. The lookup still cannot tell a client from a user; it is only being fed
values that happen not to collide. Any future code path that puts a different identifier into
`sub`, or any migration that reintroduces integer client IDs, brings it straight back. The
correctness fix is that a client bound token must resolve to no user, decided before the
lookup rather than avoided by the numbering.
