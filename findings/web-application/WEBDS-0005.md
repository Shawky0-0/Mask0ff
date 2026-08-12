---
tags: [security, flash, advisories, entry, web, sqli, kev, exploited, metabase]
updated: 2026-08-12
sources:
  - "https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf accessed 2026-08-12"
  - "CISA KEV JSON feed, https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json accessed 2026-08-12"
---

# WEBDS-0005: Metabase, unauthenticated SQL injection on the password reset endpoint, exploited in the wild

**Known exploited.** Added to the CISA KEV catalogue on 2026-08-11. Related:
the CodeIgniter SQL injection,
the web advisories folder.

```yaml
id: WEBDS-0005
component: { type: service, ecosystem: other, name: Metabase, version_scope: "the x.58 through x.63 release branches" }
affected: { introduced: "1.58, when the auth_identity module was refactored", fixed_in: "v58.24, v59.21, v60.17, v61.11, v62.9 and v63.5", tested_on: "not tested, desk research only" }
identifiers: { cve: CVE-2026-72898, ghsa: GHSA-vwf4-m7j8-wcjf, osv: ___, snyk: ___, vendor_id: "Metabase security update, 2026-08" }
class: { owasp_2025: "injection", owasp_api: ___, owasp_llm: not_applicable, cwe: "CWE-89", family: "SQL injection reachable before authentication", corpus_directory: 06-server-side-injection-file-data }
auth_required: none
entry_point: "/api/session/reset_password, the unauthenticated password reset endpoint. The exact injected parameter is ___, the advisory does not name it"
root_cause: >
  Arbitrary SQL reaches the application database from an unauthenticated endpoint, so a value
  from the request is concatenated into a query rather than bound as a parameter. The advisory
  states the flaw was introduced in 1.58 when the auth_identity module was refactored, which
  places the missing decision in that module's query construction. The advisory does not name
  the parameter or show the query, so the precise line is ___ and would have to come from the
  fix diff.
signal: >
  A pre authentication endpoint that has to look something up in a table. Password reset,
  login, signup availability checks, and invitation acceptance all take an attacker controlled
  identifier and query on it before any session exists, which makes them the highest value
  place in any application to look for injection. The Metabase case adds a second signal: the
  bug arrived in a refactor, so a security relevant module that was recently rewritten deserves
  a fresh read rather than trust in the old review.
safe_proof: >
  In a disposable lab instance only. Use a boolean or timing differential on a value that
  touches nothing: submit a condition that is always true and one that is always false and
  compare the responses. Never SELECT real data, never write, never touch the connected data
  warehouse. If a canary is needed, seed a dedicated row in the lab and read only that row.
controls:
  - "Negative control: the same request pair against a patched build, for example v63.5, must not differ."
  - "False positive to rule out: response time differences caused by rate limiting or by the email send path in password reset rather than by the query. Repeat, and vary only the injected clause."
fix: { commit_url: ___, invariant: "the parameter must be bound, not concatenated. The vendor released fixes across six branches simultaneously rather than a single version, which is the tell of a fix applied to shared query construction code" }
hardening: >
  Parameterised queries everywhere, with no exception for the authentication path. The wider
  control for a product like this: an analytics tool holds credentials for every database it
  connects to, so it is a credential store as much as a dashboard, and it should never be
  reachable from the internet without an authenticating proxy in front.
detection: >
  Requests to /api/session/reset_password with SQL syntax in any field, and any burst of
  requests to that endpoint from one source. Post compromise, the advisory's own cleanup list
  is the detection list: unexpected rows in core_session, unrecognised API keys, and new or
  altered administrator accounts.
variant_rule: >
  Look at every unauthenticated endpoint that queries a user table: reset password, forgot
  username, resend verification, check email availability, accept invite, unsubscribe by
  token. Then look at whatever module was most recently refactored. The general rule this
  entry teaches is that the pre authentication surface is small, boring, rarely re reviewed,
  and therefore where the worst bugs live.
lab: { install: "docker run a pinned vulnerable Metabase tag, for example an x.62 build below x.62.9, with an isolated database and no real data sources attached", snapshot: "docker commit the container plus a dump of the application database", teardown: "docker rm the container and drop the database. Never attach a real data source to the lab instance" }
provenance: { source: "https://github.com/metabase/metabase/security/advisories/GHSA-vwf4-m7j8-wcjf and the CISA KEV feed", accessed: 2026-08-12, license_note: "vendor security advisory and a public government catalogue" }
```

## What happens

Metabase is a business intelligence tool: you point it at your databases and it gives people
dashboards. Its password reset endpoint is reachable without logging in, by design, and it
takes a value from the request and looks it up. That value was not bound as a parameter, so an
attacker can add their own SQL to the query. The advisory rates it CVSS 10.0, the maximum,
because the scope changes: from an unauthenticated request you reach administrator access on
the instance, and an administrator of Metabase can read the stored credentials for every
database it connects to.

Attackers were using this before a patch existed. CISA added it on 2026-08-11 and several
companies have publicly disclosed data theft through it.

## Why it works

The pre authentication surface is where injection hurts most and where it gets reviewed least.
Password reset has to accept an identifier from a stranger and go look it up, so the query is
unavoidable and the input is entirely attacker controlled. There is no session to constrain it
and no permission model in the way.

The second reason is the refactor. The advisory says the bug arrived in 1.58 when the
`auth_identity` module was rewritten. Code that was safe stopped being safe without anyone
touching the endpoint, because the safety lived one layer down and the rewrite moved it.

## What the fix is, and why the obvious fix is not enough

The stated workaround is to block `/api/session/reset_password` at the proxy. It buys time and
it breaks password resets, and it only covers the one endpoint anybody has found so far. The
fix is parameter binding, and the fact that six branches shipped fixes at once suggests it was
corrected in shared code rather than at the call site. The hardening that matters more than
either: a tool holding credentials to every production database should not be exposed to the
internet on its own authentication.
