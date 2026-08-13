---
tags: [security, flash, advisories, webds, injection, sql, wildcard, php, phpmyfaq, enumeration]
updated: 2026-08-13
sources:
  - "https://github.com/advisories/GHSA-6pvm-2vjj-rx4w, accessed 2026-08-13"
---

# WEBDS-0024, the escaping was correct and the search still leaked every user

Related: the web advisories folder,
WEBDS-0006, the other SQL escaping entry,
WEBDS-0020, the other enumeration bug today.

```yaml
id: WEBDS-0024
component:
  type: package
  ecosystem: composer
  name: thorsten/phpMyFAQ
  version_scope: "the chat user search API"
affected:
  introduced: ___
  fixed_in: "4.2.0-alpha"
  tested_on: ___
identifiers:
  cve: CVE-2026-47132
  ghsa: GHSA-6pvm-2vjj-rx4w
  osv: ___
  snyk: ___
  vendor_id: ___
class:
  owasp_2025: injection
  owasp_api: "API3, broken object property level authorisation, in effect. The listing returns more than the caller should see"
  owasp_llm: not applicable
  cwe: "CWE-20 improper input validation, CWE-89 SQL injection, CWE-200 information exposure"
  family: metacharacter left live inside a correctly escaped value
  corpus_directory: 06-server-side-injection-file-data/
auth_required: user
entry_point: >
  GET /api/chat/users?q=..., the chat user search. The q parameter reaches
  Chat.php through ChatController.php. Any authenticated account can call it.
root_cause: >
  The code calls escape() on the search term, which correctly neutralises SQL
  string syntax so the term cannot break out of its quotes. It does not escape
  the LIKE metacharacters, % and _, which keep their special meaning inside a
  LIKE clause. The escaped term is then interpolated into the query rather than
  bound as a parameter. The missing decision is: nobody decided that LIKE has a
  second grammar inside the string, with its own metacharacters, which SQL
  escaping does not touch.
signal: >
  Any search box that returns matches rather than exact hits. Type a single
  percent sign. If the result set is everything, the wildcard is live. That test
  takes two seconds and costs nothing, and it is the entire discovery step.
safe_proof: >
  On your own install, call the endpoint with q set to a single %, and count the
  rows returned against the row count for a specific name. The canary is your
  own seeded test accounts appearing in a search that should not have matched
  them. One request. Nothing is modified and no real directory is touched.
controls: >
  Negative control: search for a literal string that matches nothing and confirm
  you get an empty result, so you know the endpoint filters at all. Differential
  control: search for a name fragment that legitimately matches one seeded user
  and confirm you get exactly that one, then search % and confirm you get all of
  them. Third control, and this is the one that separates this bug from real SQL
  injection: send a single quote and confirm the query does not error. If it
  errors, escaping is broken too and you have found a bigger bug that should be
  reported as such.
fix:
  commit_url: "https://github.com/thorsten/phpMyFAQ/commit/bd4b08b012234ccfcff07bfe6518062475b29e0a"
  invariant: "___, commit located but not read as a diff this run"
hardening: >
  Bind the parameter rather than interpolating it, then escape % and _ inside
  the bound value with an explicit ESCAPE clause. Those are two separate jobs and
  both are needed. Then cap the result set and require a minimum term length, so
  even a working wildcard returns a page rather than a directory. Last, ask
  whether the endpoint should list other users at all, which is the question that
  makes the bug not matter.
detection: >
  Search requests whose term is one or two characters and consists only of % or
  _. In the database slow query log, LIKE '%%' patterns. The behavioural
  fingerprint is one account issuing a search that returns the whole user table.
variant_rule: >
  Wherever a value is escaped for one grammar and then enters a second grammar
  nested inside it. LIKE wildcards are the common case: % and _ in SQL, and the
  backslash escape that comes with them. The same shape appears with regular
  expressions built from user input, with glob patterns in file matching, with
  LDAP filter metacharacters * ( ) and \, with XPath, and with the wildcard
  syntax in search engines such as Elasticsearch query strings. The general
  question to ask at every sink: is there a second language living inside the
  string I just escaped.
lab:
  install: "phpMyFAQ container pinned below 4.2.0-alpha, seeded with three throwaway accounts"
  snapshot: "not needed, the endpoint only reads"
  teardown: "drop the container and its database"
provenance:
  source: "GitHub Security Advisory GHSA-6pvm-2vjj-rx4w, reported by @proochicken"
  accessed: 2026-08-13
  license_note: "public advisory, no licence restriction on reading"
```

**A date disagreement, recorded rather than resolved.** The advisory page says
published 2026-08-08, updated 2026-08-12. The GitHub advisory listing sorted by
publication showed it under 2026-08-12, which is presumably the update date. Both
read 2026-08-13.

## What happens

phpMyFAQ has a chat feature with a user search. Type part of a name, get matching
users back. The search term is put into a SQL `LIKE` clause.

Send a single `%` as the search term and you get everybody: user ids, display
names, staff accounts, the shape of the organisation.

## Why it works

This is the interesting part, and it is why the entry is worth writing even
though the impact is modest.

**The escaping worked.** `escape()` did its job. The search term cannot break out
of its quotes, cannot end the string, cannot append another statement. Everything
people mean when they say "we protected against SQL injection" was in place.

The bug is one layer down. Inside a `LIKE` clause, SQL has a second, smaller
language. In that language `%` means "any run of characters" and `_` means "any
one character". Those characters are not dangerous to SQL syntax, so an SQL
escaper has no reason to touch them, and does not.

So the value stayed politely inside its quotes and changed the meaning of the
query anyway.

The rule:

**Escaping protects the outer grammar. If there is a second grammar inside the
string, escaping the outer one does nothing for it.**

## What it is and is not

It is not remote code execution and it is not data modification. What it is, is
enumeration: a directory listing you were not meant to have, from an account that
was only supposed to search for colleagues it already knew.

That matters more on some products than others. On an education platform, a full
list of learner display names and ids from any single learner account is a
privacy problem before it is a security one, and it is the kind of finding a
client understands immediately.

The advisory also records that the query is **not** parameterised, only escaped.
That is a second, separate weakness sitting in the same line of code, and it is
worth saying in a report even though it was not what was exploited.

## How you would reproduce it

Your own install with a few seeded accounts. Call `/api/chat/users?q=x` for a
name fragment and see one result. Call it with `q=%` and see all of them. Then
send a single quote and confirm the query does not error, which is what proves
you are looking at wildcard injection rather than plain SQL injection.

## What the fix is, and why the obvious fix would not work

There is a fix commit, recorded above, not read here.

The obvious fix is to strip `%` and `_` from the term. That works and it quietly
breaks the product: nobody can search for a name containing an underscore, and
underscores are common in usernames. Silent removal also means the search returns
results for a different query than the one typed, which users notice and cannot
explain.

The right repair has two halves and both are needed. Bind the parameter instead
of interpolating it, which fixes the structural weakness. Then escape `%`, `_`
and the escape character itself inside the bound value, and declare it with an
`ESCAPE` clause, so those characters match themselves literally. That keeps
searching for `admin_user` working while making a lone `%` mean a percent sign
and nothing more.
