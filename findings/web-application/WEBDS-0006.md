---
tags: [security, flash, advisories, entry, web, sqli, php, codeigniter]
updated: 2026-08-12
sources:
  - "https://github.com/codeigniter4/CodeIgniter4/security/advisories/GHSA-c9w5-rwh3-7pm9 accessed 2026-08-12"
---

# WEBDS-0006: CodeIgniter deleteBatch ignores the escape flag on where() bindings

Related: the Metabase SQL injection,
the other CodeIgniter advisory from the same day.

```yaml
id: WEBDS-0006
component: { type: framework, ecosystem: composer, name: codeigniter4/framework, version_scope: "the 4.x line" }
affected: { introduced: "4.3.0", fixed_in: "4.7.4", tested_on: "not tested, desk research only" }
identifiers: { cve: CVE-2026-63221, ghsa: GHSA-c9w5-rwh3-7pm9, osv: ___, snyk: ___, vendor_id: ___ }
class: { owasp_2025: "injection", owasp_api: ___, owasp_llm: not_applicable, cwe: "CWE-89", family: "SQL injection through one query builder path that skips escaping", corpus_directory: 06-server-side-injection-file-data }
auth_required: "___, depends on the application. Any route that reaches a deleteBatch call with user controlled where() values"
entry_point: "application code calling ->where(...) followed by ->deleteBatch(...) on the query builder"
root_cause: >
  Quoting the advisory: when deleteBatch() is used together with where() conditions, the bound
  values from the WHERE clause are substituted directly into the generated SQL with their
  escape flag ignored, so they are never escaped or quoted. The missing decision is inside the
  deleteBatch code path in the query builder, which reads the binding but discards the flag
  of two is wrong, which is the important detail.
signal: >
  A framework method that is the less used sibling of a common one. delete() is used
  constantly and is correct. deleteBatch() is rare, arrived later, and is wrong. The general
  signal is any batch, bulk, upsert or "fast path" variant of a safe method: it was written
  separately, it gets less traffic, and it often reimplements the escaping instead of reusing
  it.
  On a live target the observable signal is a database error or a behaviour change when a
  quote character is placed in a value that is being used to filter a delete.
safe_proof: >
  In a lab, seed a table with canary rows. Send a value containing a single quote into a
  parameter that reaches the where() before a deleteBatch(). A syntax error in the response or
  the log proves the value entered the SQL rather than a placeholder. Stop there. Do not build
  a working injection: this sink is a DELETE, so a mistake destroys data rather than reading
  it, and a syntax error is sufficient proof.
controls:
  - "Negative control: the same value against 4.7.4 must produce a normal not found or no op rather than a syntax error."
  - "False positive to rule out: an application level validation error that happens to mention SQL, or a generic 500 from something else in the request. Confirm the error text names a SQL syntax problem at the position your quote occupied."
fix: { commit_url: ___, invariant: "the escape flag on a binding must be honoured on every code path that consumes bindings. The fix is not to escape harder in deleteBatch, it is to stop one path from dropping the flag" }
hardening: >
  Never pass user input into a where() that precedes a batch operation without casting it
  first: an ID is an integer, so make it one. That control is not framework specific and it
  survives the next framework bug. At review level, treat any bulk variant of a data method as
  unreviewed code until someone has read its escaping.
detection: >
  SQL syntax errors in application logs on delete paths. Rated 9.4, but note there is no
  network signature: the request looks like any other form post, so this is found by code
  review and by error log discipline, not by a WAF.
variant_rule: >
  Go through the query builder of whatever framework is in front of you and list every method
  that generates SQL. Then ask which ones are the rarely used siblings. In Laravel's builder
  that means upsert, insertUsing, updateFrom, whereRaw and the like. The pattern to hunt is a
  second implementation of a thing that already had a correct implementation.
lab: { install: "composer create-project codeigniter4/appstarter pinned to 4.7.3, one controller calling where() then deleteBatch() with a request value", snapshot: "the project directory, composer.lock and a dump of the seeded table", teardown: "drop the database and delete the directory" }
provenance: { source: "https://github.com/codeigniter4/CodeIgniter4/security/advisories/GHSA-c9w5-rwh3-7pm9", accessed: 2026-08-12, license_note: "vendor security advisory, public" }
```

## What happens

CodeIgniter's query builder normally protects you. You call `->where('id', $input)` and the
value goes in as a binding, safely quoted. The `deleteBatch()` method reads those same bindings
but throws away the flag that says "this one still needs escaping", then pastes the raw value
into the SQL. So the exact same `where()` call is safe before a `delete()` and injectable
before a `deleteBatch()`. Rated 9.4, affecting everything from 4.3.0 to 4.7.3.

## Why it works

This is the most common way framework SQL injection happens now. Nobody concatenates strings
by hand any more. What happens instead is that a framework grows a second implementation of
something it already did correctly, usually for performance or for a bulk case, and the new
implementation reimplements part of the escaping logic and gets one flag wrong. The
application code looks completely idiomatic. A reviewer reading the controller sees a
parameterised `where()` and moves on, because at that layer it is parameterised. The defect is
one layer down and only on one path.

## How you would reproduce it

Lab only, and this is one to be careful with because the sink is a DELETE. Seed a table, send
a single quote into a value that reaches `where()` before a `deleteBatch()`, and look for a SQL
syntax error. That is enough. Proving you can delete arbitrary rows adds nothing to the finding
and destroys the evidence you would need afterwards.

## What the fix is, and why the obvious fix is not enough

The workarounds in the advisory are to cast values, avoid the combination, or use `delete()`.
They all work and they all depend on developers remembering. The real fix, shipped in 4.7.4, is
that the escape flag is honoured on the batch path too. The invariant worth carrying away: when
a value carries a flag saying how it must be treated, every consumer of that value has to
respect the flag, and a code path that reads the value but ignores the flag is a bug waiting
for the right input.
