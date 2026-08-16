---
tags: [security, flash, advisories, api, method, api1, api3, derived-read-path]
updated: 2026-08-16
sources:
  - "https://github.com/advisories/GHSA-mvv8-v4jj-g47j, accessed 2026-08-16"
  - "https://github.com/advisories/GHSA-38hg-ww64-rrwc, accessed 2026-08-16"
  - "security/advisories-api/entries/APIDS-0022.md, the AFFiNE edit history case"
---

# MTH-API-010, list the shadows of the protected object, because the permission did not travel with the copy

Related: APIDS-0032,
APIDS-0031,
APIDS-0022,
MTH-API-001.

**Carried as debt for one run, written now because three entries in two products landed on it in the
same day.** It is the single most transferable thing in this run for Tutor LMS, which is the largest
unexamined API surface on Ahmed's fleet.

## The technique in one line

For every object whose access you have confirmed is checked, list every other place the system wrote
a copy of it, and check each of those separately, because the check was written for the object and
not for its shadows.

## The discovery signal

**A feature that exists for a reason other than reading the data.** History, revisions, audit,
versioning, drafts, search, caching, export, backup, logging, previews, aggregates, notifications and
webhooks are all built by somebody solving a different problem. None of them feels like a read path
to the person who wrote it, so none of them inherits the read path's authorisation.

Two sharper tells, both seen this run:

* **A response shape the security layer was not written against.** In
  APIDS-0031 the masking code looked for the field as
  a flat key. An aggregate nests it under `min`, so the masking code walked straight past it. The
  data was the same, the shape was not, and the shape was what the control keyed on.
* **A writer on a failure path.** In APIDS-0032 one of
  the two leaking writers was the authentication service writing a revision when it auto suspended an
  account after failed logins. Nobody reviews the error path as a place data gets copied. It is.

## The mechanism

Access control on an API is usually written once, at the endpoint that returns the object. That is
where the reviewer looks and that is where the tests are.

Meanwhile the object gets copied. A revision table records it. A search index tokenises it. A cache
stores the rendered version. An export flattens it. A log line prints it. Each copy is reachable
through some other endpoint, and each of those endpoints has its own authorisation, usually written
by whoever built the feature, usually about the feature and not about the object.

So the question that finds bugs is not "is this endpoint protected". It is: **the same field, in how
many places, reachable how many ways, and does the answer change depending on which way you ask.**

That last clause is the whole discipline. A finding here is a differential: the identical account
asking for the identical field, protected on one path and raw on another. That difference is proof.
One path returning data is not.

## Which OWASP API class

Primarily `API3` broken object property level authorisation when the shadow leaks a field, and
`API1` broken object level authorisation when it leaks a whole object. `API9` when the shadow is an
endpoint the operator did not know existed.

## Which protocols

All of them. REST history endpoints, GraphQL derived fields (this is
APIDS-0022, where the AFFiNE document was protected
and its edit history was not), aggregate and search parameters, webhook payloads, and any event or
message queue carrying the object outward.

## The enumeration list

Written out so it can be worked rather than remembered. For any protected object, ask what exists at:

1. **History and versions.** Revisions, drafts, autosaves, undo stacks, `_versions` collections.
2. **Audit and activity.** Audit logs, activity feeds, "who changed what" views.
3. **Aggregates and statistics.** `min`, `max`, `count`, `sum`, group headers, facets, dashboards.
4. **Sort and filter.** Ordering by a field you cannot read, filtering with a comparison on it, a
   uniqueness error that confirms the value.
5. **Search.** The index, autocomplete, suggestions, hit highlighting. Directus CVE-2025-64748 is
   exactly this: concealed fields were searchable.
6. **Derived children.** Submissions, attempts, grades, certificates, progress records, comments,
   attachments, thumbnails, transcodes.
7. **Exports and reports.** CSV and PDF exports, scheduled reports, print views.
8. **Caches and previews.** Rendered caches, preview and share links, OpenGraph cards, email
   summaries.
9. **Outbound copies.** Webhooks, queue messages, CRM sync, analytics events, error tracker
   breadcrumbs.
10. **Failure paths.** Error messages, suspension records, retry queues, dead letter queues.

## Does it reach Ahmed's surface, and how

**Yes, and this is the strongest fleet match in the folder.** An LMS is derived read paths all the
way down. Tutor LMS carries submissions, attempts, grades, certificates and progress records, and
every one of those is a copy of, or a statement about, an object whose main endpoint is presumably
checked. **None of it has been reviewed by anyone.**

Two specific reads worth doing when the lab exists:

* For a quiz or assignment: the answer is protected on the item route. Is it protected in the
  attempt record, the grade record, the export, and the instructor preview?
* For enrolment: enrolment is checked on the course route. Is it checked on the progress route, the
  certificate route, and the search index?

Second match, from APIDS-0032: **AI provider keys.**
That advisory names `ai_anthropic_api_key` among the fields exposed in history. The EduAi `.env`
holds live Anthropic, Groq and ZAI keys. If any provider key on this fleet is ever stored on a
settings object rather than in the environment, every shadow of that object becomes a key
disclosure, and this card is the checklist for finding them.

## A safe way to test for it

Static first, and static is usually enough to write the finding. Grep the schema for tables whose
names end in `_revisions`, `_history`, `_log`, `_audit`, `_versions`, and grep the routes for
`history`, `revisions`, `export`, `preview`, `search`, `aggregate`. Then read who is allowed to
read each one.

Dynamic, in a lab only: put a unique marker in the protected field, exercise the feature that
creates the shadow, and search for the marker in every place you can read as a low privilege
account. **A marker, never a real secret.** The marker also gives you the differential for free,
because you can show the same account getting stars on one path and the marker on another.

## The control that catches a false positive

**Read the main path as the same account, in the same session, first.** If the field is visible
there too, the shadow is not a finding, it is a permissions configuration you disagree with. The
finding only exists when one account gets two different answers for one field.

Second control: check who actually holds read access on the shadow. In
APIDS-0032 the leak needs read access to the
revisions collection. That may be admin only in a given deployment, which bounds impact without
changing the defect. Report the defect and the deployment separately and do not merge them.

## Where else this shape appears

WordPress post revisions and `wp_postmeta`, Laravel model auditing packages, Rails PaperTrail,
Django simple history, event sourced stores, Elasticsearch and Algolia indexes built by a sync job,
object storage holding an export nobody expires, and database backups. The rule is the same
everywhere: **the copy was made by a feature, and features do not inherit authorisation, they
reimplement it or forget it.**

## Provenance

* GHSA-mvv8-v4jj-g47j, Directus sensitive fields in revision history, accessed 2026-08-16.
* GHSA-38hg-ww64-rrwc, Directus concealed fields via aggregate queries, accessed 2026-08-16.
* APIDS-0022, AFFiNE document edit history, from the
  2026-08-13 run.
* Directus CVE-2025-64748, concealed fields searchable, seen in the advisory listing 2026-08-16 and
  not opened.
</content>
