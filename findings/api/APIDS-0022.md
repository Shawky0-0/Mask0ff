---
tags: [security, flash, advisories, api, entry, api1, api5, graphql, field-level-auth, affine]
updated: 2026-08-13
sources:
  - "https://github.com/advisories/GHSA-m4gp-5xh5-xhq4, accessed 2026-08-13"
---

# APIDS-0022: the document was protected, its edit history was not

Related: MTH-API-001, the object graph method,
which this is a textbook instance of,
APIDS-0010, the same shape on chat memory,
APIDS-0021, the other GraphQL entry this run.

```yaml
id: APIDS-0022
component:
  type: service
  ecosystem: unknown, listed by GitHub without a package ecosystem
  name: AFFiNE
  version_scope: ___
affected:
  introduced: ___
  fixed_in: ___
  tested_on: not tested, reading only
identifiers:
  cve: CVE-2026-59262
  ghsa: GHSA-m4gp-5xh5-xhq4
  osv: ___
  vendor_id: toeverything/AFFiNE issue 15179
class:
  owasp_api: API1:2023 broken object level authorisation, primary. API5:2023 as secondary,
    because the missing check is on one field's resolver rather than on the object generally
  owasp_2025: ___
  cwe: CWE-862
  family: a sibling field that returns the protected object's contents without the protection
protocol: graphql
auth_required: user, any authenticated workspace member
entry_point:
  field: the histories GraphQL field
  parameter: a document GUID, supplied by the caller and not checked against their access
  missing_check: Doc.Read
object_graph:
  creates_the_object: a workspace member creates a document, and permissions restrict who reads it
  owns_it: the document's owner, with Doc.Read granted to a specific set of members
  should_reach_it: only members holding Doc.Read on that document
  tested_account_got: >
    the complete edit history of any document in the workspace by GUID, including who edited it,
    their email addresses and the modification timestamps. **The document body is protected and
    its history is not**, which is the whole finding: the history is a derivative of the body
    and leaks the same relationships
root_cause: >
  The missing decision is a Doc.Read check inside the histories field resolver. GraphQL
  authorises per resolver, so a permission enforced on the document query does not
  automatically extend to a neighbouring field that reads the same underlying object. Nothing
  propagated the check sideways, and nothing was written to.
signal: >
  **Whenever an object is access controlled, list everything derived from it.** History,
  versions, revisions, audit log, comments, attachments, thumbnail, preview, export, share link,
  activity feed, search index. Each is a separate code path that reads the same data, and each
  needs the same check written again by hand. The derived paths are written later, usually as a
  feature rather than as a security surface, and that is where the check is missing.
safe_proof: >
  Lab only. Two accounts in one workspace, A and B. A creates a document and does not share it
  with B. Confirm B is refused when querying the document itself. Then, as B, query the
  histories field with A's document GUID. The proof is the pair of responses side by side.
  Put a canary string in A's document, edit it once so it enters the history, and look for the
  canary in B's response. Read only, nothing modified.
controls:
  negative: >
    as B, query histories for a GUID that does not exist. It must return nothing. If it returns
    data, the response is not tied to the GUID and the test is measuring something else
  differential: >
    B must be refused on the document query in the same session. That line is what proves the
    document was protected and only the history was not. Without it the report says nothing
  attribution: >
    the canary is what ties the leaked history to A's specific document. A history response full
    of plausible looking metadata is not evidence that it is A's; the canary is
fix:
  commit_url: toeverything/AFFiNE commit 1f0bcd0, referenced by the advisory, not opened by this
    sweep
  invariant: >
    Not read from the diff. Stated from the defect: every resolver returning data derived from a
    protected object must evaluate that object's read permission itself, because in GraphQL a
    check on one field is not inherited by its siblings.
hardening: >
  Authorise at the object, not at the field. Load the document once through a function that
  performs the Doc.Read check and returns it, and have every derived resolver take that loaded
  object rather than a GUID. Then a resolver cannot be written that skips the check, because it
  never sees a GUID to skip it with. Field by field checks are correct and they rely on every
  future author remembering, which is the failure mode here.
detection: >
  Queries for the histories field carrying GUIDs the requesting user has never opened through
  any other path. In practice, a user whose history reads vastly outnumber their document reads.
variant_rule: >
  Every derived read path listed under signal, on every product. Read across to
  APIDS-0010, where Langflow's chat memory filtered on session_id and never on the owner: the
  same failure, a query that filters on the identifier the caller supplied instead of on the
  relationship the caller holds.
  **Ahmed's fleet: Tutor LMS is the read across target.** An LMS has submissions, grades,
  attempts, certificates and progress records, each of which is derived from an enrolment
  boundary and each of which is a separate route. That is exactly this shape, repeated.
lab:
  install: disposable AFFiNE, version unknown so pin whatever is available and record it
  snapshot: before
  teardown: destroy
provenance:
  source: https://github.com/advisories/GHSA-m4gp-5xh5-xhq4
  accessed: 2026-08-13
  license_note: technical description summarised, no substantial quotation
  credit: >
    ___. The advisory page lists the National Vulnerability Database as the publisher and names
    no reporter. A VulnCheck advisory is referenced and was not opened
```

## What happens

AFFiNE is a workspace tool with documents in it, and documents have permissions. If a document
is not shared with you, you cannot read it.

Documents also have an edit history: who changed what, and when.

The history is fetched by a different GraphQL field, and that field never asks whether you are
allowed to read the document. You give it a document identifier and it tells you the document's
history: the names, the email addresses, the timestamps.

## Why it works

In GraphQL, every field is resolved by its own piece of code. Permissions are enforced by
whichever resolvers happen to enforce them. There is no rule that says a check on one field
covers the field next to it.

So the document resolver got its check, because protecting documents was obviously the point.
The history resolver was written when history was added, as a feature, and nobody asked the
security question a second time.

The severity is High and worth understanding. You do not get the document text. You get who
touched it and when, which for a restricted page is often the sensitive part: it maps who is
working on what, and it hands over email addresses.

## How you would reproduce it

Two accounts, one unshared document, one canary string edited into it. Account B is refused on
the document and served on the history. Both responses go in the report. The one that gets
refused is the one that proves the other matters.

## What the fix is, and why the obvious fix would not work

The obvious fix is to add the Doc.Read check to the histories resolver, which is presumably what
the commit does. It fixes this field.

It does not fix the next one. Comments, exports, search results, activity feeds: every one is a
resolver somebody will write later, and every one will need the check written again by whoever
writes it. The pattern reproduces indefinitely.

The structural fix loads the document through one authorised accessor and passes the loaded
object to derived resolvers. Then the permission is a precondition of having the data at all
rather than a step someone has to remember.

## The uncomfortable gap in this record

**Affected and patched versions are both `___`.** The advisory lists neither, and this sweep
does not guess. That means this entry cannot answer "are we affected", only "here is the shape
to look for". For Ahmed's purposes the shape is the useful part, because AFFiNE is not on the
fleet and Tutor LMS, which is, has exactly this structure and has never been reviewed by anyone.
