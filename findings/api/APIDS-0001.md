---
tags: [security, flash, advisories, entry, api, graphql, access-control]
updated: 2026-08-12
sources:
  - "https://www.sentinelone.com/vulnerability-database/cve-2026-25497/ accessed 2026-08-12"
---

# APIDS-0001: Craft CMS GraphQL, cross volume asset modification

**Chosen as the first entry deliberately.** It is the cleanest published example of the
object graph method in the AI testing systems page.

```yaml
id: APIDS-0001
component: { type: framework, ecosystem: composer, name: Craft CMS, version_scope: ___ }
affected: { introduced: ___, fixed_in: ___, tested_on: not tested, desk research only }
identifiers: { cve: CVE-2026-25497, ghsa: ___, osv: ___, vendor_id: ___ }
class: { owasp_api: API1, owasp_2025: A01, cwe: CWE-639, family: broken-object-level-authorisation, corpus_directory: 02-access-control-bac-idor }
protocol: graphql
auth_required: user
entry_point: "the saveAsset GraphQL mutation"
object_graph:
  creates: "an asset is created inside a volume; the volume is the boundary"
  owns: "the volume owns the asset"
  should_reach: "an account with write access to that volume, and no other"
  actually_got: "an account with write access to ANY one volume could modify or transfer an asset in ANY volume, including private ones"
root_cause: >
  The mutation checks authorisation against the schema resolved volume, then fetches the
  target asset by ID WITHOUT checking that the asset actually belongs to the volume it just
  authorised. The check and the fetch answer two different questions and nobody joins them.
signal: >
  Any handler that authorises against one identifier and then loads an object by a
  different identifier. The gap between "what am I allowed to touch" and "what did I
  actually load" is where this lives.
safe_proof: >
  Two accounts, two volumes. Account A has write access to volume 1 only. Create a canary
  asset in volume 2 as account B. As account A, call saveAsset against the canary asset ID
  and observe whether it changes. Modify a marker field, never delete anything.
controls: >
  Confirm account A genuinely cannot reach volume 2 through the intended path. Confirm the
  change is persisted and not just echoed. Confirm account A did not already hold a global
  capability that made this legitimate, which is the E1 authority delta question.
fix: { commit: ___, invariant: "authorise the object you actually loaded, not the one you were told about" }
hardening: >
  Load first, then authorise against the loaded object's real owner. Authorising against a
  request supplied scope and then loading by ID is the pattern; reversing the order kills
  the whole class.
detection: "requests where the authorised scope and the loaded object's owner disagree"
variant_rule: >
  Every mutation or endpoint that takes both a scope and an object ID. Look for update,
  transfer, move, attach, share, duplicate and export operations, which almost always take
  both.
lab: { install: ___, snapshot: ___, teardown: ___ }
provenance: { source: "SentinelOne vulnerability database", accessed: 2026-08-12, license_note: "public vulnerability database" }
```

## What happens

A user with write access to one asset volume can modify or transfer assets belonging to
**any** other volume, including private and restricted ones they were never given access to.

## Why it works

The `saveAsset` mutation does two things and joins them incorrectly.

1. **It authorises** against the volume the schema resolved. That check passes: the user
   really does have write access to that volume.
2. **It then fetches** the target asset **by ID**, and never asks whether that asset lives
   in the volume it just authorised.

So the permission check is correct, it is answering the wrong question. **It proves the user
may write to volume 1. It does not prove the thing they are writing to is in volume 1.**

## Why this is the first entry in this folder

**It is the object graph problem in one sentence**, and it is the exact discipline both

> record which request created each object, who owns it, and which account should be allowed
> to access it. That is the difference between changing a random ID and proving broken
> access control.

Change the asset ID in this mutation and something happens. That alone is not a finding.
**It becomes a finding when you can say: this object was created by that request, it belongs
to that volume, this account should not reach that volume, and it reached it anyway.** Four
facts, not one observation.

## The fix, and why the obvious one is not enough

The obvious fix is to add a second permission check on the asset. That helps and it is not
the invariant.

**The invariant is ordering: load the object first, then authorise against the owner you
found on it.** As long as authorisation runs against a scope the caller supplied, some code
path will eventually load something else.
