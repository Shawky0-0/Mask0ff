---
tags: [security, flash, advisories, api, entry, api3, directus, revision-history, ai-keys]
updated: 2026-08-16
sources:
  - "https://github.com/advisories/GHSA-mvv8-v4jj-g47j, accessed 2026-08-16"
---

# APIDS-0032, the field was concealed on the item and stored in plaintext in the item's history

Related: APIDS-0031 (the same product, same class,
different derived path), MTH-API-010,
APIDS-0022.

**The clearest instance in this folder of the derived read path**, and the reason MTH-API-010 was
written this run. It also reads directly onto Ahmed's fleet, because the exposed field list
includes AI provider API keys by name.

```yaml
id: APIDS-0032
component:
  type: service
  ecosystem: npm
  name: directus
  version_scope: "the revision snapshot writer, and the authentication service's auto suspension path"
affected:
  introduced: ___
  fixed_in: "11.17.0"
  tested_on: ___
identifiers:
  cve: CVE-2026-39943
  ghsa: GHSA-mvv8-v4jj-g47j
  osv: ___
  vendor_id: ___
class:
  owasp_api: API3 broken object property level authorisation
  owasp_2025: ___
  cwe: CWE-200 exposure of sensitive information, CWE-312 cleartext storage
  family: the shadow copy, written by a feature nobody thinks of as a read path
protocol: rest
auth_required: user (any user or service account with read access to directus_revisions, or to flow logs)
entry_point: "the directus_revisions collection, read through the normal items API, and flow logs"
object_graph:
  creates: "an item create or update writes a revision row. A failed login sequence writes one too, from the auth service's auto suspension path"
  owns: "the user whose token, TOTP seed or API key is in the snapshot"
  should_reach: "nobody, for those fields. They are concealed or encrypted at rest on the item itself"
  tested_account_got: "any account with read access to directus_revisions read token, tfa_secret, external_identifier, auth_data, credentials, and the AI provider keys ai_openai_api_key, ai_anthropic_api_key, ai_google_api_key and ai_openai_compatible_api_key, all in plaintext"
root_cause: >
  The revision snapshot code does not consistently call the `prepareDelta` sanitisation pipeline, so
  the snapshot keeps whatever the item held, including fields the item endpoint would conceal, and
  it also pulled in relational fields it should not have. A second, separate path: the
  authentication service writes revision records containing raw user objects when it auto suspends
  an account after failed logins. Two writers, one of them not even a user action, and neither goes
  through the sanitiser. The missing decision is the field policy on the write into the history
  table, not on the read out of it.
signal: >
  Ask, for every protected object, what else was written when it was written. History, revisions,
  audit log, activity feed, versions, drafts, the outbox, the search index, the cache, the export,
  the webhook payload, the log line. Each of those is a second copy created by a feature nobody
  reviews as a read path, and the field policy usually did not travel with the data. **The second
  half of the signal here is the one that generalises: one of the two writers is the auth service on
  a failure path. Error and recovery paths write copies that success paths do not.**
safe_proof: >
  In a lab, set a concealed field to a marker such as `canary-apids-0032`, update the item once so a
  revision is written, then read `directus_revisions` as a low privilege account with read access.
  If the marker appears in the delta, it is proved. For the second path, trigger the auto suspension
  with deliberately wrong credentials on a throwaway lab account and read the revision it writes.
  **Markers only. Never a real key, and never outside the lab.**
controls:
  negative: "read the item itself as the same account and confirm the field is masked there. Same account, same field, two answers, which is what makes this an authorisation finding rather than a permissions misconfiguration."
  differential: "compare a revision written by an item update against one written by the auth service. The advisory says both leak but for different reasons, so proving only one leaves half the defect unfixed."
  false_positive: "an operator may have deliberately granted revision access to an admin only role, in which case exposure is bounded. Check who actually holds read on directus_revisions before scoring impact, and note that service accounts often hold more than anyone remembers."
fix:
  commit: "not read this run. The advisory links the v11.17.0 release rather than a commit"
  invariant: >
    Stated from the defect: every writer into the revision table must pass the payload through the
    same sanitisation pipeline the item read path uses, including the writers on authentication
    failure paths.
hardening: >
  The control that kills the class is to keep the secret out of the object in the first place. A
  token, a TOTP seed and a provider key should live in a store the item serialiser cannot reach, so
  that no snapshot, log, export or cache can copy what it never held. Sanitising at every writer is a
  list that grows; removing the value from the object is a decision made once.
detection: >
  Reads of the revision or audit collection filtered to rows belonging to other users, especially by
  a service account. In storage, the presence of any string matching a key or token pattern inside a
  history or log table is worth a standing check rather than an alert, because it is a condition, not
  an event.
variant_rule: >
  Every product with a history feature: WordPress post revisions and `wp_options` autoload, Laravel
  model auditing packages, Rails PaperTrail, Django simple history, any event sourced store, and any
  message queue that carries the object. Also the neighbours: flow and automation logs (named in this
  advisory), webhook payloads, Sentry and error tracker breadcrumbs, and database backups. **On
  Ahmed's fleet the loudest one is Tutor LMS: submissions, attempts, grades and certificate records
  are all derived copies of protected objects, and nobody has reviewed any of them. The second is
  any place a provider key could be stored on a settings object rather than in the environment,
  because this advisory shows what happens next.**
lab:
  install: "directus < 11.17.0 in docker, one collection with a concealed field, one low privilege user with read on directus_revisions"
  snapshot: "container snapshot before, discard after"
  teardown: "docker rm"
provenance:
  source: "GitHub Security Advisory GHSA-mvv8-v4jj-g47j"
  accessed: 2026-08-16
  license_note: "advisory text summarised, not reproduced"
```

## What happens

A field is concealed. Read the item and you get a mask.

Every time the item changes, the system saves a before and after snapshot into a history table. That
snapshot kept the real value. So the protected field is sitting in plaintext one table over, and
anyone with read access to history can take it.

The list of fields includes user tokens, two factor seeds, and the API keys for OpenAI, Anthropic
and Google.

## Why it works

There is a sanitiser. It is called `prepareDelta` and it is what strips the sensitive fields out of
a snapshot. The revision writer does not consistently call it.

Then there is a second writer nobody would look for. When an account gets auto suspended after
failed logins, the authentication service writes a revision record too, and it writes the raw user
object into it. That path was not written by the person who wrote the item revision path, and it
does not call the sanitiser either.

So the same protection failed twice, in two places, for two different reasons, and only one of them
is on a path a reviewer would think to read.

## How to reproduce

Put a marker in a concealed field. Change the item. Read the history table as a low privilege
account. The marker is there.

## The fix, and why the obvious fix would not work

Call the sanitiser everywhere.

The obvious fix is to call `prepareDelta` from both writers. That is what the vendor did and it is
correct, but the list of writers only grows: an export feature, a cache, a webhook, a new log. Each
one is a fresh chance to forget.

The fix that kills the class is to stop putting the secret in the object. If the token lives
somewhere the item serialiser cannot reach, then history, logs, exports, backups and every future
feature are all safe by construction, and none of them had to be told.
</content>
