---
tags: [security, flash, advisories, api, entry, api1, ai, rag, langflow, object-graph]
updated: 2026-08-12
sources:
  - "https://github.com/advisories/GHSA-vph6-jp7f-x3cx, accessed 2026-08-12"
  - "https://nvd.nist.gov/vuln/detail/CVE-2026-9130, referenced by the advisory, not fetched"
  - "https://www.ibm.com/support/pages/node/7282647, IBM bulletin, HTTP 403 to this sweep"
---

# APIDS-0010: the AI chat memory is filtered by session, and session is not an owner

**The first entry in the AI and RAG endpoint authorisation row**, which was the most YZH
relevant row in the class table and empty after two runs. Related:
MTH-API-001, the object graph,
APIDS-0011, the other Langflow entry,
the API folder.

```yaml
id: APIDS-0010
component:
  type: service
  ecosystem: Python, PyPI package langflow
  name: IBM Langflow OSS, the MemoryComponent
  version_scope: the chat memory component, reached through the run and workflow APIs
affected:
  introduced: 1.0.0
  fixed_in: ___ . The GitHub advisory states the patched version as unknown. IBM's bulletin at support/pages/node/7282647 returned HTTP 403 to this sweep, so the fixed release is unconfirmed and is deliberately not inferred from the 1.10.3 upper bound
  tested_on: not tested. Read only sweep
identifiers:
  cve: CVE-2026-9130
  ghsa: GHSA-vph6-jp7f-x3cx
  osv: ___
  vendor_id: IBM support node 7282647
class:
  owasp_api: API1 broken object level authorisation, primary
  owasp_2025: ___
  cwe: CWE-639 authorization bypass through user controlled key
  family: tenant scoping on conversational memory
protocol: rest
auth_required: user. An authenticated account on a multi user deployment
entry_point: >
  /api/v1/run/*, /api/v1/responses, and /api/v2/workflow/*, with session_id as the controlled
  parameter. Applies to deployments with LANGFLOW_AUTO_LOGIN disabled, which is to say the
  ones that actually have multiple users to separate.
object_graph: >
  This is the cleanest object graph case the folder has recorded, so it is worth writing out
  in full.
  Which request creates the object: a chat turn. A user runs a flow, and store_message writes
  the message row.
  Who owns it: the row genuinely belongs to a user_id and a flow_id. Both columns exist. The
  ownership information was never missing.
  Who should reach it: that user, in that flow, and nobody else.
  What the tested account actually got: any message row sharing the session_id, regardless of
  user_id or flow_id, because retrieve_messages and store_message filter on session_id alone.
  The gap is precisely that session_id is a conversation grouping key and was used as though
  it were an ownership key. It is chosen or guessed rather than owned, which is what CWE-639
  means by a user controlled key.
root_cause: >
  MemoryComponent, in the retrieve_messages and store_message methods. The query filters by
  session_id and does not add flow_id or user_id to the predicate. The missing decision is one
  clause in a database filter, and the columns needed to write that clause were already there.
signal: >
  A read path whose filter names fewer columns than the write path stored. If the row records
  user_id and flow_id but the SELECT only mentions session_id, the difference is the finding.
safe_proof: >
  Lab only. Two accounts on your own multi user install, with auto login disabled. Account A
  runs a flow and sends a message containing a canary string, for example APIDS0010CANARY.
  Account B, authenticated as itself and running its own separate flow, sets the same
  session_id and requests memory. If B's response contains A's canary, cross user disclosure
  is proved. Nothing is written to A's data and nothing is destroyed: B only reads, and the
  canary makes the crossing unambiguous rather than a matter of interpretation.
controls: >
  Negative control: repeat the read with a session_id that exists for nobody. It must return
  empty. If it returns rows anyway, the filter is broken in some other way and the session_id
  story is wrong. Differential control, and this is the one that matters: run the same read as
  account A itself. A and B must see the same rows for the finding to be about ownership. If B
  sees fewer, there is partial scoping somewhere and the write up needs to say where. Third
  control: confirm the deployment really has LANGFLOW_AUTO_LOGIN disabled. With auto login on,
  every caller is effectively the same superuser and any cross user claim is meaningless,
  which is a false positive this component invites.
fix:
  commit_url: ___ . Not located this run
  invariant: >
    Stated from the root cause description rather than from a diff, and flagged as such:
    a memory read must be scoped by the owning user_id and flow_id in addition to session_id,
    so that a caller supplied session identifier can never widen the row set beyond what that
    caller owns.
hardening: >
  Never let a client supplied grouping key be the only term in an ownership filter. Scope
  every query by the authenticated principal first, then narrow by whatever the client asked
  for. That ordering kills the whole class, including the variants below.
detection: >
  Two accounts reading the same session_id is the log signature, but only if session_id is
  logged alongside the authenticated user. Most deployments log one or the other, which is why
  this class survives. A gateway cannot see it at all, because every request is individually
  well formed and authenticated.
variant_rule: >
  Any endpoint that takes a conversation, thread, cart, room, batch or job identifier from the
  client and uses it to select rows. On Ahmed's surface the direct read across is EduAi and any
  AI or RAG route that keeps chat history: if history is fetched by a session or conversation
  id, ask whether the query also names the user. Tutor LMS is the larger unexamined case, where
  the same shape appears as course, cohort, enrolment and submission identifiers.
lab:
  install: A disposable Langflow install pinned in the affected range, two accounts, auto login disabled
  snapshot: VM snapshot before creating the second account
  teardown: Revert the snapshot. No external AI provider key is needed for the memory read path
provenance:
  source: GitHub Security Advisory GHSA-vph6-jp7f-x3cx
  accessed: 2026-08-12
  license_note: Facts, ranges and CWE only
```

## What happens

Langflow keeps chat history so a flow can remember what was said earlier. Every stored message
carries a `session_id`, a `flow_id` and a `user_id`. When the component reads history back it
filters on `session_id` and nothing else.

So if two users end up on the same `session_id`, they read each other's conversation.

## Why it works

Because `session_id` looks like an identity and is not one. It groups turns into a
conversation. It says nothing about who is allowed to see them. The row already carried the
two columns that do say that, `user_id` and `flow_id`, and the query simply did not mention
them.

This is why the object graph method insists on
writing down who owns an object separately from how it is addressed. Here the two came apart
completely, and the advisory's own word for the mechanism is "session_id collision".

Note what is **not** required: no privilege escalation, no token forgery, no unauthenticated
access. A perfectly ordinary logged in user reads someone else's chat history. That is what
`API1` looks like in practice and it is the reason it is the most common API bug there is.

## How you would reproduce it

Two accounts on your own install, auto login off, a canary string in account A's message, and
account B asking for the same `session_id`. If B gets A's canary, it is proved. Before
believing it, run the differential control: A and B must see the same rows. If they do not,
something else is going on and the finding needs rewriting rather than reporting.

## What the fix is, and why the obvious fix would not work

Unconfirmed, and deliberately left as `___`. The advisory does not name a patched version and
IBM's bulletin refused this sweep with a 403, so the fixed release is genuinely unknown here
rather than merely unrecorded. Do not read the 1.10.3 upper bound as "fixed in 1.10.4".

The invariant is clear even without the diff: scope the read by the authenticated user and the
flow, then narrow by session.

The obvious fix is to make `session_id` unguessable, a long random value, and it is the wrong
fix. It hides the bug behind entropy and leaves the authorisation decision missing. Any path
that leaks or shares a session identifier, a support tool, a URL, a log line, a shared link,
brings the whole thing back. Unguessable is not the same as unauthorised, and a fix that
confuses the two is the one worth pushing back on in review.

**Gate G5.** Whether the fleet runs Langflow at all is Ahmed's call. The repo does not record
it. This entry is filed for the shape, which reaches EduAi and Tutor LMS directly.
