---
tags: [security, flash, advisories, api, entry, api5, api4, ai-endpoint, llm-cost, open-webui]
updated: 2026-08-13
sources:
  - "https://github.com/advisories/GHSA-hp5m-24vp-vq2q, accessed 2026-08-13"
---

# APIDS-0019: the second route to the model forgot to ask which models you are allowed

**The AI endpoint entry with money attached that this folder has been chasing for four runs.**
Related: APIDS-0014, the other AI gateway entry,
MTH-API-002 on parallel routes to one
capability, APIDS-0012, the missing check pattern.

```yaml
id: APIDS-0019
component:
  type: service
  ecosystem: pip, self hosted LLM chat interface
  name: open-webui
  version_scope: "<= 0.8.12"
affected:
  introduced: ___
  fixed_in: 0.9.0
  tested_on: not tested, reading only
identifiers:
  cve: CVE-2026-44556
  ghsa: GHSA-hp5m-24vp-vq2q
  osv: ___
  vendor_id: ___
class:
  owasp_api: >
    API5:2023 broken function level authorisation, primary. API4:2023 unrestricted resource
    consumption, secondary and where the damage actually lands. See the honest note below on
    which of the two this really is.
  owasp_2025: ___
  cwe: CWE-284, CWE-862
  family: two routes to the same capability, one of them unguarded
protocol: rest
auth_required: user
entry_point:
  route: POST /api/openai/responses, the passthrough endpoint in the OpenAI router
  parameter: the model id in the request body, arbitrary
  contrast: the primary chat completion endpoint validates model ownership and group membership.
    This one confirms only that the session is valid
object_graph:
  creates_the_object: an administrator configures a model and assigns it to a user or a group
  owns_it: the deployment, with per model access controlled by administrators
  should_reach_it: only users the administrator granted that specific model to
  tested_account_got: any configured model, by naming its id, with the session check being the
    only gate crossed
root_cause: >
  The missing decision is the per model access check, and it is missing from exactly one of two
  parallel handlers. The advisory: "The /responses endpoint in the OpenAI router accepts any
  authenticated user and forwards requests directly to upstream LLM providers without enforcing
  per-model access control." Authentication was checked. Authorisation was not. The other route
  to the same capability checks both.
signal: >
  When a product adds support for a new upstream API shape, it usually adds a second handler
  beside the first rather than extending it. The old handler carries the accumulated checks.
  The new one carries the new feature. Ask, for every capability: how many routes reach it, and
  do they all enforce the same thing. A passthrough or proxy route is the highest risk shape,
  because its stated purpose is to not interfere.
safe_proof: >
  Lab only, with a fake upstream. Stand up an affected version pointed at a local stub that
  answers like a provider and costs nothing. Create two users, grant user A a model, grant user
  B nothing. As user B, call the passthrough route naming user A's model. The proof is the stub
  receiving a request attributed to user B for a model user B was not granted. Never point this
  at a real provider, because the proof would be a real billed call.
controls:
  negative: >
    as user B, call the primary chat completion route with the same model id and confirm it is
    refused. If it is not, the deployment's access control is not configured and there is
    nothing to bypass
  differential: >
    as user A, call the passthrough with the same model and confirm success. That establishes
    the route works normally and B's success is the anomaly, not a general fault
  attribution: >
    read the stub's log for which account the call was attributed to. A finding that says
    "someone reached the model" is much weaker than one that says "user B, granted nothing,
    reached user A's model"
fix:
  commit_url: https://github.com/open-webui/open-webui/pull/23481, referenced in the advisory,
    not opened by this sweep
  invariant: >
    Not read from the diff. Stated from the defect: every route that can cause an upstream model
    call must apply the same per model authorisation as the primary chat route, and that check
    belongs in shared code both routes call rather than duplicated in each.
hardening: >
  Put the model authorisation decision in one function and make the upstream call impossible
  without it, for example by having the provider client take an authorised model handle rather
  than a model id string. Then a new route physically cannot skip the check. On the money side,
  a per user spend cap enforced at the gateway limits the damage even when a route is missed.
detection: >
  Provider billing showing usage of an expensive model by accounts with no entitlement to it.
  In application logs, requests to the passthrough route carrying model ids that never appear
  in that user's normal traffic. The cost signal is often the first one anyone notices, which is
  late.
variant_rule: >
  Every product with a primary path and a compatibility, passthrough or legacy path. Also every
  streaming variant beside a non streaming one, and every batch variant beside a single item
  one. On Ahmed's fleet: if EduAi ever grows a second route to the AI providers, for example a
  streaming endpoint added later, this is the exact question to ask of it.
lab:
  install: disposable container at 0.8.12 or below, stub upstream, no real provider key present
  snapshot: before
  teardown: destroy
provenance:
  source: https://github.com/advisories/GHSA-hp5m-24vp-vq2q
  accessed: 2026-08-13
  license_note: short quoted fragments for the technical description only
  credit: reported by Classic298
```

## What happens

Open WebUI is a chat front end that sits in front of language models. An administrator can say
which people get which models, because some models cost far more than others.

There are two ways in. The main chat route checks who you are and which models you were given.
A second route, the passthrough, checks only that you are logged in, then forwards your request
to the provider.

So any account on the system can name any configured model and use it. The administrator's
whole allocation scheme applies to one door and not the other.

## Why it works

The passthrough route exists to pass things through. That is its name and its job. It was built
to be transparent, and it was transparent about the authorisation too.

The advisory names three consequences, and they are worth separating because they land on
different people. Budget exhaustion: someone runs expensive models and the bill arrives.
Model theft: a private or fine tuned model can be queried until its behaviour can be copied.
Policy bypass: cost tiers, team boundaries and compliance rules all stop meaning anything.

## Which OWASP class this really is, said honestly

The ledger has wanted an `API4` entry on an AI route for four runs, meaning a missing rate or
cost limit on something that spends money. **This is not quite that, and the record should not
pretend otherwise.**

The root cause here is a missing authorisation check, which is `API5`. The reason it is filed
with `API4` as a strong secondary is that the harm is metered in currency: the advisory's first
listed impact is exhausting API budgets by running expensive models. The mechanism is
authorisation, the damage is consumption.

The genuine `API4` primary entry from this run is
APIDS-0021, where the missing thing really is a
cost limit. The ledger records both, and records that the AI specific version of `API4`, a model
route with no spend cap, is **still not found as a primary root cause.**

## How you would reproduce it

Lab, against a stub upstream, never a real provider. Two accounts with different grants. The
one with no grant calls the passthrough and gets served. Keep the stub's log, because the
attribution line in it is the actual evidence.

## What the fix is, and why the obvious fix would not work

The obvious fix is to add the check to the passthrough route. That closes this bug and leaves
the shape that produced it, which is two handlers each responsible for remembering the same
rule. The third route added next year will forget it again.

The fix that holds moves the decision underneath both routes, so reaching the provider requires
having passed it. And separately, a spend cap per user, because authorisation answers "may you
call this model" and never answers "how many times".
