---
tags: [security, flash, advisories, api, entry, ssrf, api7, ai-endpoint, incomplete-fix, wallos]
updated: 2026-08-13
sources:
  - "https://github.com/ellite/Wallos/security/advisories/GHSA-r82v-p8cg-rgx3, accessed 2026-08-13"
---

# APIDS-0016: the SSRF helper exists, and only the test endpoints call it

**The second `API7`, and the more useful of the two, because the guard is present and still
loses.** Related: APIDS-0015, the same class
with no guard at all, MTH-API-008, the method
this entry produced, APIDS-0020, the same
architectural mistake in a different layer.

```yaml
id: APIDS-0016
component:
  type: service
  ecosystem: php, self hosted subscription tracker
  name: Wallos
  version_scope: v4.6.2 and earlier
affected:
  introduced: the incomplete fix is commit e8a513591, which shipped for CVE-2026-30840
  fixed_in: ___ (advisory lists no patched version)
  tested_on: not tested, reading only
identifiers:
  cve: CVE-2026-33401
  ghsa: GHSA-r82v-p8cg-rgx3
  osv: ___
  vendor_id: ___
  supersedes: CVE-2026-30840, whose fix this advisory documents as incomplete
class:
  owasp_api: API7:2023 server side request forgery
  owasp_2025: ___
  cwe: CWE-918
  family: a shared validator applied to some callers and not others
protocol: rest
auth_required: user
entry_point:
  - route: POST /endpoints/ai/fetch_models.php
    parameter: ollama_host
    sink: curl, after the code builds apiUrl = aiOllamaHost . '/api/tags'
    note: direct, the parameter is used verbatim in the same request
  - route: POST /endpoints/ai/generate_recommendations.php
    parameter: ai_settings.url, read from the database
    sink: curl, after appending '/api/generate'
    note: stored, the URL is written by /endpoints/ai/save_settings.php which does not validate
  - route: endpoints/cronjobs/sendnotifications.php
    parameter: notification URLs read from the database
    sink: curl
    note: stored and deferred, fires on the cron schedule with no user in the request at all.
      Affects Gotify, Discord, Mattermost, ntfy and generic webhook targets
object_graph:
  creates_the_object: the user saves an AI setting or a notification target containing a URL
  owns_it: the user who saved it
  should_reach_it: the external service the user nominated
  tested_account_got: any host the server can reach, including cloud metadata endpoints and
    localhost services, with the third path executing later under the cron job's context rather
    than the user's request
root_cause: >
  The missing decision is not missing code, it is misplaced code. validate_webhook_url_for_ssrf()
  in ssrf_helper.php exists and works. It is called only from the five test endpoints
  (test{webhook,gotify,ntfy,discord,mattermost}notifications.php). The save endpoints for both
  notifications and AI settings persist a URL without ever calling it, and the consumers read
  that URL back out and call curl without revalidating. A second, narrower defect: the helper
  itself does not block RFC 6598 CGNAT space, 100.64.0.0/10.
signal: >
  A repository that contains a file named like a guard is telling you a guard exists. The
  question is never "is there validation", it is "how many call sites are there, and how many
  reach the sink". Grep for the helper, grep for the sink, and subtract. The gap is the finding.
safe_proof: >
  Lab only. Disposable Wallos instance in the affected range, canary listener on an address the
  container can reach and the tester cannot. Save a setting pointing at the canary through the
  save endpoint, then trigger the consumer. The proof is the canary log line showing the server
  as the source. For the cron path the proof is the same log line arriving on the schedule with
  no request from the tester at that moment, which is what makes the deferred path worth
  demonstrating separately.
controls:
  negative: point at a non existent host and confirm no canary hit
  differential: >
    confirm the canary address is unreachable from the tester's own network. Reaching it
    through the server is only a finding when it is otherwise unreachable
  attribution: >
    for the cron path especially, check the timestamp. A hit arriving on the cron schedule,
    minutes after the tester stopped interacting, is the evidence that the stored value fires
    without a user present
fix:
  commit_url: e8a513591, the incomplete one, referenced in the advisory. The complete fix is ___
  invariant: >
    Stated by the advisory as the reason the first fix failed: "validation must occur at
    save-time across all endpoints, and revalidation is necessary when consuming stored URLs."
    Two obligations, not one. Validate on the way in, and check again on the way out.
hardening: >
  Route every outbound call through one egress function, so a new call site cannot be written
  without it. Validating at the point of storage alone is not enough, because the ranges you
  refuse can change and stored data outlives the rule that admitted it. That is the argument
  for revalidating at use.
detection: >
  Outbound requests from the web server or the cron worker to private, loopback, link local or
  CGNAT addresses. The cron path is the loud one in logs, because the request has no user
  session attached to it.
variant_rule: >
  Wherever an application has a "test this connection" button, look for the save path beside it.
  The test path is the one a developer thinks about, because it is the one that shows a result
  on screen. The save path is silent, and the consumer is silent, and both reach the same sink.
  On Ahmed's fleet this maps directly onto anything storing a webhook target or a provider base
  URL: the GoHighLevel and WhatsApp integration settings, and any AI provider configuration.
lab:
  install: disposable container of v4.6.2 or earlier, isolated network
  snapshot: before the test
  teardown: destroy
provenance:
  source: https://github.com/ellite/Wallos/security/advisories/GHSA-r82v-p8cg-rgx3
  accessed: 2026-08-13
  license_note: short quoted fragments for the technical description only
  credit: reported by @b-hermes
```

## What happens

Wallos had an SSRF bug, fixed it, and the fix covered the wrong endpoints.

The application has a helper whose one job is to look at a URL and decide whether the server is
allowed to fetch it. That helper is real and it is called. It is called from the five "test this
notification" endpoints, the ones behind a button that says try it now.

It is not called when you save a setting. And it is not called when something later reads that
saved setting and fetches it.

So the attack moves one step to the left. Instead of asking the server to fetch a bad URL, you
save a bad URL, and wait. The AI recommendations route reads it. The cron job reads it. Neither
one asks the helper anything.

There is also a direct path that skipped the helper entirely: `fetch_models.php` takes an
`ollama_host` value straight out of the POST body and curls it.

## Why it works

A developer fixing an SSRF report fixes the endpoint in the report. The report named the test
endpoints, so the test endpoints got the helper. Nobody drew the full list of places a URL can
enter the system and the full list of places one leaves it.

The cron path is the sharpest version. By the time the request goes out there is no user, no
session, and no request to inspect. Whatever was in the database is simply trusted, because
somebody upstream is assumed to have checked it, and nobody did.

## How you would reproduce it

Lab instance. Save a URL pointing at a canary through the save endpoint, which will accept it
without complaint. Then make the consumer run. The canary log line, showing the server's own
address as the source, is the whole proof. For the cron variant, save it and walk away: the hit
that arrives on the schedule with you doing nothing is a stronger piece of evidence than the
direct one, because it shows the value survives the request that created it.

## What the fix is, and why the obvious fix would not work

The obvious fix is the one that was already tried: add the helper to the endpoint that was
reported. That is what commit `e8a513591` did, and this advisory is the result.

The next obvious fix is "validate at save time". Better, and still not enough, for a reason the
advisory itself hands you: the helper had a hole in it, missing the CGNAT range
`100.64.0.0/10`. Rows saved while the rule was wrong sit in the database being trusted forever.
Validation at save time is a snapshot of the rule on the day of the save.

That is why the invariant has two halves. Check on the way in so bad data does not land. Check
again on the way out so the check reflects today's rule rather than the day the row was written.

## Why this one matters for the fleet

Ahmed's products store outbound URLs: CRM callbacks, WhatsApp endpoints, AI provider base URLs.
The question this entry teaches him to ask is not "does the settings form validate the URL". It
is "count the call sites, and count the sinks, and show me the ones that do not line up".
