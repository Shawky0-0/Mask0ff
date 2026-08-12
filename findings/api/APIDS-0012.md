---
tags: [security, flash, advisories, api, entry, api5, wordpress, rest, permission-callback]
updated: 2026-08-12
sources:
  - "https://wpscan.com/vulnerability/1b815cde-cd9d-46fa-a6ab-3d2851705e7b/, accessed 2026-08-12"
  - "https://radar.offseq.com/threat/cve-2026-2025-cwe-200-information-exposure-in-mail-212f0a08, accessed 2026-08-12"
  - "https://nvd.nist.gov/vuln/detail/CVE-2026-2025, HTTP 502 to this sweep, not read"
---

# APIDS-0012: a plugin REST route with no permission callback, handing out every admin email

**A recurring WordPress REST authorization pattern**, now represented by a shipped plugin with
a CVE. Related:
MTH-API-001,
the API folder.

```yaml
id: APIDS-0012
component:
  type: library
  ecosystem: WordPress plugin
  name: Mail Mint, email marketing and WooCommerce emails
  version_scope: the mrm/v1 REST namespace
affected:
  introduced: ___
  fixed_in: 1.19.5
  tested_on: not tested. Read only sweep
identifiers:
  cve: CVE-2026-2025
  ghsa: ___
  osv: ___
  vendor_id: WPScan WPVDB 1b815cde-cd9d-46fa-a6ab-3d2851705e7b
class:
  owasp_api: API5 broken function level authorisation, primary. API3 broken object property level authorisation, secondary, since the response over exposes an address that no anonymous caller should see
  owasp_2025: ___
  cwe: CWE-200 exposure of sensitive information to an unauthorized actor
  family: WordPress REST route registered without a permission callback
protocol: rest
auth_required: none
entry_point: >
  GET /wp-json/mrm/v1/wp/admins, with a term query parameter. WPScan records that the route
  accepts partial search terms such as term=@, term=.com or term=gmail, which turns it from a
  lookup into an enumeration: a caller who knows no addresses can supply a fragment that every
  address contains and receive the list.
object_graph: >
  The object is a WordPress user account, specifically its email address. It is created by
  registration or by an administrator. It is owned by that user, and the site administrator can
  read it. Who should reach it through this route: an authenticated administrator, because the
  route exists to populate an admin picker in the plugin's own screens. What an anonymous
  caller actually got: the same list, in full, by asking. There is no identifier to tamper with
  and nothing to guess. The route simply never asked who was calling.
root_cause: >
  The register_rest_route() call for this endpoint either omits permission_callback or supplies
  one that returns true unconditionally. WordPress will register a route with no permission
  callback and only emit a notice, so the route works, and it works for everyone. The missing
  decision sits in the route registration, not in the handler, which is why reading the handler
  alone will not find it.
signal: >
  A route that exists to serve an admin screen. If the only caller the developers imagined was
  their own dashboard, the check is often assumed to live in the dashboard. Grep the plugin for
  register_rest_route and read the permission_callback argument of every one, not the handler.
safe_proof: >
  Lab only, on a researcher-controlled WordPress sandbox with the affected plugin version installed.
  Create a test account with a canary address, for example apids0012canary@example.invalid.
  Then, logged out entirely and in a private window with no cookies, request the route with a
  term fragment. If the canary address comes back to an anonymous caller, it is proved. The
  address is one you planted, so no real person's data is involved at any point.
controls: >
  Negative control: request a route in the same namespace that is correctly protected and
  confirm it returns 401 or 403 to the same anonymous session. That proves the site is
  enforcing authentication generally and that this route is the exception, rather than the
  whole install being open. Second control: confirm you are genuinely anonymous. A logged in
  administrator session in another tab, or a lingering auth cookie, is the single most common
  false positive in WordPress REST testing, and it makes every route look unprotected. Use a
  private window or a separate client and verify with a route that must reject you.
  Differential control: compare the anonymous response to the administrator response. If they
  are identical, the route applies no filtering by caller at all.
fix:
  commit_url: ___ . Plugin source diff not read this run
  invariant: >
    Stated from the root cause rather than a diff, and flagged as such: the route must declare
    a permission_callback that requires a capability appropriate to reading user email
    addresses, list_users or manage_options, so that an unauthenticated caller is rejected
    before the handler runs.
hardening: >
  Audit every register_rest_route in every plugin for its permission_callback, as a standing
  check rather than a one off. The class dies when no route can ship without an explicit
  capability decision, and __return_true is treated in review as a finding rather than as an
  answer.
detection: >
  Requests to a plugin REST namespace from unauthenticated sources, especially repeated
  requests varying a search term. The enumeration pattern, term=a, term=b, term=@, is visible
  in access logs as a burst against one path with a changing query string, which is one of the
  few API abuses a WAF can key on without understanding the application.
variant_rule: >
  Every plugin on an LMS or content platform, especially plugins that expose student,
  instructor, or enrolment lookups. The
  question for each is the same: does register_rest_route declare a permission_callback, and
  does that callback check a capability rather than return true. A correct callback in custom
  routes does not establish that separately installed plugins enforce the same invariant.
lab:
  install: A researcher-controlled WordPress lab, plugin pinned below 1.19.5
  snapshot: Snapshot before installing the plugin
  teardown: Revert the snapshot. Never point any of this at a production site
provenance:
  source: WPScan vulnerability database entry, and the OffSeq threat radar record
  accessed: 2026-08-12
  license_note: Facts, route name and version range only
```

## What happens

Mail Mint registers a REST route to populate an administrator picker in its own settings
screens. Ask it for `/wp-json/mrm/v1/wp/admins?term=@` while logged out, and it returns the
email addresses of users on the site.

Every address contains `@`, so a caller who knows nothing gets everything.

## Why it works

WordPress will happily register a REST route that has no permission callback. It emits a
notice in the log and then serves the route to the world. Nothing fails loudly, nothing
refuses to load, and the plugin works perfectly in testing, because the developers only ever
called it from an admin screen where they were already logged in.

That is the whole mechanism, and it is why this class keeps recurring. The check was assumed to
live somewhere it did not, and the failure mode of forgetting it is silence.

## How you would reproduce it

On a researcher-controlled sandbox, never on a production site. Plant a canary address on a test account,
install the affected version, log out completely, and request the route from a private window.

Then run the controls, because this is exactly where a WordPress tester fools themselves. If a
session cookie is still attached, every protected route looks open. Prove you are anonymous by
requesting something that must reject you, and only then believe the result.

## What the fix is, and why the obvious fix would not work

The route needs a `permission_callback` that checks a capability, `list_users` or
`manage_options`, so the request is rejected before the handler runs. The plugin fixed it in
1.19.5.

Two obvious fixes are wrong and both get proposed.

The first is to filter the response so it returns less. That leaves an unauthenticated route
querying the user table and only narrows what leaks, which is not an authorisation decision at
all, only a smaller leak.

The second is `permission_callback => '__return_true'` with a nonce check inside the handler.
A nonce proves the request came from a page the user was served, not that the user is allowed
to do anything. It is CSRF protection standing in for an authorisation check, and it is one of
the most common confusions in WordPress code. When that appears in review, the response is that
a nonce answers "did this request come from my form" while a capability check answers "is this
caller allowed", and the route needs the second one.

**Deployment relevance must be established per target.** The reason this record is filed is the
reusable mechanism and its named CVE, not an assumption that Mail Mint is installed on a
particular site.
