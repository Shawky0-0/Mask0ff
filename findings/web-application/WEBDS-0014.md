---
tags: [security, flash, advisories, webds, laravel, authentication, middleware, crm]
updated: 2026-08-12
sources:
  - "https://jivasecurity.com/writeups/krayin-installer-bypass-account-takeover-cve-2026-41452, accessed 2026-08-12"
  - "https://www.vulncheck.com/advisories/krayin-crm-missing-authentication-via-install-api-admin-config-setup, accessed 2026-08-12"
---

# WEBDS-0014, Krayin Laravel CRM, pre auth admin takeover through the installer middleware

**First entry in the authentication and session class, which was at zero.**
Related: the web advisories folder,
MTH-WEB-005, read the route file for middleware exceptions,
WEBDS-0012, the other Laravel item.

```yaml
id: WEBDS-0014
component:
  type: service
  ecosystem: composer
  name: krayin/laravel-crm
  version_scope: the Installer package, packages/Webkul/Installer
affected:
  introduced: ___
  fixed_in: ___
  tested_on: "2.2.0 per the researcher writeup"
identifiers:
  cve: CVE-2026-41452
  ghsa: ___
  osv: ___
  snyk: ___
  vendor_id: ___
class:
  owasp_2025: broken authentication
  owasp_api: "API2, broken authentication"
  owasp_llm: not applicable
  cwe: "CWE-306, missing authentication for critical function"
  family: setup endpoint left live after setup
  corpus_directory: 03-authentication-session-oauth-jwt/
auth_required: none
entry_point: >
  POST to /install/api/admin-config-setup, with the header
  X-Requested-With: XMLHttpRequest. Two sibling install/api routes are in the
  same route file and are declared withoutMiddleware('web'), so no CSRF token is
  required either.
root_cause: >
  The CanInstall middleware guards the installer routes with
  "if ($this->isAlreadyInstalled() && ! $request->ajax())". The redirect away
  from the installer therefore only fires when the application is installed AND
  the request is not AJAX. Setting X-Requested-With makes $request->ajax()
  return true, the second half of the AND is false, and the guard does nothing.
  The missing decision is named and located: the AJAX exception was added so the
  installer's own XHR calls could work during setup, and nobody decided it had
  to stop applying once setup finished. The middleware answers "is this a
  browser navigation" when the only question that matters is "is this thing
  already installed".
auth_note: >
  The endpoint then overwrites the user at hardcoded id 1, which is the primary
  administrator. So the attacker does not bypass a login, they replace the
  account that owns the login.
signal: >
  An /install or /setup route tree that still answers on a running production
  application. Any answer other than a redirect to the dashboard, including a
  422 validation error, means the guard is not stopping you. A 422 is the
  giveaway: it means your request reached the controller.
safe_proof: >
  In a disposable local install, send the POST with X-Requested-With and a
  canary email at a domain you own in the lab, for example
  canary-WEBDS0014@lab.invalid. The proof is the admin row changing to the
  canary address. Do not use a real address, do not use a real domain, and do
  not run this anywhere but the lab. Against a live system this destroys the
  real administrator's access, which makes it destructive, not a test.
controls: >
  Negative control: send the identical request without the X-Requested-With
  header and confirm you are redirected to the dashboard. That one difference is
  the entire finding, and without it you have only shown that an installer
  exists. Differential control: confirm the application genuinely reports itself
  as installed first, otherwise you have found a machine mid setup, which is a
  different and much less interesting problem.
fix:
  commit_url: ___
  invariant: >
    Per the researcher writeup, the fix is to drop the AJAX exception, leaving
    "if ($this->isAlreadyInstalled())". The invariant is that installed means
    installed, for every request shape, with no exception for how the request
    was made. The upstream commit was not read, so the commit URL stays unknown.
hardening: >
  Delete or physically remove installer code after deployment rather than
  guarding it. A guard is a decision that can be got wrong once; an absent file
  cannot be. Where the code must stay, gate it on a filesystem lock the web user
  cannot write, and never on a property of the incoming request. Anything the
  client sends is under the attacker's control, and a header is the easiest
  thing in the world to set.
detection: >
  Any request to an /install path on a live system is worth an alert on its own.
  In logs, a POST to install/api/* returning 200 rather than 302. In the
  database, the admin row's updated_at changing without a corresponding admin
  session. The writeup notes there is no rate limiting on these endpoints, so
  there is nothing throttling repeated attempts either.
variant_rule: >
  Look for the shape, not the product. Any middleware whose condition is an AND
  with a request property on the right hand side: is_installed AND not ajax,
  is_production AND not debug, is_authenticated AND not api. The attacker
  controls the right hand side, so they control the whole expression. Also
  every setup wizard in every CMS and CRM, health and status endpoints, and
  debug toolbars gated on a header. The Laravel specific tell is
  withoutMiddleware('web'), which also strips CSRF.
lab:
  install: "Krayin 2.2.0 in Docker on an isolated network, complete the installer so the app is genuinely installed"
  snapshot: "snapshot after install and before the first request, because the proof overwrites the admin account"
  teardown: "drop the container and the volume"
provenance:
  source: "Jiva Security writeup, plus the VulnCheck advisory for the identifier"
  accessed: 2026-08-12
  license_note: "public writeup, read only. The exploit command in it was read and summarised, never executed"
```

## What happens

Krayin is a CRM built on Laravel. Like most self hosted applications it ships a
web installer: you visit `/install`, fill in the database details and the
administrator account, and it sets itself up. After that the installer is
supposed to be closed off.

It is not closed off. Send one POST to the installer's admin setup endpoint with
one extra header, and it will happily set the administrator account again, on a
system that has been running for months. You supply the name, the email and the
password. You are now the administrator, and you were never asked to log in.

## Why it works

The guard reads, in effect: if we are already installed, and this is not an AJAX
request, send them to the dashboard.

Read that as an attacker. There are two ways to avoid being sent to the
dashboard. Do not be installed, which you cannot arrange. Or be an AJAX request,
which you arrange by adding one header.

`X-Requested-With: XMLHttpRequest` is a convention from the jQuery era. It is
not a security feature, it has never been a security feature, and any client can
set it. Laravel's `$request->ajax()` is just a helper that looks for it.

The reason the exception was there at all is understandable: during setup the
installer's own JavaScript calls these endpoints, and if the middleware
redirected those calls the wizard would break. The developer needed the
exception to be true during install. They did not notice they had also made it
true forever after.

## How you would reproduce it

Install Krayin 2.2.0 in a container, on an isolated network, and finish the
setup so it is genuinely a live installed application. Snapshot it, because what
follows overwrites the admin account.

Send the POST to `/install/api/admin-config-setup` with `X-Requested-With:
XMLHttpRequest`, a JSON body with a canary email, and no session, no cookie, no
CSRF token. Then check the admin row.

Then restore the snapshot and send the same request without the header. You
should be redirected. That pair of results is the evidence. One request on its
own proves nothing.

## What the fix is, and why the obvious fix would not work

Remove `&& ! $request->ajax()`.

The obvious fix is to require a CSRF token on the installer routes. It does not
help. CSRF protection stops another site making a request using a victim's
session. Here there is no victim and no session; the attacker sends the request
directly, and would simply fetch a token first if one were needed. CSRF is the
wrong control for a missing authentication bug, and reaching for it is a common
way to close a ticket without closing the hole.

The other obvious fix is to check for an admin session on the installer routes.
That is closer, but it inverts the intent: during a genuine first install there
is no admin yet, so the check would either block real installs or need its own
exception, and the exception is what caused this in the first place.

The real lesson is the one worth carrying to the YZH fleet. This is not a Krayin
bug in any deep sense. It is a setup endpoint that outlived setup, and the
gate on it asked a question about the request instead of a question about the
system. Ahmed will meet that shape again, and it will not be in a CRM.
