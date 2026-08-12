---
tags: [security, flash, advisories, method, laravel, middleware, authentication, source-review]
updated: 2026-08-12
sources:
  - "https://jivasecurity.com/writeups/krayin-installer-bypass-account-takeover-cve-2026-41452, accessed 2026-08-12"
---

# MTH-WEB-005, read the route file for the middleware that was taken off

Related: the web advisories folder,
WEBDS-0014, the Krayin entry this came from,
MTH-WEB-004.

## The technique in one line

Open the framework's route definition file, find every route that has protection
explicitly removed or conditionally skipped, and ask what condition the attacker
controls.

## The discovery signal

The researcher did not scan Krayin. They read
`packages/Webkul/Installer/src/Routes/web.php` and noticed three POST endpoints
declared `withoutMiddleware('web')`.

That declaration is the signal. It is a developer writing down, in the source,
that the normal protections do not apply here. In Laravel the `web` middleware
group carries session handling and CSRF verification, so removing it is a
deliberate statement that this route is different. Developers do it for real
reasons, usually because an API style call was failing CSRF. The reason is
almost always legitimate and the consequence almost never gets revisited.

Generalised: **look for the places where somebody had to make an exception to
make the feature work.** Exceptions are written down, they are rare enough to
enumerate, and they are where the guarantees stop.

## The mechanism

Two related things live in a route file.

**Protection removed outright.** `withoutMiddleware()`, or a route registered
outside the protected group. Whatever that middleware was doing, it is not doing
it here.

**Protection made conditional.** The middleware runs but its guard has an AND in
it, and part of that AND is a property of the request. Krayin's was:

```
if ($this->isAlreadyInstalled() && ! $request->ajax())
```

Read the boolean as an attacker. The guard fires only when both halves are true.
`isAlreadyInstalled()` is a fact about the server and you cannot change it.
`$request->ajax()` is a fact about your request, decided entirely by whether you
send `X-Requested-With: XMLHttpRequest`. So you control half of the condition,
and controlling half of an AND is enough to make the whole thing false.

The general rule this teaches, and it is the transferable part:

**When a security guard's condition mentions anything about the incoming request,
the attacker has a vote on whether the guard runs.**

## Which class it belongs to, and which stacks

Authentication, session, OAuth and JWT, corpus directory
`03-authentication-session-oauth-jwt/`, with an access control flavour.

Directly applicable to Ahmed's stack. Laravel is named in
the company stack, and the pattern is a Laravel idiom. The same
shape exists everywhere under a different spelling: Symfony security annotations
and access control rules in `security.yaml`, Express routers where a
`router.use()` guard is registered after some routes rather than before, Django
decorators and `@csrf_exempt`, and Spring's `permitAll()` matchers. The
WordPress equivalent is a callback registered with `permission_callback` set to
`__return_true`, which is worth passing to the sibling sweep as a search string.

## A safe way to test for it

This is a source reading method first, which makes it the cheapest and safest
kind, and the one that needs no authorisation gate at all when the code is
public.

1. Find the route definitions. Laravel: `routes/*.php` and any package's
   `Routes/` directory. Grep for `withoutMiddleware`, `->middleware(`,
   `Route::group`, and any route registered outside a group.
2. List every exception you find, with the reason if a comment gives one.
3. For each, open the middleware it would have hit and read the guard condition.
   Write the condition out as a boolean and mark which terms the client controls.
4. Only then, and only against a lab install Ahmed owns, send the request with
   and without the controlled term. The pair of responses is the evidence.

For a live target, stop at step 3 and report. Steps 1 to 3 are reading, and
reading is always in scope. Step 4 is a request against a system, and the Flash
lane's authorisation gate applies to it in full.

## The control that would catch a false positive

**Send the identical request without the controlled term.** In the Krayin case,
the same POST with no `X-Requested-With` header should redirect. If both requests
behave the same way, the header is not what let you in and your explanation is
wrong even if your result is real.

The second control is confirming the precondition the guard was meant to check.
Krayin's guard only matters on an installed system, so check the application
genuinely reports itself installed. Testing a half installed instance and
reporting an installer bypass would be embarrassing and wrong.

The third is source to behaviour agreement. If the code says the guard should
have fired and the guard did not fire, you have understood it. If you cannot
explain the observed behaviour from the code you read, you have found something
else and should keep reading before writing it up.

## Where else this shape appears

Search for the boolean shape rather than the product. Any guard of the form
`if (production && !debug)`, `if (installed && !ajax)`, `if (authenticated &&
!api)`, `if (locked && !admin_override)`. The right hand term is nearly always
the attacker's.

Then the specific recurring cases: install and setup wizards that survive
install, first run and onboarding flows, health and status endpoints gated on a
header, debug toolbars enabled by a query parameter or cookie, maintenance mode
bypasses, and feature flags read from a request header. All of them are the same
bug wearing different clothes.

## Provenance

Jiva Security, "One Header, Total Compromise: Pre-Auth Admin Takeover in Krayin
CRM 2.2.0 (CVE-2026-41452)". Read at
`https://jivasecurity.com/writeups/krayin-installer-bypass-account-takeover-cve-2026-41452`,
accessed 2026-08-12.

The page carried a working curl exploit command. It was read and summarised into
WEBDS-0014 and **not executed**,
per rule 2 of the sweep. No text on the page was addressed to an automated
reader.
