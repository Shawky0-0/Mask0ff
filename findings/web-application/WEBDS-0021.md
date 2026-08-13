---
tags: [security, flash, advisories, webds, access-control, winter-cms, laravel, php]
updated: 2026-08-13
sources:
  - "https://github.com/advisories/GHSA-j5jq-cr68-v2xx, accessed 2026-08-13"
  - "https://github.com/advisories/GHSA-5c4f-9pq9-6c77, accessed 2026-08-13"
---

# WEBDS-0021, Winter CMS checks handler names on one door and not the other

Winter CMS is built on Laravel, so this is stack adjacent. Related:
the web advisories folder,
MTH-WEB-005, the guard whose condition the attacker controls,
WEBDS-0014, the same shape in Krayin.

```yaml
id: WEBDS-0021
component:
  type: package
  ecosystem: composer
  name: "winter/wn-backend-module, with winter/wn-cms-module as the paired advisory"
  version_scope: "the backend controller handler dispatcher"
affected:
  introduced: ___
  fixed_in: "1.2.13"
  tested_on: ___
identifiers:
  cve: CVE-2026-35445
  ghsa: GHSA-j5jq-cr68-v2xx
  osv: ___
  snyk: ___
  vendor_id: "paired with CVE-2026-32639, GHSA-5c4f-9pq9-6c77, same release"
class:
  owasp_2025: broken access control
  owasp_api: ___
  owasp_llm: not applicable
  cwe: "CWE-285 improper authorisation, and CWE-639 authorisation bypass through a user controlled key"
  family: two entry paths into one dispatcher, only one carries the check
  corpus_directory: 02-access-control-bac-idor/
auth_required: user
entry_point: >
  Any backend form postback that carries a _handler field. The AJAX path
  validates the handler name against the pattern on[A-Z][\w+]*. The postback path
  hands the name straight to the dispatcher with no validation at all.
root_cause: >
  The same dispatcher is reachable two ways, and the name check was written into
  one of them. The Users controller then made it exploitable by anyone signed in,
  because it conditionally nullified its permission requirement for the myaccount
  action, and that nullification applied to the whole controller rather than to
  that one action. So a low privilege user reaching myaccount could call
  update_onDelete, update_onRestore, update_onUnsuspendUser and
  update_onManualPasswordReset with parameters of their choosing. The missing
  decision is: nobody decided that authorisation belongs to the dispatcher, so
  each route into it had to remember on its own.
signal: >
  A framework that names its actions in the request body rather than in the URL.
  Any field called _handler, action, do, method or op is the signal. Then the
  question is whether the same names are reachable from more than one kind of
  request, and whether both kinds validate. In Winter's case, watch for a
  controller that turns its own permission requirement off for one action.
safe_proof: >
  On your own Winter install below 1.2.13, sign in as a user with only the
  lowest backend permission. Create a second throwaway user as the target.
  Postback to the Users controller with _handler set to update_onSuspendUser
  against that throwaway id. The canary is the throwaway account's own suspended
  flag flipping. Suspend rather than delete, because it is reversible and the
  destructive handlers add nothing to the proof.
controls: >
  Negative control: send the same handler name over the AJAX path, with
  X-Requested-With, and confirm it is rejected by the name pattern. That
  contrast is the finding. Second control: confirm the low privilege user cannot
  reach the same action through the normal user interface, so you know you
  bypassed something rather than used a permission you were granted. Third
  control: CSRF protection is still active, so the request needs a valid session
  and token. If your request works without one you have found a different bug and
  should say so.
fix:
  commit_url: "___, the advisory links the v1.2.13 release rather than a commit"
  invariant: >
    Stated by the advisory as: the postback path validates handler names the same
    way the AJAX path does. The underlying rule is that both entry paths agree on
    what a legal handler name is. Not read as a diff this run, so this is the
    advisory's claim rather than something verified in code. The paired advisory,
    CVE-2026-32639, adds granular per handler permission checks in
    Cms\Controllers\Index and theme validation in the AssetList onUpload handler.
hardening: >
  Put the authorisation check in the dispatcher, once, so every path through it
  inherits the same rule. Then treat any permission nullification as scoped to a
  single action by construction rather than by convention, so "this one page is
  open" cannot silently mean "this controller is open".
detection: >
  Backend request logs carrying a _handler value that no rendered page on the
  site would ever produce, especially update_ prefixed handlers submitted by a
  session that never loaded the corresponding edit screen. The mismatch between
  the handler submitted and the page previously fetched is the fingerprint.
variant_rule: >
  Anywhere one action is reachable by two transports. The classic pairs are AJAX
  versus form postback, REST route versus RPC style dispatch, GET versus POST for
  the same handler, a web route and a console command sharing a service, and a
  public API endpoint next to an internal one that calls the same code. In each
  case the question is not "is there a check" but "is there a check on every
  path". The related shape, the OR permission, is the paired advisory: holding
  any one of five theme permissions granted access to all five template types.
lab:
  install: "composer create-project wintercms/winter pinned below 1.2.13, in a throwaway container"
  snapshot: "database snapshot before the run, so the suspended flag can be restored"
  teardown: "drop the container and the database"
provenance:
  source: "GitHub Security Advisories GHSA-j5jq-cr68-v2xx and GHSA-5c4f-9pq9-6c77"
  accessed: 2026-08-13
  license_note: "public advisories, no licence restriction on reading"
```

## What happens

Winter CMS's backend does not put the action in the URL. It puts a name in the
form, `_handler`, and the controller looks up a method by that name.

There are two ways to send that name. If the request looks like AJAX, the name is
checked against a pattern first, so only names starting with `on` and a capital
letter get through. If the request is an ordinary form post, no check runs and
the name goes straight to the lookup.

The Users controller made that reachable for everyone, because it switched off
its permission requirement so that people could open their own account page. Any
signed in backend user could then call the handlers that delete users, restore
users, unsuspend users, and force a password reset.

## Why it works

One dispatcher, two doors, one lock.

The check was written where somebody was thinking about it, in the AJAX path,
and it never travelled to the other path. Nothing about the code says the two
paths are meant to be equivalent, so nothing catches the drift.

Then the second half. A controller that turns off its own permission requirement
"for the my account page" turned it off wider than intended. On its own that is
a small mistake. Combined with an unchecked handler name it is an escalation
from any backend account to user administration.

The transferable rule:

**Count the doors before you check the lock. A check written into a request
handler protects that handler, not the thing behind it.**

## How you would reproduce it

Own install, below 1.2.13. Make a low privilege backend user and a throwaway
target user. Sign in as the low privilege one, and postback to the Users
controller with `_handler` set to a suspend handler and the target's id. Watch
the target's state change.

Then send exactly the same handler name as AJAX and watch it be rejected. That
rejection is what turns a working request into a finding: it shows the product
believes that name should not be callable.

Keep the effect reversible. Suspending proves the dispatch just as well as
deleting, and it can be undone.

## What the fix is, and why the obvious fix would not work

The release makes the postback path validate handler names the same way the AJAX
path does. Note that this was read from the advisory text and not from a diff,
so it is a claim, not something confirmed in code here.

The obvious fix is to fix the Users controller, since that is where the damage
was. That fails because the Users controller was only the first place anyone
looked. The dispatcher stays willing to call any method whose name arrives in a
form field, so the next controller with a slightly loose permission is the next
report.

The second obvious fix is to extend the name pattern check to the postback path
and stop there, which is close to what shipped. It is a real improvement and it
is still not the whole class, because the pattern only says a name looks like a
handler. It does not say the caller is allowed to run that particular handler.
The paired advisory, `CVE-2026-32639`, is the same product learning that lesson
in the CMS module on the same day: broad access to a section had been standing in
for permission on each individual handler.
