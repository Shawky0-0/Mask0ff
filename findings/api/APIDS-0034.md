---
tags: [security, flash, advisories, api, entry, api2, oauth, identity, authorizer]
updated: 2026-08-16
sources:
  - "https://github.com/advisories/GHSA-29rf-f4vv-pvq6, accessed 2026-08-16"
---

# APIDS-0034, register first with the victim's email, never verify it, and let their Google login verify it for you

Related: APIDS-0008 (the other `API2` on a login
flow), MTH-API-001,
the ledger.

**The first OAuth flow entry in this folder.** OAuth, OIDC and JWT attack research has been carried
debt for five runs. This does not close the research gap, but it puts a real identifier and a real
version range against the most classic flow attack there is.

```yaml
id: APIDS-0034
component:
  type: service
  ecosystem: Go
  name: "github.com/authorizerdev/authorizer"
  version_scope: "internal/http_handlers/oauth_callback.go"
affected:
  introduced: ___
  fixed_in: "0.0.0-20260807033110-66fe488fd2a4, released as 2.4.0-rc.16"
  tested_on: ___
identifiers:
  cve: CVE-2026-35511
  ghsa: GHSA-29rf-f4vv-pvq6
  osv: ___
  vendor_id: "commit 66fe488fd2a4e7acf1e517334344d5e8f3ddd296"
class:
  owasp_api: API2 broken authentication
  owasp_2025: ___
  cwe: CWE-287 improper authentication
  family: identity linking on an unproven identifier
protocol: rest
auth_required: none for the attacker. The victim performs an ordinary OAuth login
entry_point: "the OAuth callback handler, for every configured provider (the advisory lists Google, GitHub, Facebook, Apple, LinkedIn, Twitter, Discord, Twitch, Roblox and Microsoft)"
object_graph:
  creates: "the attacker's password account creates the user row first, keyed on the victim's email address, and is never verified"
  owns: "the attacker owns the password. The victim owns the mailbox"
  should_reach: "only the person who proved control of that mailbox should end up holding the account"
  tested_account_got: "the attacker kept a working password on an account that the victim's own Google login then marked verified and started filling with the victim's data"
root_cause: >
  The callback looks up an existing user by email (line 125), swaps the OAuth user object for that
  existing user (line 164), appends the provider to the signup methods (lines 173 to 176), and then
  the decisive part: **if the existing account's email was not verified, it marks it verified**
  (lines 179 to 181). It saves the merged user without invalidating the original password (line 219).
  The missing decision is a check on the existing account's verification status before linking. An
  unverified account is a claim, not an identity, and the code treats it as an identity the moment a
  verified provider agrees about the email string.
signal: >
  Two independent ways to create an account that key on the same identifier, where one of them proves
  control of that identifier and the other does not. The question to ask of any account system is:
  what happens when the same email arrives twice by two different doors, and which door wins.
  **The tell in the code is a merge that adds a credential without removing one.** Read the branch
  where the user already exists, and count what it grants against what it revokes.
safe_proof: >
  Entirely in a lab with two accounts you own. Register account A with password login using an
  address you control at a provider, and skip verification. Then complete the OAuth flow as that same
  address. Read the user row: `email_verified` flipped to true, the signup methods now list both, and
  the original password still authenticates. **The proof is the state of the row, not a takeover.**
  Never run any part of this against an address you do not own.
controls:
  negative: "run the same flow where the pre existing account was verified. If linking still occurs, the finding is broader than the advisory states. If it is refused, the verification flag is confirmed as the deciding input."
  differential: "register the pre existing account through a second OAuth provider instead of a password. If linking two verified providers is allowed and linking a verified provider to an unverified password account is also allowed, the system has no concept of proof at all, only of email string equality."
  false_positive: "some products deliberately allow linking and then force a password reset on the merged account. Check whether the original credential survives, because that is the difference between a merge policy and a takeover. Here the advisory is explicit: the password remains valid."
fix:
  commit: "https://github.com/authorizerdev/authorizer, commit 66fe488fd2a4e7acf1e517334344d5e8f3ddd296. Not read this run"
  invariant: >
    Stated from the defect: an OAuth identity must not be linked to an existing local account whose
    email was never verified, and linking must never itself be the act that marks an email verified.
hardening: >
  Never let one unproven identifier be upgraded by an unrelated proof of the same string. The control
  that kills the class: an unverified registration does not own the address, so it must not occupy
  it. Either hold unverified signups outside the user table until proven, or require the OAuth login
  to reset the local credential rather than inherit it. Notifying the victim is worth doing and is
  not a control, because the advisory's whole point is that a zero click takeover gives them nothing
  to notice.
detection: >
  An account whose `email_verified` flag flips at the same moment a provider is appended to its
  signup methods, with no verification email ever sent. In logs, a password login succeeding on an
  account whose only recent activity was an OAuth callback.
variant_rule: >
  Every system with more than one signup door: WordPress with a social login plugin, Laravel Socialite
  alongside password registration, Firebase Auth account linking, any CRM that creates a contact from
  an email address, and single sign on layered over an existing user table. Also the neighbouring
  shapes: linking on a provider supplied email the provider itself never verified, linking on a
  normalised email so that `a.b@` and `ab@` collide, and linking on a phone number. **On Ahmed's fleet:
  GoHighLevel is an identity store keyed on email and it sits beside WordPress accounts. If a contact
  or a user can be created from either side on the same address, the question in this entry applies
  directly, and nobody has asked it.**
lab:
  install: "authorizer before the fixed pseudo version, in docker, with one OAuth provider configured against a test client"
  snapshot: "container snapshot before, discard after"
  teardown: "docker rm"
provenance:
  source: "GitHub Security Advisory GHSA-29rf-f4vv-pvq6"
  accessed: 2026-08-16
  license_note: "advisory text summarised, not reproduced"
```

## What happens

An attacker signs up with the victim's email address and a password of their choosing. They never
click the verification link, because they cannot: the mailbox is not theirs.

Later the victim signs in with Google, as they always do. The system sees an account already exists
for that email, links Google to it, and, because the account was unverified, marks it verified now.

The attacker's password still works. They log in with the victim's email and their own password, and
the account is theirs, along with everything the victim has done since.

The victim did nothing wrong and saw nothing happen. That is what zero click means here.

## Why it works

The account was a claim, not an identity. Anybody can type any email address into a registration
form, which is exactly why verification exists.

The callback code then treats "an account exists with this email" as if it meant "this person owns
this email". It links the two, and the linking step itself supplies the verification that was never
earned. Google proved the victim owns the mailbox, and that proof was applied to the attacker's row.

The last piece is the one that turns a mess into a takeover: the merge adds the OAuth provider and
does not remove the password. Nothing revokes the credential that was never proven.

## How to reproduce

Two addresses you own, in a lab. Register one with a password and skip verification. Complete the
OAuth flow with the same address. Then read the user row. The verified flag is on, both signup
methods are listed, and the password still authenticates. That is the whole finding and it needs no
victim.

## The fix, and why the obvious fix would not work

Check the verification status before linking.

The obvious fix is to send a verification email when the accounts merge. That does not work, because
the merge already happened and the attacker's password already survived it. It also asks the victim
to notice something they have no reason to expect.

The stronger fix is to stop letting an unverified signup occupy the address at all. If an unproven
claim never gets a row keyed on that email, there is nothing for the OAuth callback to find, nothing
to merge, and nothing to accidentally verify.
</content>
