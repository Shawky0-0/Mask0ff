---
tags: [security, flash, advisories, webds, laravel, symfony, crlf, injection]
updated: 2026-08-12
sources:
  - "https://github.com/laravel/framework/security/advisories/GHSA-5vg9-5847-vvmq, accessed 2026-08-12"
---

# WEBDS-0013, Laravel CRLF injection in the default email validation rule

Related: the web advisories folder,
WEBDS-0012, the other Laravel item,
MTH-WEB-002, CRLF through a percent decode.

```yaml
id: WEBDS-0013
component:
  type: framework
  ecosystem: composer
  name: laravel/framework
  version_scope: the default email validation rule, in combination with Symfony Mailer and Symfony Mime
affected:
  introduced: ___
  fixed_in: "13.10.0 and 12.60.0"
  tested_on: ___
identifiers:
  cve: CVE-2026-48019
  ghsa: GHSA-5vg9-5847-vvmq
  osv: ___
  snyk: ___
  vendor_id: ___
class:
  owasp_2025: injection
  owasp_api: ___
  owasp_llm: not applicable
  cwe: "___, the advisory does not state one. The shape is CWE-93, improper neutralisation of CRLF sequences"
  family: header injection through a validator that accepts a control character
  corpus_directory: 06-server-side-injection-file-data/
auth_required: none
entry_point: >
  any form field validated with Laravel's email rule whose value later reaches
  Symfony Mailer. Registration, password reset, contact forms, newsletter
  signup, invite by email. Unauthenticated in the ordinary case, because these
  forms are public by design.
root_cause: >
  Laravel's email validation rule accepted values containing carriage return and
  line feed sequences and reported them as valid email addresses. Symfony Mime
  then treats those sequences as header separators when it builds the message.
  The missing decision sits in the validator: it decided the value was a
  syntactically acceptable address without deciding that a control character can
  never appear in one. The advisory is explicit that the impact comes from the
  combination, "in combination with how Symfony Mailer and Symfony Mime handle
  certain character sequences", not from either component alone.
signal: >
  A registration or contact form that accepts an address containing an encoded
  newline and does not reject it at validation. The observable is the validator
  returning valid, before any mail is sent.
safe_proof: >
  In a disposable app wired to a local mail catcher such as Mailpit or
  MailHog, submit an address carrying a CRLF and a benign extra header
  containing a canary token. The proof is the canary appearing as a header in
  the caught message. Nothing leaves the lab, no real mail server is involved,
  and the injected header does nothing but carry the marker.
controls: >
  Negative control: submit the same address with the CRLF removed and confirm
  only the expected headers appear. Differential control: compare the caught
  message headers between the two submissions, so the extra header is shown to
  come from your input and not from the mailer's own behaviour. Without a local
  catcher you cannot see headers at all, and guessing from a bounce message is
  not evidence.
fix:
  commit_url: ___
  invariant: >
    ___. The advisory states the fixed versions but does not link a commit, and
    the fix commit was not read. Recorded as unknown rather than guessed.
    The expected invariant is that the email rule rejects any value containing a
    control character, so a value that passes validation can never carry a
    header separator.
hardening: >
  Validate on an allow list of the characters an address may contain, rather
  than checking the value looks roughly like an address. Then encode again at
  the mail layer. Two independent checks, because the validator and the mailer
  are maintained by different people who disagree about whose job this is,
  which is exactly the gap this bug lived in.
detection: >
  Mail logs showing a message with duplicated or unexpected headers, or more
  recipients than the application intended. At the web layer, a request body
  containing %0d%0a inside an email field.
variant_rule: >
  Any validator that hands a string to a protocol where a newline is
  structural. Email headers, HTTP response headers, SMTP, LDAP, log files, and
  CSV export. The question is always the same: does the thing that said "valid"
  know what the next layer treats as a separator?
lab:
  install: "Laravel below 12.60.0, plus Mailpit in Docker as the mail transport"
  snapshot: "container snapshot before the first submission"
  teardown: "drop both containers, no external mail service ever configured"
provenance:
  source: "GitHub Security Advisory GHSA-5vg9-5847-vvmq, reported by OmarXtream"
  accessed: 2026-08-12
  license_note: "public advisory, no licence restriction on reading"
```

## What happens

A public form asks for an email address. Laravel checks it with the built in
email rule and says it is fine. The address is then used to send mail. Because
the address was allowed to contain a newline, and because a newline is how the
mail format separates one header from the next, whatever the attacker put after
the newline becomes a header of its own.

## Why it works

Email messages are headers, then a blank line, then the body. The separator is a
CRLF. If a value that lands in a header contains a CRLF, the attacker stops
writing a value and starts writing headers.

The severity is 8.9 and the scope is marked changed in the CVSS vector, which is
the interesting part. Scope changed means the damage lands somewhere other than
the vulnerable component. Here the vulnerable code is a validator in a PHP
application, and the damage lands on the mail infrastructure: mail relay abuse,
messages redirected to recipients the application never chose, and content the
application never wrote. The advisory is careful that severity "depends on what
the application sends by email and how its mail infrastructure is configured".

Note that no authentication is required. Signup and password reset forms are
public because they have to be.

## How you would reproduce it

Point a vulnerable Laravel app at a local mail catcher. Submit a registration
with an address carrying an encoded CRLF followed by a harmless header holding a
canary string. Open the caught message and look at the headers. If the canary is
there as a header, the injection worked. Then submit again without the CRLF and
diff the headers.

Use a catcher, never a real mail server. Sending real mail from a test is how a
lab exercise turns into someone else's incident.

## What the fix is, and why the obvious fix would not work

Upgrade to 12.60.0 or 13.10.0. The commit was not read, so what the patch
actually enforces is recorded as unknown rather than guessed.

The obvious fix is to strip newlines from the address just before sending. That
is weaker than it looks. It puts the check in one call site, and every other
place the address is used, logging, a CRM sync, an audit trail, a webhook, keeps
the bad value. The value was declared valid at the door, so it now travels
everywhere with a clean bill of health. Rejecting it at validation is the only
place that fixes every downstream consumer at once.

This is also the reason the bug is worth Ahmed's attention beyond Laravel. Two
components were each behaving reasonably. The validator thought its job was
syntax. The mailer thought its input had been validated. Nobody owned the
control character question, so nobody handled it.
