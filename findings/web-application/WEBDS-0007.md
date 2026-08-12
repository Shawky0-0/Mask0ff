---
tags: [security, flash, advisories, entry, web, proxy, headers, php, codeigniter]
updated: 2026-08-12
sources:
  - "https://github.com/codeigniter4/CodeIgniter4/security/advisories/GHSA-7wmf-pw8j-mc78 accessed 2026-08-12"
---

# WEBDS-0007: CodeIgniter trusts X-Forwarded-Proto from anyone, so isSecure lies

Related: the CodeIgniter SQL injection from the same day,
the Nuxt cache key bug.

```yaml
id: WEBDS-0007
component: { type: framework, ecosystem: composer, name: codeigniter4/framework, version_scope: "the 4.x line" }
affected: { introduced: ___, fixed_in: "4.7.4", tested_on: "not tested, desk research only" }
identifiers: { cve: CVE-2026-63220, ghsa: GHSA-7wmf-pw8j-mc78, osv: ___, snyk: ___, vendor_id: ___ }
class: { owasp_2025: "security misconfiguration, by way of trusting a client supplied header", owasp_api: ___, owasp_llm: not_applicable, cwe: "___, the advisory does not state one. CWE-348, use of less trusted source, is the usual mapping", family: "the application trusts a hop by hop header that any client can set", corpus_directory: 07-protocol-cache-routing }
auth_required: none
entry_point: "the X-Forwarded-Proto and Front-End-Https request headers, on any route whose behaviour depends on IncomingRequest::isSecure()"
root_cause: >
  isSecure() treated two request headers as evidence about the transport. They are not
  evidence, they are claims: a header is only trustworthy if a trusted proxy set it and
  stripped any client supplied copy first, and the framework had no way of knowing whether
  that happened. The missing decision is a trusted proxy check between reading the header and
  believing it. The framework asked "is this header present" instead of "did somebody I trust
  put it there".
signal: >
  Any security decision that reads a header beginning X-Forwarded, Forwarded, Front-End, True-
  Client-IP, CF-Connecting-IP or similar. All of them are hop by hop hints, all of them are
  client settable at the origin, and applications routinely use them for HTTPS enforcement,
  IP allow listing, rate limit keys, and audit logs. The observable signal is a request sent
  over plain HTTP that the application reports as secure.
safe_proof: >
  In a lab, request a page over plain HTTP directly against the origin with
  X-Forwarded-Proto: https set, and confirm the application does not issue its usual HTTPS
  redirect, or that a page echoing isSecure() reports true. Read only, one request, nothing
  written.
controls:
  - "Negative control: the same request without the header must redirect or report insecure. That proves the header is the variable."
  - "Differential control: send the header through the real proxy path instead of directly to the origin. If the proxy overwrites it, the finding is limited to whoever can reach the origin directly, which changes the severity and must be stated rather than assumed."
  - "False positive to rule out: an application that never calls isSecure() at all. Confirm there is a real decision hanging off it before writing it up."
fix: { commit_url: ___, invariant: "forwarding headers are only honoured when the immediate peer is a configured trusted proxy. Anything else is ignored" }
hardening: >
  Two layers, and you want both. At the proxy, always strip or overwrite the forwarding headers
  on the way in, so a client copy can never survive. At the application, configure the trusted
  proxy list explicitly, and default to not trusting. The infrastructure control that makes the
  whole question academic is refusing plain HTTP at the origin, so the origin cannot be reached
  except through the proxy.
detection: >
  Requests arriving at the origin with forwarding headers already set, seen from a source that
  is not the proxy. Worth an explicit log field, because on a normal day that number is zero
  and any nonzero value is interesting.
variant_rule: >
  Same shape, higher stakes, in three other places. IP based access control keyed on
  X-Forwarded-For, where a spoofed header reaches an admin panel restricted by IP. Rate
  limiting keyed on the same header, where a spoofed value resets the counter every request.
  And Host header trust, where a spoofed Host lands in a password reset link. In all four the
  question is identical: who set this, and can I prove it.
lab: { install: "composer create-project codeigniter4/appstarter pinned below 4.7.4, one route that calls force_https() or echoes isSecure()", snapshot: "the project directory and composer.lock", teardown: "delete the directory" }
provenance: { source: "https://github.com/codeigniter4/CodeIgniter4/security/advisories/GHSA-7wmf-pw8j-mc78", accessed: 2026-08-12, license_note: "vendor security advisory, public" }
```

## What happens

When a reverse proxy terminates HTTPS and forwards the request onward over plain HTTP, the
application behind it has no way to know the original connection was encrypted. The convention
is that the proxy adds a header saying so. CodeIgniter believed that header, `X-Forwarded-Proto`
or `Front-End-Https`, without checking who sent it. Anyone who can reach the application
directly can set it themselves and be told they are on a secure connection. Rated 4.8,
moderate, which is fair for the direct impact and understates how often this is one link in a
longer chain.

## Why it works

Nothing about the header is authenticated. It is a note taped to the request. The design
assumes a topology, which is that the only way to reach the application is through the proxy
and the proxy always overwrites the header, and it silently fails when that topology is not
true. It stops being true more often than people expect: a container exposed on the host
network, a health check port, an internal load balancer that forwards without rewriting, a
staging environment nobody put a proxy in front of, or a second ingress added later.

## How you would reproduce it

One request, in a lab. Hit the origin over plain HTTP with `X-Forwarded-Proto: https` and watch
the HTTPS redirect not happen.

## Why the low score is not the whole story

The direct impact is that HTTPS enforcement can be skipped. The reason to care more is the
family, not this instance. The same "trust a header nobody authenticated" mistake keyed on
`X-Forwarded-For` gives IP allow list bypass into admin panels and free rate limit resets, and
fleet, and this is the cheapest possible way to learn to ask the question.

## What the fix is, and why the obvious fix is not enough

The obvious fix is to redirect HTTP to HTTPS at the load balancer, which the advisory suggests,
and it does help. It is not sufficient on its own, because it fixes the symptom for this one
header while leaving the application still believing whatever it is told. The fix in 4.7.4 is
the right one: only honour forwarding headers from a configured trusted proxy. And the proxy
should still strip the client copy, because two independent controls is the point.
