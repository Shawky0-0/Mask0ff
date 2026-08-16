---
tags: [security, flash, advisories, appsec, graphql, api, ssrf, webds]
updated: 2026-08-16
sources:
  - "https://api.osv.dev/v1/vulns/CVE-2026-72784, accessed 2026-08-16"
  - "https://github.com/advisories?query=graphql, accessed 2026-08-16"
---

# WEBDS-0029: Craft CMS blocks the private ranges it remembers, and CGNAT and NAT64 are not on the list

```yaml
id: WEBDS-0029
component:
  type: framework
  ecosystem: composer
  name: craftcms/cms
  version_scope: "the GraphQL save<Volume>Asset mutation, and the validateIp() helper behind it"
affected:
  introduced: "4.0.0-RC1 on the 4 branch, 5.0.0-RC1 on the 5 branch"
  fixed_in: "4.18.2 and 5.10.6"
  tested_on: "___, not installed by this sweep"
identifiers:
  cve: CVE-2026-72784
  ghsa: GHSA-2mx8-9ww7-p27x
  osv: CVE-2026-72784
  snyk: ___
  vendor_id: ___
class:
  owasp_2025: "server side request forgery"
  owasp_api: "API7, server side request forgery"
  owasp_llm: n/a
  cwe: CWE-918, server side request forgery
  family: API surface reaching an outbound fetch
  corpus_directory: 04-api-graphql-websocket-cors/
auth_required: user
entry_point: "the GraphQL save<Volume>Asset mutation, with a GraphQL token scoped to asset creation"
root_cause: >
  The mutation fetches a URL the caller supplies, and the anti SSRF check is a deny list of
  address ranges held in validateIp(). Per the OSV record that list does not contain the
  CGNAT range 100.64.0.0/10 or the NAT64 prefix 64:ff9b::/96. The missing decision is that
  a deny list of address ranges is being asked to answer the question "is this destination
  internal", which it cannot, because the set of ways to write an internal destination is
  open ended and the list is closed.
signal: >
  A write endpoint that takes a URL rather than a file. The word "import", "from URL",
  "remote", "fetch" or "sideload" next to an upload feature. Once you see it, the question
  is never whether there is a filter, it is which notations the filter's author had in mind
  the day they wrote it. Second signal, specific to GraphQL: an SSRF reachable from a
  scoped token is often missed by testers who only exercise the REST surface, because the
  same capability is exposed twice and only one copy is audited.
safe_proof: >
  Lab instance only, and the destination must be a host inside the lab that you own. Stand up
  a listener on a lab address inside the CGNAT range, ask the mutation to fetch it, and take
  the arrival of the request as the canary. Never point this at 169.254.169.254 or any cloud
  metadata service on a system that is not yours, and never at a YZH or client address.
controls: >
  Negative control: the same mutation with a plain 127.0.0.1 or 10.0.0.0/8 target, which the
  filter should block. A block there and a pass on the CGNAT address is what proves the
  finding is the gap in the list and not a filter that is simply absent. Differential control:
  a public address you control, to confirm the fetch works at all and that a failure is a
  block rather than a network problem. DNS control: resolve the hostname yourself first, so a
  pass caused by a resolver returning something unexpected is not mistaken for a filter gap.
fix:
  commit_url: "___, no commit was located this run. The advisory page github.com/craftcms/cms/security/advisories/GHSA-2mx8-9ww7-p27x was not opened"
  invariant: "___, not read"
hardening: >
  The control that kills the class is not a longer list. It is resolving the hostname once,
  checking the resolved address against an allow list of destinations the feature is meant to
  reach, and then connecting to that same resolved address rather than re resolving the name.
  Better still, take the fetch out of the application entirely and put it behind an egress
  proxy that has its own allow list, so a gap in application code cannot reach anything.
detection: >
  Outbound connections from the web application to addresses it has no business reaching.
  On the application side, a spike of asset records whose source URL is an IP literal rather
  than a domain. A WAF is close to useless here because the request is a legitimate mutation
  with a legitimate parameter.
variant_rule: >
  The catalogue in MTH-WEB-009 applies whole.
  CGNAT 100.64.0.0/10, NAT64 64:ff9b::/96, IPv4 mapped IPv6, decimal and octal integer
  literals, 0.0.0.0, short forms like 127.1, redirects that land somewhere the first check
  never saw, and DNS names that resolve to a private address. Then look for the sibling
  surfaces on the same product: webhooks, avatar import, favicon fetch, oEmbed and link
  preview, PDF and image conversion by URL, and any "test connection" button.
lab:
  install: "craftcms/cms 5.10.5 in docker, with a GraphQL token scoped to asset creation, and a second container holding the listener"
  snapshot: "compose snapshot before the first mutation"
  teardown: "remove both containers and the lab network. No address outside the lab is ever a target"
provenance:
  source: "https://api.osv.dev/v1/vulns/CVE-2026-72784"
  accessed: 2026-08-16
  license_note: "OSV record, open data, read only"
```

## What happens

Craft CMS has a GraphQL mutation for saving an asset. You can give it a URL and it will go and
fetch that URL from the server, then store what comes back.

The code tries to stop you pointing it at the server's own network. It checks the address
against a list of ranges that count as internal. Two ranges are missing from that list: the
carrier grade NAT range `100.64.0.0/10`, and the NAT64 prefix `64:ff9b::/96`.

So you write the internal address you want in one of those two forms, the check says it is fine,
and the server fetches it for you and hands you the result.

## Why it works

The filter is a deny list. A deny list works when the set of bad things is small and known. The
set of ways to write an internal address is neither.

NAT64 is the sharper of the two. It is a standard prefix that lets an IPv6 only network reach
IPv4 hosts: you take the IPv4 address, put `64:ff9b::` in front of it, and the network does the
translation for you. So `64:ff9b::a9fe:a9fe` is the cloud metadata address written in IPv6.
A string comparison against a list of IPv4 ranges will never see it. The network stack will.

That gap between what the filter reads and what the socket does is the mechanism. The filter is
reading a string. The socket is resolving an address. They are answering different questions.

This is the second time this exact pair has landed in this folder in four days.
WEBDS-0019 is Open WebUI blocking the metadata
address and then fetching the same address written as NAT64. Same prefix, different product,
different language, two weeks apart. That is what a class looks like.

## How you would reproduce it

In a lab, with a listener you own inside the CGNAT range. Ask the mutation to fetch it. If the
listener records a connection, the filter passed an internal address.

Run the plain `127.0.0.1` version too, and confirm that one is blocked. Without that control you
have not shown a gap in the list, only that requests go out.

## What the fix is, and why the obvious fix would not work

No commit was read this run, so what the patch actually enforces is `___` and recorded as debt.

The obvious fix is to add the two ranges to the list. That fixes today and guarantees this
advisory again next year, because the next notation is already out there. The catalogue in
MTH-WEB-009 has more entries than any product's deny list has ever had.

The fix that ends it is to invert the question. Instead of asking "is this address on the bad
list", ask "is this address on the short list of places this feature is allowed to go". That
list is small, closed, and written by somebody who knows what the feature is for. Then connect
to the address you checked, not to the name, so a second DNS lookup cannot return something
different from the first.

Related: WEBDS-0019 and
MTH-WEB-009.

**Class note.** Counted once, under API, GraphQL, WebSocket and CORS, because the entry point is
a GraphQL mutation reachable with a scoped token and that class is the thinnest in this folder.
The mechanism belongs equally to recon and cloud infrastructure, and a reader looking for SSRF
should find it from either direction.
