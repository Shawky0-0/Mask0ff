---
tags: [security, flash, advisories, webds, recon, ssrf, cloud-metadata, llm, rag, open-webui]
updated: 2026-08-13
sources:
  - "https://github.com/advisories/GHSA-8x5v-cpv7-8jjp, accessed 2026-08-13"
---

# WEBDS-0019, Open WebUI blocks the metadata address, then fetches the same address written another way

**Second entry in the recon and cloud infrastructure class, and it is also an AI
surface bug.** Related: the web advisories folder,
WEBDS-0010, the other AI plumbing bug,
MTH-WEB-009, the filter reads a string and the socket reads an address.

```yaml
id: WEBDS-0019
component:
  type: service
  ecosystem: other
  name: open-webui
  version_scope: "the RAG web retrieval path, pip package open-webui"
affected:
  introduced: "0.9.0"
  fixed_in: "0.11.0"
  tested_on: ___
identifiers:
  cve: CVE-2026-70485
  ghsa: GHSA-8x5v-cpv7-8jjp
  osv: ___
  snyk: ___
  vendor_id: ___
class:
  owasp_2025: server side request forgery
  owasp_api: ___
  owasp_llm: "LLM plumbing rather than the model itself, the RAG ingestion fetcher"
  cwe: "CWE-918, server side request forgery"
  family: allowlist bypass by alternative address encoding
  corpus_directory: 01-recon-cloud-infrastructure/
auth_required: user
entry_point: >
  POST /api/v1/retrieval/process/web, the endpoint that takes a URL and fetches
  it so the model can read the page. Any verified account reaches it. No admin
  role is needed.
root_cause: >
  validate_url() in backend/open_webui/retrieval/web/utils.py asked whether the
  destination address is globally routable, and it asked that question of the
  literal address it was given. An IPv6 address in the NAT64 well known prefix
  64:ff9b::/96 carries an IPv4 address inside its last 32 bits. The check saw a
  global IPv6 address and said yes. The network stack, later, sent the packet to
  the IPv4 address inside it. The missing decision is: nobody decided that an
  address must be reduced to its final destination before it is judged. The same
  gap existed in _ssrf_safe_new_conn() and _SSRFSafeResolver, so all three
  checkpoints shared the blind spot.
signal: >
  A feature that fetches a URL you supply, plus a denial message rather than a
  silent failure when you point it at 169.254.169.254. A product that returns
  400 for the metadata address has a filter, and a filter is a thing with edges.
  The message tells you where to push.
safe_proof: >
  In a disposable container of your own, run the vulnerable version and point
  the fetch at a webserver you control at a private address, reached through the
  NAT64 form of that address. The canary is a unique marker string served by
  your own listener. Do not point it at any real metadata service and do not
  request any credential path. The proof is that a private destination was
  reached at all, not what was found there.
controls: >
  Negative control: request the plain IPv4 form of the same private address and
  confirm you get the 400. Without that, a success proves nothing, because the
  filter might not have been on. Differential control: request the NAT64 form of
  a public address you own and confirm it also succeeds, which shows the
  encoding itself is accepted rather than the request having silently failed
  somewhere else. Environment control: the advisory says a NAT64 gateway must be
  present on the deployment network. Confirm that before reporting, or you have
  a theory rather than a finding.
fix:
  commit_url: "https://github.com/open-webui/open-webui/commit/1717b493d83c86afa82aa8bc50139250852dd2f3"
  invariant: >
    An IPv4 address embedded in an IPv6 transition encoding is unwrapped before
    the globally routable test runs, and it is unwrapped at all three
    checkpoints, not one. The rule is: judge the destination you will actually
    reach, not the string you were handed.
hardening: >
  Do not decide this in the application. Give the fetcher its own network
  namespace or egress proxy that can only reach the public internet, so the
  private ranges and the metadata service are not routable from that process at
  all. On AWS, require IMDSv2 so a plain GET cannot lift credentials even if
  something does reach 169.254.169.254. Both controls survive the next encoding
  nobody thought of.
detection: >
  Outbound connection logs from the application host to 169.254.169.254, to
  link local ranges, or to any address inside 64:ff9b::/96. In the application,
  a fetch request whose URL contains a bracketed IPv6 literal at all is worth an
  alert, because ordinary users paste ordinary links.
variant_rule: >
  Every way of writing an address that a filter and a resolver read differently.
  IPv4 mapped IPv6 (::ffff:169.254.169.254), decimal and octal and hexadecimal
  IPv4 (2852039166 for 169.254.169.254), a DNS name that resolves to a private
  address, DNS rebinding where the name resolves twice, a redirect from a public
  URL to a private one, and shorthand forms like http://169.254.169.254 written
  with fewer octets. Same shape wherever a URL is accepted: avatar fetchers,
  webhook senders, PDF and screenshot renderers, link previews, import from URL,
  and every RAG ingestion path.
lab:
  install: "docker run the pinned open-webui image below 0.11.0, on an isolated bridge network"
  snapshot: "container snapshot before any request"
  teardown: "docker rm the container and the network, no cloud account involved"
provenance:
  source: "GitHub Security Advisory GHSA-8x5v-cpv7-8jjp, credited to tonghuaroot"
  accessed: 2026-08-13
  license_note: "public advisory, no licence restriction on reading"
```

## What happens

Open WebUI lets a signed in user hand it a link so the model can read that page.
Before fetching, it checks that the link points somewhere on the public
internet. Pointing it at the cloud metadata address, `169.254.169.254`, is
refused with a 400.

There is another way to write that same address. IPv6 has a prefix,
`64:ff9b::/96`, whose whole job is to carry an IPv4 address inside an IPv6 one.
Written that way the metadata address becomes `[64:ff9b::a9fe:a9fe]`. The check
looks at that and sees an ordinary public IPv6 address, so it allows it. The
packet still ends up at `169.254.169.254`.

On a cloud host, that address hands out the machine's own credentials to anyone
who asks it. So an ordinary user account can read the server's identity.

## Why it works

The filter and the network are reading two different things.

The filter reads a **string** and classifies it. The network reads an
**address** and delivers to it. Between those two moments the string gets
translated, and the filter never saw the result of the translation.

`a9fe:a9fe` is just `169.254.169.254` written in hexadecimal, split into two
halves. `a9` is 169, `fe` is 254. The address was never hidden. It was only
spelled differently, and the check was spelling sensitive.

The general rule, and it is the transferable part:

**Judge the destination, not the notation. If the check runs before a
translation step, the check is on the wrong side of it.**

## How you would reproduce it

Run a vulnerable Open WebUI in a container on an isolated network, with a small
webserver of your own on a private address on that network serving one marker
string. Ask Open WebUI to fetch the plain private URL and watch it refuse. Then
ask it to fetch the NAT64 form of the same address and watch the marker come
back. The pair is the evidence: one refusal, one success, same destination.

Do not aim any of this at a real metadata endpoint or any credential path. The
finding is that the filter can be walked around. Nothing is added by proving
what is behind it.

## What the fix is, and why the obvious fix would not work

The fix unwraps the embedded IPv4 address before deciding, and it does so at all
three places that decide.

The obvious fix is to add `64:ff9b::/96` to the block list. That fails because
it is a denial list against a grammar, and the grammar has more forms than
anyone will enumerate: IPv4 mapped IPv6, decimal integers, octal octets, short
forms, DNS names, redirects. Every one of them is a new line in the list, and
the list is only ever as long as the last person's imagination.

Unwrapping is different in kind. It says the address will be reduced to its
final numeric form first, and the judgement happens after that. One rule instead
of a growing list.

There is a further point worth noticing. Three separate functions had to be
patched, because three separate places made the same judgement. When a rule is
implemented three times it will be fixed in one place and left wrong in the
other two, which is exactly the shape of the next bug in this product.
