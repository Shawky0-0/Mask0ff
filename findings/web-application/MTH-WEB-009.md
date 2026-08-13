---
tags: [security, flash, advisories, method, ssrf, recon, cloud-metadata, normalisation]
updated: 2026-08-13
sources:
  - "https://github.com/advisories/GHSA-8x5v-cpv7-8jjp, accessed 2026-08-13"
  - "https://github.com/advisories?query=SSRF+metadata&sort=published, accessed 2026-08-13"
---

# MTH-WEB-009, the filter reads a string and the socket reads an address

**The first method card in the recon and cloud infrastructure class.** Related:
the web advisories folder,
WEBDS-0019, the Open WebUI case,
MTH-WEB-007, instance fix or class fix.

## The technique in one line

Find a feature that fetches a URL you supply, confirm it has a filter by getting
it to refuse something, then write the same destination in a notation the filter
classifies differently from the network stack.

## The discovery signal

The signal is the **refusal**, not the success.

A product that silently fails when you point it at `169.254.169.254` might have
no filter and no route. A product that returns a specific 400 has a filter. A
filter is a piece of code that classifies strings, and classification code has
edges. The error message is the product telling you it has a boundary and
inviting you to find where it runs out.

In the Open WebUI case the researcher had one further observation available for
free: the same judgement was made in three separate places, `validate_url()`,
`_ssrf_safe_new_conn()` and `_SSRFSafeResolver`. A rule implemented three times
is a rule that will be fixed in one place. That is worth checking before writing
anything, and it is readable in the repository with no requests sent.

## The mechanism

Two components look at one destination and they are not looking at the same
thing.

The **filter** looks at a string and asks a question about categories: is this
address globally routable, is it in a private range, is it on my list. It
answers from the text in front of it.

The **network stack** looks at an address and delivers a packet to it. Between
the two moments, the text gets translated: names resolve, encodings expand,
redirects are followed. Every one of those steps is a chance for the thing
judged and the thing reached to differ.

The NAT64 case is the cleanest example there is. The prefix `64:ff9b::/96` exists
specifically to carry an IPv4 address inside an IPv6 one. So:

```
169 . 254 . 169 . 254        the metadata address, blocked
a9    fe    a9    fe         the same four numbers in hexadecimal
[64:ff9b::a9fe:a9fe]         a globally routable IPv6 address, allowed
```

Nothing is hidden. The address is written in plain sight, in a notation the
filter was never taught to read. The filter sees a public IPv6 address and says
yes. The network sees the embedded IPv4 and delivers to the metadata service,
which hands out the machine's own credentials to anyone who asks.

The rule, and it generalises far past SSRF:

**If a check runs before a translation step, the check is on the wrong side of
it. Normalise first, judge second.**

## The catalogue of notations, which is the working part of this card

Any of these can be the difference between refused and fetched.

**Alternative encodings of the same IPv4 address.** Decimal, `2852039166`. Octal,
`0251.0376.0251.0376`. Hexadecimal, `0xA9FEA9FE`. Mixed forms and short forms
with fewer than four octets, since `169.254.43518` still resolves.

**IPv6 wrappers around IPv4.** NAT64, `64:ff9b::a9fe:a9fe`. IPv4 mapped,
`::ffff:169.254.169.254`. IPv4 compatible, `::169.254.169.254`.

**Names instead of numbers.** A domain you control with an A record pointing at
a private address. Public wildcard resolvers that encode an address in the name.
Then DNS rebinding, where the name resolves to a public address when the filter
checks and a private one when the socket connects, which defeats a correct
filter by exploiting the gap in time rather than in notation.

**Redirects.** A public URL that answers 302 to a private one. This one is worth
testing separately every time, because a filter that normalises perfectly often
validates only the first URL and then hands the whole chain to a client library
that follows redirects by default.

**Parser disagreement in the URL itself.** Credentials in the authority,
`http://expected.com@169.254.169.254/`. Fragments and backslashes that different
URL parsers split at different points. This overlaps with
MTH-WEB-001 and is the same
underlying defect.

**Other schemes.** `file://`, `gopher://`, `dict://`. Less common now because
most HTTP clients refuse them, but a filter that only allowlists hostnames and
forgets the scheme is still a live shape.

## Which class it belongs to, and which stacks

Recon and cloud infrastructure, corpus directory
`01-recon-cloud-infrastructure/`, with an obvious overlap into server side
injection.

**Reaches Ahmed's stack directly, and this is one of the few method cards where
that is not speculative.** The EduAi application has AI and RAG features with
provider keys in its `.env`, and a RAG ingestion path is by definition a feature
that fetches a URL somebody supplied. Every one of the following is the same
surface: fetch a link so the model can read it, import a document from a URL,
generate a link preview, render a page to PDF, fetch an avatar from a remote
address, deliver a webhook to a customer supplied endpoint, and validate a URL a
user typed by requesting it.

If any YZH property runs in a cloud instance with an instance metadata service
reachable, the payoff of this class is credentials rather than information. That
is why it is worth putting ahead of a lot of higher scoring bugs.

## A safe way to test for it

The gate matters more here than on most cards, because this method is the one
that most easily becomes an unauthorised request against a third party.

1. **Read first.** If the source is available, find the validation function and
   read what it normalises. Most of this method is answerable without sending
   anything.
2. **Establish the filter exists**, in a lab, by requesting a plainly private
   address and recording the refusal. Without this you have no baseline.
3. **Stand up your own listener** on a private address on an isolated network,
   serving one unique marker string.
4. **Aim the encoded form at your own listener**, not at a metadata service. The
   finding is that a private destination was reached. Which private destination
   is your choice, and choosing your own removes every question about what you
   touched.
5. **Stop at proof of reach.** Do not request credential paths. Do not enumerate
   an internal network. Do not follow the finding inwards.

Against a live target that Ahmed does not own outright, this method stops at step
1. Steps 2 onwards are requests against a system and the Flash lane's
authorisation gate covers them in full. Sending a crafted URL to a third party
product's fetcher makes that product send traffic somewhere on your behalf, and
that is a request you caused whether or not your hands touched the socket.

## The control that would catch a false positive

**The negative control is the plain form.** The same private destination, written
normally, must be refused. If it is allowed, there is no filter, the encoding
proved nothing, and the finding is simply "this fetches anything", which is a
different report.

**The positive control is the encoded form of a public address.** Request the
NAT64 or decimal form of an address you own on the public internet and confirm it
is fetched. That shows the encoding is accepted and parsed, so a failure on the
private form later means blocking rather than a malformed URL.

**Confirm the reach at your own listener, not in the product's response.** The
product may cache, may show a stale error, may render nothing. Your own access
log is the evidence. A marker in your log at the right second is proof; a
plausible looking response body is not.

**Check the environment precondition.** The Open WebUI advisory says a NAT64
gateway must exist on the deployment network for that specific route to work.
Every notation has a precondition of some kind: NAT64 needs a gateway, DNS
rebinding needs the resolver to honour a short time to live, a redirect chain
needs the client to follow redirects. Confirm the precondition or write the
finding as conditional and say so plainly.

## Where else this shape appears

**Normalise then judge, applied to other grammars.** The mechanism is not about
addresses, it is about checking a value before its final form is known. Path
traversal filters that run before URL decoding, so `%252e%252e` survives.
Extension checks that run before the filename is normalised, which is
WEBDS-0016. Unicode normalisation
turning a lookalike character into an ASCII one after a username uniqueness check.
Case folding applied after a route match, which is
WEBDS-0002. Every one is the same
sentence with a different noun.

**The same product family.** This sweep has already recorded four sibling
advisories in one search: a Flowise SSRF guard bypass, a compliance-trestle
`URLSecurityValidator` bypass, a SeaweedFS unauthenticated SSRF, and a Craft CMS
SSRF, all within nine days. AI tooling is over represented in that list because
fetching arbitrary URLs is a core feature of retrieval augmented generation
rather than an incidental one.

**Where the fix belongs.** Note for reporting: the durable repair is almost never
in the filter. It is an egress network policy or a dedicated proxy that cannot
route to private space at all, plus IMDSv2 so a plain GET cannot lift
credentials. A report that recommends only "add the prefix to the block list" is
recommending the instance fix, which is exactly what
MTH-WEB-007 warns about.

## Provenance

GitHub Security Advisory `GHSA-8x5v-cpv7-8jjp`, Open WebUI `CVE-2026-70485`,
credited to tonghuaroot. Sibling advisories seen in the GitHub advisory database
search for SSRF and metadata. Both accessed 2026-08-13.

The advisory carried proof of concept URLs. They were read and summarised and
**not sent to anything**. No page carried text addressed to an automated reader.
