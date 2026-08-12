---
tags: [security, flash, advisories, method, api, gateway, desync, proxy]
updated: 2026-08-12
sources:
  - "https://portswigger.net/research/crlf-powered-desync-attacks accessed 2026-08-12"
---

# MTH-API-003: make the proxy rewrite your path into a header, and the stream stops being yours

**The technique in one line.** Where a reverse proxy builds the upstream request out of a
normalised copy of your URL, get an encoded newline through the normaliser and you are no longer
writing a path, you are writing lines in someone else's HTTP conversation.

Source: Tom Stacey and Tobia Righi, PortSwigger Research, 2026-08-05. Related:
MTH-API-002,
the API folder, and the watchlist entry for James Kettle,
whose protocol layer work this sits in the line of.

## The discovery signal

The signal is **an error status you did not ask for, in a family that has nothing to do with
your request**: 505 Version Not Supported, 501 Not Implemented, 417 Expectation Failed.

Those codes are the tell because they are not application errors. An application answers 400,
403, 404. A 505 means something parsed your request as HTTP and disliked the version, which
means a machine you were not addressing read your input as protocol rather than as data. That is
the whole signal, and it is cheap to look for.

The second signal is far louder and comes later: **responses arriving that belong to other
people.** The researchers describe it plainly, that they "received a stream of responses from
various unrelated applications." If that ever happens, stop immediately, because the queue is
already poisoned and every subsequent request is somebody else's.

## The mechanism

Nginx URL decodes the request path as part of normalisation, and `$uri` holds that decoded
value. A configuration that passes `$uri` into `proxy_pass`, or into a custom upstream header,
puts the decoded string into the request the proxy writes upstream.

Send `%0d%0a` in the path. The proxy decodes it into a real carriage return and line feed, and
writes it into the upstream request. A newline inside an HTTP request is not a character, it is
a structural delimiter. You have just ended a line and started a new one in a message you do not
own.

From there the two machines disagree about where the request ends. The front end counts one
request, the back end counts two, or the reverse. Once the two are out of step, the connection
between them is desynchronised, and requests and responses stop pairing up correctly. The
victim is whoever shares that upstream connection next.

The insertion point does not have to be the path. The research notes custom upstream headers and
non path locations such as cookies work the same way, because the defect is "a decoded value
gets written into a structural position", not "the path is special".

## Which class this belongs to

It sits outside the OWASP API Top 10, which is a limitation of that list rather than of the
technique. The closest label is `API8:2023` security misconfiguration, since the trigger is a
proxy configuration, but that undersells it: the impact is other users' requests and responses,
which in effect is an authentication and authorisation failure produced entirely at the
transport layer.

**Why it belongs in an API sweep at all:** this is the layer every API in a fleet shares. An API
gateway, a CDN, an ingress controller and a Kubernetes service mesh are all reverse proxies. A
desync there is not one API's bug, it is every API behind that hop at once. The research
specifically documents exploitation inside CDN infrastructure and a payment provider's cluster.

## Which protocols it applies to

HTTP/1.1 between proxy and upstream, which is where the line based framing lives, and that
remains extremely common on the internal hop even when the client facing side is HTTP/2 or
HTTP/3. Anything that terminates one protocol and re emits HTTP/1.1 upstream is in scope.

## A safe way to test for it, and the hard limit first

absolute here.** More than any other card in this folder. The reason is specific and worth
stating: a desync attack does not stay inside your own session. A successful test poisons a
connection that other people's requests travel over, which means it can capture a stranger's
credentials or serve them your response. That is unauthorised access to third party data even
when the target is in scope for testing, and it can happen on the first probe rather than as an
escalation.

Given that, the safe procedure:

   not a CDN, not a company host, not a bug bounty target without explicit written permission
   for desync testing specifically.
2. **Confirm the injection point exists without triggering a second request.** The published safe
   probe is a deliberately malformed HTTP version number rather than a complete smuggled request,
   so the upstream errors out visibly instead of processing anything. You are asking "does my
   newline arrive", and the error answers it.
3. **Stop at the error.** Confirming the injection point is the finding. Response queue
   poisoning is the impact, and demonstrating it means taking other people's traffic.

## The control that catches a false positive

The core control: **prove your input changed the upstream request structure, not just the
response.** An application that returns 505 because it genuinely dislikes something in your
input is not a desync. The evidence has to be that the upstream saw a different message shape
than the one you addressed to the front end. In a lab that is settled by reading the upstream's
own logs, which is another reason the lab has to be his.

The research also notes a timing technique that distinguishes whether the front end or the back
end is the one processing `Content-Length`, which is the standard way of telling which side of
the pair is confused.

The second control is one this card adds: **encoding survives many hops.** A `%0d%0a` that
reaches the application unchanged proves the application saw your literal string, and proves
nothing about any proxy. The finding requires the decode to have happened somewhere in between.

## Where else this shape appears

The general shape is **a value that crosses a boundary where it changes meaning from data to
structure**. Path to header is one instance. Others:

* header values reflected into other headers, or into a log line that is later parsed;
* anything user controlled interpolated into an SMTP or IMAP command, which is where CRLF
  injection originally lived;
* values written into structured log formats and then re read by a parser, which is how log
  injection becomes log forging;
* URLs assembled from user input and handed to an internal HTTP client, which is the same
  boundary crossing that produces SSRF.

**The question to carry:** where does this string stop being content and start being syntax, and
who decodes it on the way.

## Recall question

Why is confirming the injection point the place to stop, rather than demonstrating impact, and
what specifically goes wrong for people who are not the tester if you continue?
