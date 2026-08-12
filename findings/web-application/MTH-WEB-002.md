---
tags: [security, flash, advisories, method, web, desync, protocol, nginx, crlf]
updated: 2026-08-12
sources:
  - "https://portswigger.net/research/crlf-powered-desync-attacks accessed 2026-08-12"
  - "https://x.com/t0xodile read 2026-08-12"
  - "https://x.com/m4st3rspl1nt3r read 2026-08-12"
---

# MTH-WEB-002: chase the gap between what people say is common and what you have actually seen

**The technique in one line.** When nginx has `$uri` in a proxy directive it hands the backend
a path it has already URL decoded, so `%0d%0a` in the request path becomes a real line break
inside the proxied request, and a line break is where one HTTP message ends and the next begins.

By Tom Stacey (PortSwigger) and Tobia Righi (TurtleSec), published 2026-08-05, presented at
Black Hat USA 2026 and DEF CON 34. Related:
shared parser confusion,
the forwarded header entry.

## The discovery signal, which is the best part of this writeup

Most research starts from a target. This one started from a contradiction. A post claimed that
CRLF header injection was "not that uncommon", and the researchers had never once run into it
in practice. They went looking for the reason the two statements could both be true.

**That is a reusable move and it is the reason this card exists.** The gap between what the
field believes is common and what you have personally observed is a research lead, in both
directions:

* People say it is common and you never see it. Either you are not looking in the right place,
  or the thing they are describing is not the thing you are testing for. Both answers are worth
  having.
* People say it is rare and you keep seeing it. You have found a niche nobody has swept.

is a question with an answer at the end of it.

## The mechanism

Desync attacks all reduce to one thing: **the front end and the back end disagree about where
one request ends and the next begins.** The classic disagreement comes from `Content-Length`

1. nginx normalises the request path, and normalisation includes percent decoding.
2. If the configuration uses the `$uri` variable in a `proxy_pass` directive, the decoded path
   goes into the request that nginx builds for the backend.
3. `%0d%0a` decodes to a carriage return and a line feed, which in HTTP/1.1 is the separator
   between headers, and two in a row is the separator between the headers and the body.
4. So an attacker writing `%0d%0a` in a URL is writing structure into the message, not data.

Quoting the research on why this primitive is so effective: CRLF sequences in a row are
"simply another boundary between requests and as a result, this technique works exceptionally
well."

The connection is a keep alive connection shared between front end and back end, which is what
lets the leftover fragment attach itself to the next person's request.

## Which class this belongs to

Protocol, cache and routing, corpus directory `07-protocol-cache-routing`. This is the class the
ledger flags as the one a lazy sweep never reaches, and it is now covered by two method cards
rather than zero.

## The false positive control

**Desync and request tunnelling look alike and are not the same finding.** Tunnelling means your
smuggled fragment goes to the backend but stays inside your own connection, so it cannot touch
anybody else. Desync means it lands on a different connection and reaches another user's
request. Only the second has cross user impact.

The control is connection reuse and response stacking: prove the extra response arrives on a
request that is not the one that carried the payload. Timing oddities and strange status codes
alone are a curiosity, not a finding. This mirrors the control on
MTH-WEB-001 and it is the same discipline: proof
is a second, separate request being affected.

## Where else this shape appears

**The shape is: a component decodes or rewrites a value before passing it on, and the value can
carry structure for the next parser.** Once you hold it that way it is everywhere.

* Any percent decoding that happens before a value is placed into a protocol that uses
  delimiters. CRLF into headers is the classic. Newline into a log file is log injection.
  Newline into an SMTP header is email header injection, which is the same bug class as the
  Laravel CRLF advisory noted in this folder's first run file.
* Path normalisation ahead of a routing decision, which is
  WEBDS-0002 in this folder: proxy and origin
  disagreeing about what a path means.
* Cache key construction, where the decoded and the raw form disagree, which is cache poisoning
  and cache deception.
* Anywhere a value is decoded once too often. Double decoding is the same defect running twice.

## Recall question

Why is percent decoding in a proxy a security decision rather than a convenience, and what
exactly has to be demonstrated before a strange status code counts as a desync?
