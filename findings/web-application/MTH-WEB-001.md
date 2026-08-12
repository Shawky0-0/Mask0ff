---
tags: [security, flash, advisories, method, web, desync, ai, protocol]
updated: 2026-08-12
sources:
  - "https://portswigger.net/research/http-terminator, referenced 2026-08-12"
  - "https://thehackernews.com/2026/08/ai-assisted-http-terminator-finds-novel.html accessed 2026-08-12"
  - "https://x.com/albinowax, read 2026-08-12"
---

# MTH-WEB-001: shared parser confusion, and what an AI research system actually found

**The technique in one line.** When a server reuses the same parsing code for requests and
responses, rules that were written for one can be misapplied to the other, and the
disagreement is a desynchronisation primitive.

Presented by James Kettle at Black Hat USA 2026 and DEF CON 34 as
"Can AI do novel security research? Meet the HTTP Terminator".

## Why this card exists, beyond the technique

answer to whether that works**, from the Director of Research at PortSwigger, with numbers:

* roughly **30,000 candidate desync vectors** explored,
* tested against roughly **30,000 sites where scanning was authorised** through bug bounty
  or disclosure programmes,
* roughly **700 vulnerable targets** found, including banks, government infrastructure,
  security products and an airport,
* a **zero day in Apache Traffic Server**, which came from a human guided discovery cascade
  rather than the automated sweep.

**Note the split, because it is the same lesson as
the AI testing systems page.** The machine generated and
tested the candidate space. **The novel category, shared parser confusion, came from Kettle
noticing something in the output and generalising it.** The zero day came from human guided
follow up. The system found volume; the person found the class.

That is the third independent source this week saying the same thing: **the structured sweep
builds the map, the findings come from someone following what looks strange.**

## The discovery signal

Look for **one piece of code serving two roles**. In HTTP that is a parser used for both
request and response handling. The signal is any rule that only makes sense for one
direction being observable in the other.

More generally: shared code across a trust boundary. The boundary is where the assumptions
differ, and shared code carries assumptions across it.

## The mechanism

HTTP request smuggling and desync all come from **two servers disagreeing about where one
message ends and the next begins**. Traditionally that disagreement comes from
`Content-Length` versus `Transfer-Encoding`.

Shared parser confusion is a new source of the same disagreement: the server applies
response parsing rules to a request because the code is the same code. The research also
produced a **dual matching Content-Length pattern** and a **dangling byte technique** that
makes response queue poisoning more reliable.

## A safe way to look for it

stand up a proxy in front of a backend, send a request the two parse differently, and
observe whether a second request gets attached to the first. Never against a shared or
third party host, because the damage lands on other users of that host.

## The false positive control

A timing difference or an odd status code is not desync. **Proof is a second, separate
request being affected**, and demonstrating that safely means both requests being yours.
If you cannot show the poisoning landing on a request you control, you have a curiosity.

## Where else this shape appears

Anywhere a boundary is negotiated by two parties who parse independently: HTTP, WebSocket
upgrade handling, multipart form parsing, JSON versus form encoding disagreements, and
character encoding. **The XSS2Shell root cause in
WPDS-0002 is the same family in miniature**: two
sanitisers disagreeing about the same bytes.

## Recall question

Why is a parser disagreement a security bug rather than a compatibility bug, and what has to
be demonstrated before calling it one?
