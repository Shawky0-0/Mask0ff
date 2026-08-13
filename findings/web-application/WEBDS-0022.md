---
tags: [security, flash, advisories, webds, supply-chain, php, dos, algorithmic-complexity, markdown]
updated: 2026-08-13
sources:
  - "https://github.com/advisories/GHSA-2q4p-g7hv-5rgv, accessed 2026-08-13"
  - "security/advisories-digest/next-run-web.md, handed over by the API sweep 2026-08-12"
---

# WEBDS-0022, one accented letter puts a Markdown line on the slow path

Handed to this lane by the API sweep, which judged it not an API defect. Related:
the web advisories folder,
WEBDS-0015, the other supply chain entry,
MTH-WEB-001, parser disagreement.

```yaml
id: WEBDS-0022
component:
  type: library
  ecosystem: composer
  name: league/commonmark
  version_scope: "the parser, with the Autolink extension making it worse"
affected:
  introduced: "0.6.0"
  fixed_in: "2.9.0"
  tested_on: ___
identifiers:
  cve: CVE-2026-71488
  ghsa: GHSA-2q4p-g7hv-5rgv
  osv: ___
  snyk: ___
  vendor_id: ___
class:
  owasp_2025: "vulnerable and outdated components, as a dependency. The defect itself is a resource consumption bug"
  owasp_api: "API4, unrestricted resource consumption"
  owasp_llm: not applicable
  cwe: "CWE-407 inefficient algorithmic complexity, and CWE-1050 excessive resource consumption within a loop"
  family: quadratic blowup from a units mismatch between two layers
  corpus_directory: 09-components-supply-chain/
auth_required: none
entry_point: >
  Any route that renders user supplied Markdown. In a Laravel application that
  is typically a comment box, a profile bio, a support ticket body, a rich text
  field, or a mail template that runs user text through Markdown. No special
  parameter is needed, only text.
root_cause: >
  Two layers count in different units. The parser tracks positions in
  characters. The regular expression engine reports matches in bytes. For ASCII
  those are the same number, so the mismatch is invisible in almost all input. A
  UTF-8 character wider than one byte makes them diverge, and the parser then
  translates between the two by rescanning the line from the start, again and
  again, over a growing portion of the line. The Autolink extension multiplies
  it by copying and validating the rest of the line at every prefix that looks
  like the start of a URL. The missing decision is: nobody decided one unit for
  positions and made every layer use it.
signal: >
  Response time that climbs faster than input size on a text field. Concretely,
  post 1 KB and time it, then 2 KB, then 4 KB. Linear cost roughly doubles.
  Quadratic cost roughly quadruples. The second signal is specific to this bug
  and much cheaper: the same payload with a single non ASCII character in it
  should be dramatically slower than the pure ASCII version of the same length.
safe_proof: >
  In a disposable app of your own, render a crafted string locally through the
  library, not over HTTP, and time it. The canary is wall clock time on your own
  process. Sizes stay small enough to finish, and the demonstration is the shape
  of the curve, not a hang. Never demonstrate this by loading a live service.
  A denial of service proof against something you do not own is an outage, and
  the Flash lane's authorisation gate covers it in full.
controls: >
  Negative control: the identical payload with the non ASCII character replaced
  by an ASCII one, at the same byte length. If both are slow, the cause is
  length, not the multibyte path, and the explanation is wrong. Differential
  control: run with the Autolink extension enabled and disabled, since the
  advisory names it as the multiplier. Third control: measure the parse in
  isolation, not through the web stack, so network time and framework overhead
  are not what you are actually plotting.
fix:
  commit_url: >
    https://github.com/thephpleague/commonmark/commit/a6ef6cdc308dfa39a34239c35818e75892a0e6a8,
    plus a70979ea0d7d3377bd7127536748454a922bf5eb and
    c97b02e5e652b992033b93ba5d6182f706343fc6. Located and recorded, not read as a
    diff this run.
  invariant: "___, not read. The advisory describes the cause but does not state what 2.9.0 enforces"
hardening: >
  Cap the input before it reaches the parser: a maximum length on any field that
  gets rendered as Markdown, and a rendering timeout. Then render once and cache
  the HTML, so the same text is never parsed twice. Those three together survive
  the next complexity bug in any parser, which matters because there will be
  one.
detection: >
  Application performance monitoring showing one route with a small request body
  and a long CPU time. In PHP, requests hitting max_execution_time on a text
  rendering route. The fingerprint in the payload is a long run of leading
  whitespace or repeated Markdown punctuation with at least one non ASCII
  character on the same line.
variant_rule: >
  The general shape is a units mismatch between two layers that both index into
  the same string: characters against bytes, code points against UTF-16 code
  units, grapheme clusters against anything. Look for it wherever a regular
  expression result is fed back into a hand written scanner. Then the wider
  class, algorithmic complexity in anything that parses attacker text: Markdown,
  YAML, XML, regular expressions supplied by users, CSV, HTML sanitisers,
  template engines, and colour or unit parsers. Two live siblings are already on
  this sweep's list, js-yaml quadratic CPU in !!omap, GHSA-5p4m-2wfm-xmqj, and
  SvelteKit ReDoS in Accept header parsing, GHSA-29g2-3rmr-qm68.
lab:
  install: "composer require league/commonmark pinned below 2.9.0, in a throwaway directory"
  snapshot: "not needed, nothing is written"
  teardown: "delete the directory"
provenance:
  source: "GitHub Security Advisory GHSA-2q4p-g7hv-5rgv"
  accessed: 2026-08-13
  license_note: "public advisory, no licence restriction on reading"
```

## What happens

`league/commonmark` turns Markdown into HTML. It is the default Markdown library
across the PHP world and it sits underneath a great many Laravel applications
without anyone choosing it directly.

Feed it a line with one non ASCII character on it, plus a long run of spaces or
repeated punctuation, and the time it takes stops being proportional to the
length. Double the input and the work goes up four times. A small request can
occupy a worker for a long time, and a handful of them can occupy all of them.

## Why it works

Two parts of the same code are counting the same string in different units.

The parser thinks in characters. It wants to know "which character am I at".
The regular expression engine answers in bytes. It says "I matched at byte 40".

In English text those are the same number, because every character is one byte.
Put one accented letter, one emoji, one Arabic character anywhere on the line
and they stop agreeing. From that point on, every time the parser needs to turn
a byte position into a character position, it counts from the beginning of the
line again.

Do that once per position and the line gets scanned once per position, which is
the definition of quadratic: cost grows with the square of the length.

The Autolink extension makes it worse in a way worth understanding on its own.
It looks for things that could be the start of a URL, and at each one it copies
the rest of the line and validates it. Repeated punctuation gives it many
candidate starts, and each candidate pays for the whole tail again.

The rule to keep:

**When two layers index into the same string, they must agree on the unit. A
units mismatch does not usually produce a wrong answer, it produces a slow one,
which is why it survives so long.**

## Why the non ASCII character is the whole trick

This is the part that makes it a good teaching case. The expensive path was
always there. It just never ran, because almost all input is ASCII and on ASCII
the two counters agree, so no translation is needed.

One character flips the whole line onto the slow path. The attacker is not
supplying a payload in any normal sense. They are supplying a **mode switch**.

That generalises: look for the branch a codebase almost never takes, and ask
what cheap thing makes it take that branch.

## How you would reproduce it

Locally, in a throwaway directory, with the library pinned below 2.9.0. Render a
string of repeated Markdown punctuation at a few lengths and time each parse.
Then repeat with a single non ASCII character in the string. Plot both. One line
should be roughly straight, the other should curve.

Do this against the library in a script. Not over HTTP, and not against anything
you do not own. A working demonstration of this bug is an outage, and an outage
you cause on someone else's system is not evidence, it is an incident.

## What the fix is, and why the obvious fix would not work

2.9.0 fixes it. The three commits are recorded above but were not read this run,
so what the release actually enforces is `___` here and is worth a later look.

The obvious fix is to reject non ASCII input. That is not a fix, it is a
regression: the whole point of a Markdown renderer on an education platform is
that people write in their own language. Arabic content would break by design.

The second obvious fix is a length cap alone. That helps and it should be done
anyway, but it does not remove the quadratic term, it only chooses a ceiling for
it. If the cap is generous enough to be useful, it is generous enough to be
expensive.

The real repair is to stop translating: carry one unit through the parser, or
keep an index so a translation is constant time instead of a rescan.
