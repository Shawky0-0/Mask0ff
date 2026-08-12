---
tags: [security, flash, advisories, method, wordpress, parser-differential]
updated: 2026-08-12
sources:
  - "https://portswigger.net/research/top-10-web-hacking-techniques-of-2025 accessed 2026-08-12, rank 10, Parser Differentials: When Interpretation Becomes a Vulnerability, by @joernchen"
  - "https://pwn.ai/blog/xss2shell accessed 2026-08-12, the XSS2Shell writeup"
---

# MTH-WP-001: hunt the disagreement between two functions that read the same string

The first method card in this folder. Related:
WPDS-0002, XSS2Shell,
WPDS-0001, wp2shell,
the advisories folder.

## The technique in one line

Do not attack a parser. Find two pieces of code that read the same input and disagree about
what it means, then send the input they disagree about.

## The discovery signal, meaning what makes a researcher look there

The signal is **two names for the same job in one call stack**. Not one function behaving
oddly, but two functions both described as making a value safe, both applied to the same
value, written at different times by different people.

In practice you find it by asking three questions about any value that reaches output:

1. How many times is this value inspected between where it enters and where it is used?
2. Were those inspections written to agree with each other, or do they just both happen to
   be there?
3. Does one of them **modify** the value and hand the result to the other? A modify then
   re read pair is the strongest signal of all, because the second function is now reading
   something the first one created, not what the user sent.

The whitespace and the edge case are where the disagreement lives. `< area` with a space
after the bracket is the classic: one parser says "that is not a tag", strips the bracket,
and hands on the rest; the second parser looks at the leftovers and says "that is a tag".

PortSwigger ranked this shape number ten in the Top 10 Web Hacking Techniques of 2025, as
Parser Differentials by `@joernchen`. XSS2Shell is the same shape landing in WordPress core
seven months later. That is why it is worth a card and not just a note.

## The mechanism

* **Controlled source.** Any user supplied string that survives to output. In XSS2Shell it
  is the username field on `wp-login.php`, which is about as controlled as a source gets.
* **Transforms applied.** `wp_strip_all_tags()`, which wraps PHP's `strip_tags()`, and then
  `wp_kses_post()`, which is WordPress's own KSES engine. Both are real sanitisers. Neither
  is broken.
* **The missing decision.** Nobody decided which of the two is authoritative. The code
  applies both and assumes that two safety checks are safer than one. They are not: the
  second one is reading the output of the first, so the first one's idea of "harmless
  leftovers" becomes the second one's input.
* **The sink.** The failed login error message, interpolated into the login page HTML.
* **Prerequisites.** None for the reflection. The value only has to reach output.

## Does it transfer to WordPress, and how

It **is** WordPress. But the general rule is broader than the one bug, and here is where to
point it inside a WordPress codebase:

* `wp_strip_all_tags()` followed by `wp_kses()` or `wp_kses_post()` on the same value.
* `sanitize_text_field()` followed by anything that re parses HTML.
* Any value that goes through `wp_unslash()`, then a sanitiser, then a template.
* Shortcode attribute parsing followed by output through a theme template.
* A REST endpoint that validates a parameter with one callback and sanitises it with
  another. WordPress's REST arguments have separate `validate_callback` and
  `sanitize_callback` slots, and nothing makes them agree.
* Anywhere a plugin stores sanitised HTML in the database and a later version changes the
  sanitiser. The stored value was cleaned by the old rules and is read by the new ones.

The same shape also produced WPDS-0001, in a different form: there the disagreement is not
between two parsers but between a validation loop and a dispatch loop that were supposed to
walk the same list. Same family, same question. **Who else reads this, and do they agree?**

## A safe way to test for it


1. Pick a value with a controlled source and a known output point.
2. Send a **canary**, a unique harmless marker, and confirm it reaches output at all. If it
   does not, stop; there is no path.
3. Send the marker wrapped in the awkward constructs, one per request: bracket then space
   then a name, bracket then tab, bracket then newline, bracket then carriage return, a
   null byte, a doubled bracket, an unclosed tag.
4. Read what comes back **in the raw response body**, not in the rendered page. You are
   looking for the marker arriving as markup rather than as text.

No payload has to execute. Rendering as markup is the whole finding.

## The control that would catch a false positive

Three, and skipping the first is the common mistake:

* **Negative control.** The same request against a patched build. If the construct also
  survives there, you have found normal behaviour, not a bug.
* **Differential control.** The plain canary with no awkward construct. If that also renders
  as markup, the sanitiser is not being applied at all, which is a different and simpler
  finding, and reporting it as a parser differential would be wrong.
* **Attribution control.** Confirm the reflection comes from core and not from a theme or a
  plugin sitting in the same response. Swap to a default theme with plugins disabled and
  repeat.

## Where else this shape appears

* Two HTTP parsers disagreeing on a request boundary, which is request smuggling.
* A WAF and an application disagreeing on encoding, which is most WAF bypass work.
* Unicode normalisation applied after a check rather than before, which is rank four in the
  same PortSwigger list.
* A file extension parser and a web server disagreeing about what `.phar` is, which is
  WPDS-0003.
* Any importer that validates a document with one library and consumes it with another:
  XML, YAML, JSON with duplicate keys, CSV with embedded quotes.

## Provenance

* PortSwigger Research, Top 10 Web Hacking Techniques of 2025, rank 10, Parser Differentials
  by `@joernchen`. `https://portswigger.net/research/top-10-web-hacking-techniques-of-2025`,
  accessed 2026-08-12. The original talk is linked from that page as a video, which was not
  watched this run, so the mechanism here is taken from the XSS2Shell case and the
  PortSwigger one line summary, not from the talk itself.
* pwn.ai, the XSS2Shell writeup, `https://pwn.ai/blog/xss2shell`, accessed 2026-08-12.
* Neither page carried text addressed to an AI agent.
