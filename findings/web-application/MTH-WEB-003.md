---
tags: [security, flash, advisories, method, web, css, client-side, exfiltration, email]
updated: 2026-08-12
sources:
  - "https://portswigger.net/research/css-the-bomb-inside-your-inbox accessed 2026-08-12"
  - "https://x.com/garethheyes read 2026-08-12"
---

# MTH-WEB-003: test what the browser does, not what the sanitiser believes

**The technique in one line.** CSS alone, with no JavaScript anywhere, is enough to read secrets
out of a page character by character and to hijack where a click lands, so any surface that
strips scripts and permits styles is only half sanitised.

By Gareth Heyes (PortSwigger), published 2026-08-06, presented at Black Hat USA 2026. Related:
the DOMPurify entry,
the CRLF desync card.

## The discovery signal

Heyes went looking for the difference between **what a sanitiser believes is safe and what a
browser actually does with the same bytes.** He then walked that question through webmail
clients one at a time: Yahoo Mail, AOL, Fastmail, ProtonMail, Gmail, Outlook.

**The reusable move is the systematic sweep of one question across many implementations.** Not
"is this product secure", which is unbounded, but "here is one precise disagreement, now who
has it". A single question asked of ten products finds more than ten questions asked of one.

The second signal, and the one worth internalising: **script removal is treated as the finish
line for HTML sanitisation.** Everybody checks that `<script>` is gone. Far fewer people ask
what a `<style>` block can still do. The assumption that CSS is presentational is exactly the
assumption being cashed in.

## The mechanism, in plain terms

CSS can be made to do three things it was never meant to do.

**It can read text.** Attribute selectors match on the beginning of a value, or on a value
containing a substring: `[value^="a"]`, `[value*="ab"]`. Pair each with a background image URL
on the attacker's server, and whichever selector matches causes a request. The presence of the
request tells the attacker that character. Repeat and you have read the value one character at a
time. CSS nesting is what makes the payload small enough to be practical.

**It can measure.** A `@font-face` rule with `unicode-range` and `descent-override` makes
different characters render at different heights, so the height of an element becomes a readout
of which characters are in it. That is a font height oracle, and it works on text the attacker
cannot select on directly.

**It can move things.** `:before` and `:after` pseudo elements inherit click behaviour, and the
`inset` property can position a link fullscreen or push it offscreen. So a click intended for
one control can be made to land on another. `:has()` and animation keyframes extend this into
detecting what the user has selected in a menu.

None of it needs JavaScript. All of it needs a style injection point and a way to receive the
requests, which is a server log or a DNS record.

## Which class this belongs to

Client side and browser, corpus directory `05-client-side-browser`.

## A safe way to test for it

**Inject a style that proves rendering, not a style that exfiltrates.** The safe canary is a
rule that changes something visible and harmless, for example setting a distinctive background
colour on a container. If the colour appears, the style survived sanitisation, and that is the
whole finding: the sanitiser permits attacker controlled CSS.

target a seeded canary string, never real data. The difference matters: proving CSS is permitted
requires no data at all, and proving exfiltration works requires very little more. There is
never a reason to read a real secret to make this point.

## The control that would catch a false positive

Three, and the middle one is the one people skip.

1. **Confirm the style was attacker supplied.** A page's own stylesheet turning something red
   proves nothing. Change the value in your input and confirm the rendered result changes with it.
2. **Confirm the request came from the CSS and not from the HTML.** An image loading may simply
   mean `<img>` survived sanitisation, which is a different and lesser finding. Deliver the
   callback purely through a stylesheet rule so there is no other explanation.
3. **Confirm the reader is a different user than the author.** Content that only its own author
   can see is a self inflicted finding and worth almost nothing. The severity lives entirely in
   who renders it, which is why the admin preview screen is the case to check first.

## Where else this shape appears

**The general shape: a filter that removes the obvious dangerous thing and permits a second
language that is more powerful than anyone gives it credit for.**

* CSS in any HTML sanitiser, which is this card.
* SVG, which carries its own script and animation surface, and which sanitiser configurations
  frequently permit as an image format.
* Markdown, where the dangerous part is the HTML passthrough and the link and image syntax.
* Template engines in user editable content, which is server side template injection, and the
  same "this is presentational" assumption is what leads to it being allowed.
* Anywhere a preview feature renders the raw thing so the user can check it before publishing.
  The preview is often less sanitised than the publish path, because it feels private and it is
  not.

The unifying question to carry: **after the sanitiser has run, which languages are still
allowed through, and what is the most powerful thing each of them can do?**

## Recall question

A sanitiser strips every script tag and event handler and lets style blocks through. Name two
things an attacker can still do, and name the single control that would stop both regardless of
what the sanitiser missed.
