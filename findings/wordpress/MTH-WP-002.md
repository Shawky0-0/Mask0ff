---
tags: [security, flash, advisories, method, wordpress, dom-clobbering, xss]
updated: 2026-08-12
sources:
  - "https://pwn.ai/blog/xss2shell accessed 2026-08-12"
  - "https://wordpress.org/news/2026/08/wordpress-7-0-3-release/ accessed 2026-08-12, which credits the pwn.ai team"
---

# MTH-WP-002: clobber the variable the page forgot to define

Related: WPDS-0002, XSS2Shell,
MTH-WP-001,
the advisories folder.

## The technique in one line

When you can inject HTML but not script, look for a JavaScript variable the page reads but
never sets, then create it by giving an injected element that `id`, so the browser defines
it for you.

## The discovery signal

The signal is **a script loaded on a page it was not written for**.

WordPress enqueues `wp-admin/js/user-profile.js` on the login page, because the password
reset form lives there. That script was written for the profile screen in wp-admin, where a
global called `ajaxurl` is always defined. On `wp-login.php` it is not defined. The script
still reads it.

So the question that found this bug was not "can I inject script". It was:

> Which scripts run on this page, and which of them were written for a different page?

And then:

> What do those scripts read that nobody on **this** page sets?

That is a question you can answer by reading, with no requests at all. Open the page source,
list the enqueued scripts, and grep each one for globals it reads without declaring. Every
undefined global that a loaded script touches is a slot an attacker can fill.

## The mechanism

The browser turns HTML `id` and `name` attributes into properties on `window` and on
`document`. This is old behaviour and it is not a bug in the browser. It means that
injecting `<area id=ajaxurl href=...>` makes `window.ajaxurl` exist, with the element as its
value, and reading it in a string context gives the `href`.

The XSS2Shell chain, from the pwn.ai writeup:

1. HTML injection on the login page, no script tags, only tags the sanitiser allows. `area`
   is on the KSES allow list with `id`, `class`, `href` and `name` permitted, which is
   exactly the set needed.
2. The injected `<area id=ajaxurl>` becomes `window.ajaxurl`, now attacker controlled.
3. `user-profile.js` has a jQuery ready handler and a delegated click handler. Injected
   elements carrying the class names that script listens for get clicked automatically on
   page load, so no user interaction is needed.
4. The handler calls `$.post(ajaxurl, ...)`, which now posts to the attacker's URL shape.
5. The URL points back at the site's own REST API with `_jsonp=alert&_envelope=1`. The REST
   API wraps its response in the named callback, jQuery evaluates the response, and script
   now runs in the site's origin. The injection never contained a script tag.

Step 5 is worth its own note: `_envelope=1` makes the REST API return HTTP 200 with the real
status inside the body, which is how a 401 stops being a barrier.

## Does it transfer to WordPress, and how

Directly, and it is not limited to `ajaxurl`. Where to look in a WordPress codebase:

* **Any script enqueued on a page it was not written for.** Login page, block editor,
  Customizer, and any admin screen a plugin adds. Compare the enqueue hook against the
  script's original home.
* **`wp_localize_script()` gaps.** That function is how WordPress hands data to a script.
  If a script is enqueued on one screen with its localised data and on another screen
  without it, the second screen has undefined globals a script is reading.
* **Plugins that reuse an admin script on the front end.** Extremely common, and the front
  end is where unauthenticated HTML injection lives.
* **Any place KSES allows an element with `id` or `name`.** The allow list is the attack
  surface here, not the block list.

The prerequisite that makes this powerful: you only need **HTML** injection, not script
injection. Most sanitiser reviews stop once they confirm script tags are stripped.

## A safe way to test for it


1. Load the page and list every enqueued script from the source. No requests beyond loading
   the page normally.
2. Read each script for globals it reads but does not define. `ajaxurl`, `pagenow`,
   `typenow`, `adminpage`, and anything a plugin invented.
3. In the browser console on a page you own, set `window.<name>` to a canary string by hand
   and see whether the script uses it. That confirms the sink without any injection.
4. Only then, and only if you already have a confirmed HTML injection point, inject an
   element with that `id` carrying a canary. Proof is `window.<name>` resolving to your
   element.

Stop at the clobber. You do not need to complete the chain to prove the finding, and the
rest of the chain touches an administrator session.

## The control that would catch a false positive

* **Negative control.** Check whether the global is already defined on that page by
  something else. If `ajaxurl` is legitimately set, your injected element does not win, and
  the finding is dead. Browsers give a real declared variable precedence over a named
  property.
* **Differential control.** Load the page with plugins disabled and a default theme. If the
  script only appears because of a plugin, the finding belongs to that plugin, not core.
* **Reachability control.** Confirm the sanitiser on the injection point actually allows an
  element with `id`. If it strips `id`, there is no clobber, and the HTML injection is a
  different and lesser finding.

## Where else this shape appears

* Any framework that reads configuration from a global set by an inline script earlier in
  the page: if your injection lands before that script, you set it first.
* `document.forms`, `document.images` and named form controls, which shadow properties in
  the same way.
* Prototype pollution, which is the same idea one layer down: instead of filling a slot
  nobody set, you fill the default that everybody inherits.
* Service configuration read from `<meta>` tags or `data-` attributes, where injecting the
  tag rewrites the configuration.

## Provenance

* pwn.ai, XSS2Shell writeup, `https://pwn.ai/blog/xss2shell`, accessed 2026-08-12. Every
  step above is from that page.
* `https://wordpress.org/news/2026/08/wordpress-7-0-3-release/`, accessed 2026-08-12, which
  credits the pwn.ai team for the pre authentication reflected XSS on the login screen. That
  is the independent confirmation that the writeup is the original research and not a
  summary of somebody else's.
* Neither page carried text addressed to an AI agent.
