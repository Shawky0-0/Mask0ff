---
tags: [security, flash, advisories, method, wordpress, supply-chain, admin-surface]
updated: 2026-08-12
sources:
  - "https://www.wordfence.com/blog/2026/08/psa-supply-chain-compromise-in-bdthemes-ecosystem-via-poisoned-api-response/ accessed 2026-08-12"
  - "https://plugins.svn.wordpress.org/advanced-responsive-video-embedder/trunk/changelog.md accessed 2026-08-12"
---

# MTH-WP-004: Poison the feed the plugin already trusts

**The technique in one line.** Instead of attacking the site, find the third party data the
site's plugins fetch and render, and attack that, because plugin authors escape input from
users and forget that a network response is input too.

Related: WPDS-0005, the incident this came from,
MTH-WP-003,
the advisories folder.

## Where this came from

Wordfence's analysis of the BdThemes compromise, published 2026-08-08 by Paolo Tresso. It is
original vendor research with a full timeline and indicators, not a summary of somebody else's
work.

## The discovery signal, what made the researchers look there

The signal is inverted from the usual one, and that is why this card exists. Nobody found this
by reading plugin code looking for a bug. They found it because **sites were being compromised
and no plugin file had changed.**

The reasoning that follows from that observation is the transferable part:

* files on disk match the official WordPress.org copies, so it is not the source
* no update was installed before the compromise, so it is not a poisoned release
* the compromise fires for administrators in wp-admin, so it is running in a browser
* therefore something the admin page LOADS is hostile, and it is not on disk

That is the chain worth memorising. **When the files are clean and the site is owned, look at
what the page fetches.**

The forward looking version of the same signal, the one a tester can run before any incident:
open a plugin's admin JavaScript and ask, does this contact anything, and what does it do with
the answer.

## The mechanism

1. A plugin ships a component that fetches JSON from the vendor's own endpoint. Promotional
   banners, news panels, licence checks, upsell notices, recommended plugins.
2. The script is enqueued on `admin_init`, so it runs on every wp-admin page load, for every
   logged in administrator, unconditionally.
3. One field from that JSON reaches the DOM without escaping. In this case `display_id`
   concatenated into an HTML `id` attribute, while the very same value was escaped correctly
   for the neighbouring `data-display-id` attribute.
4. The attacker never touches the site. They compromise the place the JSON is served from, which
   here was a static object storage bucket, not an application server.
5. The injected value breaks out of the attribute and adds an event handler that fires by
   itself, no click needed, using a CSS animation with a duration of about ten milliseconds.
6. It now runs with the administrator's session. It creates an administrator through the REST
   API using the nonce already on the page, installs a webshell disguised as a plugin, and
   drops must use plugins for persistence, one of which hides the new accounts from the user
   list.

**Why it is hard to catch:** no file changed, so integrity scanning says clean. The payload
arrives over HTTPS from the vendor's legitimate domain, so egress filtering and a web
application firewall see a normal request to a normal place.

## Does it transfer to WordPress? It IS a WordPress method

But the mechanism is general, so state it generally: **any client that renders a response from
a server it considers its own, without escaping, is one credential leak away from this.** The
WordPress admin dashboard is a particularly rich target because the person looking at it always
holds every capability in the system.

Where to look on any WordPress install:

* admin notices that show vendor marketing or news
* update and licence checks that render release notes or messages
* "other plugins by this author" and recommendation panels
* dashboard widgets pulling remote feeds
* anything in a plugin's JavaScript calling `fetch` or `wp.apiFetch` to a domain that is not
  the site

Second live example from the same period, worth recording because it shows the pattern being
retired: the Advanced Responsive Video Embedder changelog for 10.9.0, dated 2026-08-05, says in
substance that ARVE news is now opt in and no longer fetched by default. A different vendor
removing the same pattern within days.

## A safe way to test for it

**Do not poison anything. Ever.** The test is entirely local and does not involve the vendor.

1. Install the plugin on the sandbox.
2. Put a proxy Ahmed controls between the sandbox and the network, and intercept the plugin's
   own outbound request.
3. Return a JSON body where the suspect field holds a harmless canary: a string that would
   visibly break out of the attribute if unescaped, but that contains no script and no event
   handler at all. A marker that sets a known dummy attribute is enough.
4. Read the rendered DOM. If the canary appears as markup rather than as text, that is the
   finding.

Nothing executes. The proof is that the string crossed from JSON into markup, which is the
whole bug. Firing a real handler adds no evidence and turns a test into an attack.

## The control that catches a false positive

**The differential control is unusually strong here and you should always use it.** Send the
same canary into a field that IS escaped properly, and confirm it comes out as text. In the
BdThemes case `data-display-id` is escaped while `id` is not, in the same render, from the same
source value. Showing both results side by side rules out "the whole page is unescaped" and
pins the finding to one sink.

Second control: send the canary into the `content` field, which later versions sanitise with a
DOMParser based cleaner. If the canary survives in `display_id` and is stripped in `content`,
the gap is specific and demonstrable.

Third, environmental: the script runs only for a logged in administrator in wp-admin. Check the
front end and you will find nothing and conclude wrongly.

## Where else this shape appears

* **Any auto updater that renders a changelog** fetched from the vendor.
* **The JavaScript supply chain generally.** A CDN hosted script is the same trust, with the
  escaping step removed entirely. That belongs to the sibling sweep at `advisories-web/`.
* **CRM and marketing embeds** that render remote HTML into an admin console.
* **AI surfaces, and this is the one closest to Ahmed's current work.** A model response is a
  network response. A chat widget that renders model output as markup is structurally identical
  to this banner, and the "vendor endpoint" is even less predictable. This is the same family as
  the EduAi prompt injection finding: content
  arriving from elsewhere gets treated as trusted because of where it came from.

**The generalisation worth carrying:** trust is about the channel, not the content. Ask of any
value, "if the party at the other end of this were hostile tomorrow, what would this line do",
and treat your own vendor as a party that could be hostile tomorrow, because the thing that
gets compromised may be their bucket rather than their code.
