# METHOD-INDEX: every technique the daily sweeps have extracted

**Generated file. Do not edit it by hand, it is overwritten in full on every build.**
Built by `build-method-index.py` from the four intelligence sweeps.

**34 method cards and 79 records.**

**How to use this page.** Read it before hunting, not after. Each line is a technique and the signal that gives it away. When a line matches the surface in front of you, open the full card with the `search` command using its id, and read the mechanism and the false positive control before you test anything.

**What these records are.** Desk research from published sources. Every one is a cited hypothesis, not a reproduced finding, and most were never run in a lab. Recheck the affected versions and the root cause against the current target before adapting one.

---

## The method cards

### WordPress

**`MTH-WP-001` hunt the disagreement between two functions that read the same string**
  Do not attack a parser. Find two pieces of code that read the same input and disagree about what it means, then send the input they disagree about.
  *Signal:* The signal is **two names for the same job in one call stack**. Not one function behaving oddly, but two functions both described as making a value safe, both applied to the same value, written at di…
  *Transfers:* It **is** WordPress. But the general rule is broader than the one bug, and here is where to point it inside a WordPress codebase: * `wp_strip_all_tags()` followed by `wp_kses()` or `wp_kses_post()` o…

**`MTH-WP-002` clobber the variable the page forgot to define**
  When you can inject HTML but not script, look for a JavaScript variable the page reads but never sets, then create it by giving an injected element that `id`, so the browser defines it for you.
  *Signal:* The signal is **a script loaded on a page it was not written for**. WordPress enqueues `wp-admin/js/user-profile.js` on the login page, because the password reset form lives there.
  *Transfers:* Directly, and it is not limited to `ajaxurl`. Where to look in a WordPress codebase: * **Any script enqueued on a page it was not written for.** Login page, block editor, Customizer, and any admin sc…

**`MTH-WP-003` Authorise the object, serve the path**
  Three steps and a gap. 1. **Resolve.** User input, a URL or a path or a name, is turned into a domain object: a post ID, a user, an attachment, an order.
  *Signal:* You are reading a handler and you notice that the security check and the action take different arguments.
  *Transfers:* WordPress hands you this pattern by design. `url_to_postid()`, `wp_attachment_url_to_post_id()`, `get_page_by_path()`, and every plugin's own lookup helper take a string and give you an object.

**`MTH-WP-004` Poison the feed the plugin already trusts**
  1. A plugin ships a component that fetches JSON from the vendor's own endpoint. Promotional banners, news panels, licence checks, upsell notices, recommended plugins.
  *Signal:* The signal is inverted from the usual one, and that is why this card exists. Nobody found this by reading plugin code looking for a bug.
  *Transfers:* But the mechanism is general, so state it generally: **any client that renders a response from a server it considers its own, without escaping, is one credential leak away from this.** The WordPress…

**`MTH-WP-005` when the app has no surface, attack the library it hands files to**
  When the target application is too small to have bugs, stop testing the application and go audit the third party library it passes user files to, because that library makes its own decisions about what those files are.
  *Signal:* The pwn.ai team were given a client application that was, in their description, minimal: an upload box and little else.
  *Transfers:* It already has, and the entry is WPDS-0008. WordPress uses ImageMagick through `WP_Image_Editor_Imagick` whenever the extension is available, and it does that on every media upload to build thumbnail…

**`MTH-WP-006` treat `fixed in` as a claim and bisect the tags**
  Do not read an advisory's fixed version as a fact. Find the sanitising line in the patched release, then walk backwards through the version tags until it disappears, and the release where it first appears is the real fix.
  *Signal:* Two things make a `fixed_in` field worth checking rather than believing. **The advisory states a range and not a release.** "All versions up to and including 27.5" is a statement about what is broken.
  *Transfers:* It is native to WordPress. The plugin directory keeps every released tag on public SVN forever, which is unusual and very useful.

**`MTH-WP-007` go straight to the AI feature, it is the newest code and the least reviewed**
  In any product that has recently grown an AI feature, review that feature first, because it is the newest code in the codebase, it was written fastest, and it tends to be wired straight into the front end with no authentication.
  *Signal:* The signal is a function name. In the Jobify theme it was `download_image_via_ai`. Read what that name tells you before reading any code.
  *Transfers:* It is a WordPress finding already. The transfer worth writing down is to Ahmed's fleet. An AI or RAG feature needs, by its nature, to do things ordinary application code does not: * **Fetch a URL**,…


### Web application

**`MTH-WEB-001` shared parser confusion, and what an AI research system actually found**
  HTTP request smuggling and desync all come from **two servers disagreeing about where one message ends and the next begins**.
  *Signal:* Look for **one piece of code serving two roles**. In HTTP that is a parser used for both request and response handling.

**`MTH-WEB-002` chase the gap between what people say is common and what you have actually seen**
  Desync attacks all reduce to one thing: **the front end and the back end disagree about where one request ends and the next begins.** The classic disagreement comes from `Content-Length` against `Transfer-Encoding`.
  *Signal:* Most research starts from a target. This one started from a contradiction. A post claimed that CRLF header injection was "not that uncommon", and the researchers had never once run into it in practic…
  *Transfers:* **It reaches his, and this is the honest version rather than the exciting one.** nginx is confirmed locally: his WordPress sandbox runs it.

**`MTH-WEB-003` test what the browser does, not what the sanitiser believes**
  CSS can be made to do three things it was never meant to do. **It can read text.** Attribute selectors match on the beginning of a value, or on a value containing a substring: `[value^="a"]`, `[value*="ab"]`.
  *Signal:* Heyes went looking for the difference between **what a sanitiser believes is safe and what a browser actually does with the same bytes.** He then walked that question through webmail clients one at a…
  *Transfers:* **Yes, and not through the surface most people would guess.** The affected list in the research is long and includes Yahoo Mail, AOL, Fastmail, ProtonMail, Gmail, Outlook, Medium, Firefox, Slack and…

**`MTH-WEB-004` benchmark first: finding race conditions by looking for sub states**
  Treat every request as if it passes through several hidden intermediate states, then send a batch of requests engineered to arrive during one of them, and judge the result against a sequential benchmark rather than against your expectation…
  *Signal:* This is the field the brief calls most valuable and most buried, and here it is unusually clear.

**`MTH-WEB-005` read the route file for the middleware that was taken off**
  Open the framework's route definition file, find every route that has protection explicitly removed or conditionally skipped, and ask what condition the attacker controls.
  *Signal:* The researcher did not scan Krayin. They read `packages/Webkul/Installer/src/Routes/web.php` and noticed three POST endpoints declared `withoutMiddleware('web')`.

**`MTH-WEB-006` reconstruct the attack from the patch, and read the tests first**
  Open the fix commit rather than the advisory, read the changed tests before the changed code, and let the test names tell you the attack the vendor's prose would not.
  *Signal:* The signal here is a property of the advisory, not of a target: **a security advisory whose description is vague about mechanism.** GHSA-crmm-hgp2-wgrp says a signed URL "can be interpreted different…

**`MTH-WEB-007` did the patch fix the bug or fix the class**
  Read the fix diff and decide which of two things it did: added the reported case to a list, or stated a rule that covers cases nobody has reported yet.
  *Signal:* Two independent cases produced this card on the same run, which is why it is worth a card rather than a note.

**`MTH-WEB-008` the hash of nothing, or what a security function returns when it gives up**
  Find the error path inside a security function where an exception is swallowed and an empty value is used instead, then precompute the check's answer for that empty value, because it is a constant and it is the same on every install on ear…
  *Signal:* Zakhar Fedotkin was not looking for a new bug. He and Gareth Heyes had already broken `ruby-saml` in 2024 with XML signature wrapping through DTDs.

**`MTH-WEB-009` the filter reads a string and the socket reads an address**
  Find a feature that fetches a URL you supply, confirm it has a filter by getting it to refuse something, then write the same destination in a notation the filter classifies differently from the network stack.
  *Signal:* The signal is the **refusal**, not the success. A product that silently fails when you point it at `169.254.169.254` might have no filter and no route.


### API

**`MTH-API-001` the object graph, and why changing an ID is not a finding**
  Two questions look like one question: 1. May this account write to scope X? (usually checked) 2.
  *Signal:* You are looking for a **gap between two identifiers in the same request**. Almost every API handler that goes wrong this way takes both: * a **scope**: a volume, a workspace, a tenant, a course, an o…

**`MTH-API-002` break one item in a batch and watch the others answer for each other**
  Two passes, one list, joined by index: 1. Validation walks the list and records, for each item, what it is and who may do it.
  *Signal:* The signal is **a batch endpoint that reports per item results**. That is it, and it is usually visible from the documentation alone.

**`MTH-API-003` make the proxy rewrite your path into a header, and the stream stops being yours**
  Nginx URL decodes the request path as part of normalisation, and `$uri` holds that decoded value.
  *Signal:* The signal is **an error status you did not ask for, in a family that has nothing to do with your request**: 505 Version Not Supported, 501 Not Implemented, 417 Expectation Failed.

**`MTH-API-004` send the one time request twice at once**
  Find a request the user interface only ever sends once, send two at the same instant, and see whether the effect lands twice.
  *Signal:* This is the field most writeups bury, and here it is unusually specific. **You are not looking for a suspicious response.
  *Transfers:* Directly, and this is the most fleet relevant method card in the folder so far. * **Tutor LMS**, the largest unexamined API surface on the fleet.

**`MTH-API-005` read the verifier, not the documentation**
  For every inbound webhook, find the function that verifies it and check that the secret it is handed is actually read.
  *Signal:* The narrowest and most mechanical signal in this folder, which is what makes it worth having.
  *Transfers:* **Directly, and this is the row the folder had no coverage of at all.** The company stack names two consumers of inbound callbacks: * **GoHighLevel CRM.** Contact and pipeline updates arriving from t…

**`MTH-API-006` the endpoints that promise to do nothing are the ones with no check**
  Enumerate every route whose name promises it has no effect, then check whether anybody guarded it, because the name is usually why nobody did.
  *Signal:* **A route named after a non action.** `validate`, `check`, `verify`, `lint`, `parse`, `preview`, `render`, `test`, `dry-run`, `simulate`, `estimate`, `probe`, `health`.
  *Transfers:* **Yes, and by shape rather than by product.** Neither Langflow nor LiteLLM is recorded anywhere on the fleet.

**`MTH-API-007` attack the rate limiter's key, never its number**
  A rate limit is a counter with a name on it. Find out what the name is made of, and if the caller controls any part of it, the caller gets a fresh counter whenever they want one.
  *Signal:* **Nobody writes down the rate limit key, so nobody checks it.** Documentation says "5 attempts per minute".
  *Transfers:* Yes, in four places, and none has been checked. * **WordPress login throttling plugins.** Every one keys on something.

**`MTH-API-008` the guard exists, so count its call sites instead of looking for it**
  Stop asking whether a product validates. Assume it does, find the validator, then count every path that reaches the dangerous operation and subtract the ones that call it.
  *Signal:* **A file named like a guard is an invitation, not a reassurance.** `ssrf_helper.php`, `sanitize.js`, `checkPermission()`, `validateUrl()`.
  *Transfers:* This is the most directly transferable method in the folder, because Ahmed has already done the inventory that this method consumes.

**`MTH-API-009` in GraphQL the client writes the workload, so count what the server counts**
  One GraphQL request is not one unit of anything, so find the unit the server's defences count and multiply everything else.
  *Signal:* **A single URL that accepts arbitrary work.** With REST, a route is a rough proxy for an operation, so per route limits and per request limits and path based edge rules all approximately work.
  *Transfers:* **Partly, and the honest answer is less than the other two cards this run.** * **WPGraphQL** is present in the WordPress ecosystem and there is a live advisory for it, CVE-2026-54768, user existence…


### Web3 and the web2 seam

**`MTH-W3-001` Split the two questions on every signed input**
  On every input that arrives with a signature, separate "is the sender authorised" from "is this value possible", and find out which of the two the code actually asks.
  *Signal:* A verification function that ends at the signature or the role check. Read the ingestion path top to bottom, and if the last thing it does before acting on the value is confirm who sent it, stop ther…
  *Transfers:* **Yes, and this is the strongest transfer in the whole folder.** It is the signed webhook problem exactly: the HMAC verifies, so the body is trusted, and nobody asks whether the amount is plausible.

**`MTH-W3-002` Read the dependency's publish pipeline, not only its code**
  For any dependency, stop asking whether the code is good and ask what it would take for a stranger to publish code into your build.
  *Signal:* Public registry and repository metadata answers all of it, and none of it requires installing anything: * A version published minutes after a commit, which means no human stood between them.
  *Transfers:* **Yes, completely. This is not a web3 method at all.** It applies unchanged to every npm and composer dependency on the WordPress and Laravel fleet, to every GitHub Actions workflow, and to every dev…

**`MTH-W3-003` Ask what the user sees, what the user authorises, and who can change the code in between**
  Treat the served front end as a security boundary: check who can replace it, whether anyone would notice, and whether the confirmation screen states what is actually being authorised.
  *Signal:* Three questions, all answerable from outside with public data: * **Who can move the domain.** No registry lock, no DNSSEC, a registrar account without hardware backed multi factor.
  *Transfers:* **Yes, and of the three cards this is the closest to what Ahmed does now.** Strip out the wallet and every control is one he can already test: * Registrar and DNS hygiene on every company domain, whi…

**`MTH-W3-004` follow every signature back to the moment of consent**
  For every signature, token or approval a system accepts, ask three questions: when was it created, what could the person creating it actually see, and what stops it being spent somewhere else later.
  *Signal:* Words in the design that separate approval from execution. **Durable. Offline. Queued. Pending approval.
  *Transfers:* **Yes. This is the strongest transfer in the folder so far, and none of it needs a chain.** The same shape, in things Ahmed already tests: * A password reset link with no expiry, or one that survives…

**`MTH-W3-005` trace every claim to the party that chose it**
  Take every field the server reads out of a signed or encoded blob, and for each one write down who chose the value it is compared against: the server, or the sender.
  *Signal:* Verification code shaped like this: ``` if (verify(message, signature)) { user = parse(message).address; createSession(user); } ``` **The signal is the gap between line 1 and line 2.** If nothing bet…
  *Transfers:* **Yes, completely, and it is the same bug Ahmed will meet without any web3 at all.** Direct equivalents: * **JWT.** Signature verified, then `iss`, `aud` and `exp` ignored.

**`MTH-W3-006` read your own incident runbook as the attacker's script**
  Take the message the organisation would send during an incident, and treat it as a phishing template the attacker gets to fill in, faster and louder than you can.
  *Signal:* Any user facing instruction that combines **urgency**, **a destination**, and **an unfamiliar action**.
  *Transfers:* **Yes, completely, and it is the item in this folder Ahmed could act on soonest.** The education app fleet reaches users by email, by WhatsApp and through the CRM.

**`MTH-W3-007` ask what the lookup returns when it finds nothing**
  For every read that is keyed by something a caller controls, or that happens before the data is written, ask what comes back on a miss, and then ask whether that value is distinguishable from a real answer.
  *Signal:* Two shapes, and both are visible by reading code rather than by running anything. * A value is fetched by an identifier that arrived in the request, and there is no bounds or existence check on that…
  *Transfers:* **Yes, directly.** The web versions Ahmed can look for tomorrow: * An API that resolves a signing key, an API client or a tenant from an identifier in the request, gets nothing, and continues with an…

**`MTH-W3-008` normalise both sides, or the gate never matches the door**
  Wherever a protection is selected by matching a string, find the code that normalises the request and the code that normalises the rule, and check they are the same function.
  *Signal:* A configuration file where a human wrote the path, the role, the host or the file extension by hand, and a matcher that transforms the incoming value before comparing.
  *Transfers:* **Yes, completely. This is not a web3 method at all**, and it is the strongest transfer in this run.

**`MTH-W3-009` test with two users, because a cache bug is invisible to one**
  Write out the cache key in full, list every input the cached computation actually read, and if the second list is longer than the first, you have found a cross user disclosure.
  *Signal:* Any memoisation, caching or reuse in front of code that reads ambient state: the current request, the session, the logged in user, a token, a tenant.
  *Transfers:* **Yes, completely, and it is the most immediately usable card in this folder for the QA lane.** The same defect, in the fleet's own stack: * A CDN or Varnish rule that caches a page containing the lo…


## The records, by id

### WordPress

* **`WPDS-0001`** wp2shell, pre authentication RCE in WordPress core  | CVE-2026-60137, CVE-2026-63030
* **`WPDS-0002`** XSS2Shell, pre authentication XSS on the WordPress login page  | CVE-2026-64638
* **`WPDS-0003`** Gravity Forms, unauthenticated file upload through the legacy chunked uploader  | CVE-2025-12974
* **`WPDS-0004`** User Access Manager, unauthenticated arbitrary file read through `uamgetfile`  | CVE-2026-18352
* **`WPDS-0005`** BdThemes Biggopti, site takeover through a poisoned vendor data feed  | CVE-2026-18072
* **`WPDS-0006`** Demi, unauthenticated directory deletion through the restore step endpoint  | CVE-2026-14490, CVE-2026-15012
* **`WPDS-0007`** Bookly unauthenticated SQL injection through `staff_ids`  | CVE-2026-14516
* **`WPDS-0008`** WordPress core Author level RCE through Imagick and Ghostscript  | CVE-2026-65640

### Web application

* **`WEBDS-0001`** Spring GraphQL, authorisation annotation silently not applied  | CVE-2026-41856
* **`WEBDS-0002`** Nuxt drops route rules for mixed case paths, so the auth gate never runs  | CVE-2026-53721, CVE-2026-71315
* **`WEBDS-0003`** Nuxt caches the server rendered payload under a path only key, so one user's data is served to the next  | CVE-2026-71316
* **`WEBDS-0004`** Nuxt server islands accept a template key in props, and the runtime compiler executes it  | CVE-2026-71320
* **`WEBDS-0005`** Metabase, unauthenticated SQL injection on the password reset endpoint, exploited in the wild  | CVE-2026-72898
* **`WEBDS-0006`** CodeIgniter deleteBatch ignores the escape flag on where() bindings  | CVE-2026-63221
* **`WEBDS-0007`** CodeIgniter trusts X-Forwarded-Proto from anyone, so isSecure lies  | CVE-2026-63220
* **`WEBDS-0008`** Hono memo() caches on props alone, so context read during render is invisible to the cache key  | CVE-2026-71850
* **`WEBDS-0009`** API Platform accepts a relation IRI pointing at the wrong resource type  | CVE-2026-54164
* **`WEBDS-0010`** Langflow mints a SUPERUSER token for anyone, then runs the Python you send it  | CVE-2026-9198
* **`WEBDS-0011`** DOMPurify leaves a removed element's children armed in IN_PLACE mode  | no CVE
* **`WEBDS-0012`** Laravel temporary signed URL path confusion  | CVE-2026-48041
* **`WEBDS-0013`** Laravel CRLF injection in the default email validation rule  | CVE-2026-48019
* **`WEBDS-0014`** Krayin Laravel CRM, pre auth admin takeover through the installer middleware  | CVE-2026-41452
* **`WEBDS-0015`** crypto-js weak random number generator, and why upgrading does not fix it  | CVE-2026-71851
* **`WEBDS-0016`** CodeIgniter upload validation bypass in is_image and mime_in  | CVE-2026-63223
* **`WEBDS-0017`** CodeIgniter path traversal in UploadedFile::move()  | CVE-2026-63222
* **`WEBDS-0018`** the Nuxt dev server hands out the project path to anyone on the LAN  | no CVE
* **`WEBDS-0019`** Open WebUI blocks the metadata address, then fetches the same address written another way  | CVE-2026-70485
* **`WEBDS-0020`** Craft Commerce only rate limits the cart when you tell it which cart  | CVE-2026-55795
* **`WEBDS-0021`** Winter CMS checks handler names on one door and not the other  | CVE-2026-32639, CVE-2026-35445
* **`WEBDS-0022`** one accented letter puts a Markdown line on the slow path  | CVE-2026-71488
* **`WEBDS-0023`** strip_tags cannot protect a JavaScript string, because no tag is needed  | CVE-2026-45694
* **`WEBDS-0024`** the escaping was correct and the search still leaked every user  | CVE-2026-47132
* **`WEBDS-0025`** a MariaDB setting that is really a command line  | CVE-2026-48165

### API

* **`APIDS-0001`** Craft CMS GraphQL, cross volume asset modification  | CVE-2026-25497
* **`APIDS-0002`** WordPress REST batch endpoint dispatches sub requests against the wrong handler  | CVE-2026-63030
* **`APIDS-0003`** WP_Query author__not_in loses its integer casting when passed a string  | CVE-2026-60137
* **`APIDS-0004`** Laravel Passport resolves a client credentials token into a real user account  | CVE-2026-39976
* **`APIDS-0005`** Hono memo() serves one user's rendered output to another  | CVE-2026-71850
* **`APIDS-0006`** Nuxt island endpoint parses and hashes attacker input before it validates it  | CVE-2026-71321
* **`APIDS-0007`** Nuxt DevTools exposes an unauthenticated RPC channel over the Vite HMR WebSocket  | CVE-2026-71319
* **`APIDS-0008`** Craft CMS accepts a replayed passkey login because the challenge comes from the request  | no CVE
* **`APIDS-0009`** the webhook parser is handed the secret and never reads it  | CVE-2026-47212
* **`APIDS-0010`** the AI chat memory is filtered by session, and session is not an owner  | CVE-2026-9130
* **`APIDS-0011`** the validation endpoint that executes, and the login endpoint that hands out superuser  | CVE-2026-0770, CVE-2026-9198
* **`APIDS-0012`** a plugin REST route with no permission callback, handing out every admin email  | CVE-2026-2025
* **`APIDS-0013`** the one time offer accepted thirty times at once  | no CVE
* **`APIDS-0014`** the AI gateway test button that spawns a process, and the header bypass in front of it  | CVE-2026-42271, CVE-2026-48710
* **`APIDS-0015`** Langflow validates an AI provider key by fetching a URL the caller supplies  | CVE-2026-9081
* **`APIDS-0016`** the SSRF helper exists, and only the test endpoints call it  | CVE-2026-30840, CVE-2026-33401
* **`APIDS-0017`** the rate limiter counted IPv6 addresses one at a time, and the client had 18 quintillion of them  | CVE-2026-45364
* **`APIDS-0018`** Strapi built the rate limit key out of a field the attacker fills in  | CVE-2025-64526
* **`APIDS-0019`** the second route to the model forgot to ask which models you are allowed  | CVE-2026-44556
* **`APIDS-0020`** the allowlist ran on the envelope, and the batch handler opened it afterwards  | CVE-2026-50008
* **`APIDS-0021`** one GraphQL request, the same expensive query a thousand times, because aliases are free  | CVE-2026-35441
* **`APIDS-0022`** the document was protected, its edit history was not  | CVE-2026-59262
* **`APIDS-0023`** the coupon rate limit only ran if you sent an optional parameter  | CVE-2026-55795
* **`APIDS-0024`** the cache key knew who you were and not what you were allowed  | CVE-2026-61836

### Web3 and the web2 seam

* **`W3DS-0001`** rsETH, forged cross chain message through a single bridge verifier  | no CVE
* **`W3DS-0002`** CrossCurve, a function that forgot who was allowed to call it  | no CVE
* **`W3DS-0003`** Injective SDK, 18 npm packages backdoored to steal wallet keys  | no CVE
* **`W3DS-0004`** Ostium, the signer was authorised so the price was believed  | no CVE
* **`W3DS-0005`** KelpDAO and LayerZero, the verifier's view of the chain was the attacker's  | no CVE
* **`W3DS-0006`** CoW Swap, the registrar handed over the domain and the front end became the attack  | no CVE
* **`W3DS-0007`** VerusCoin, the receipt was authentic and nothing was behind it  | no CVE
* **`W3DS-0008`** COLDCARD, a guard that asked whether the flag existed instead of whether it was on  | no CVE
* **`W3DS-0009`** ERC-721 tokenURI, an on chain asset pointing at a file nobody is committed to  | no CVE
* **`W3DS-0010`** Nine npm packages wearing a brand name, asking the developer for a private key  | no CVE
* **`W3DS-0011`** a signature collected months early, executed on the day  | no CVE
* **`W3DS-0012`** five of seven keys, one compromise  | no CVE
* **`W3DS-0013`** the attacker registers the panic domain before you do  | no CVE
* **`W3DS-0014`** the signature was valid, the message was not the one you issued  | no CVE
* **`W3DS-0015`** a platform migration turned off two factor authentication, and the front ends moved  | no CVE
* **`W3DS-0016`** the minimum was computed by division, and the division rounded to zero  | no CVE
* **`W3DS-0017`** an out of range lookup returned a zero key, and a zero signature verified against it  | no CVE
* **`W3DS-0018`** a secret dropped out of the nonce, so one signature gave up the private key  | no CVE
* **`W3DS-0019`** the router folded case and the rule table did not, so the auth gate never matched  | CVE-2026-53721, CVE-2026-71315
* **`W3DS-0020`** an unauthenticated dev tools channel that runs commands on the developer's machine  | CVE-2026-71319
* **`W3DS-0021`** a render cache keyed on props only, so one user got another user's page  | CVE-2026-71850
* **`W3DS-0022`** minting read an uninitialised slot, got zero, and stamped it on the NFT  | no CVE
