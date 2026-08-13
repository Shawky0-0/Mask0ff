---
tags: [security, flash, advisories, method, wordpress, ai-features, nopriv, ssrf]
updated: 2026-08-13
sources:
  - "https://patchstack.com/articles/unauthenticated-arbitrary-file-read-vulnerability-in-jobify-theme/, accessed 2026-08-13"
  - "https://dhakal-ananda.com.np/advisories/jobify-file-read/, accessed 2026-08-13"
---

# MTH-WP-007, go straight to the AI feature, it is the newest code and the least reviewed

Related: the advisories folder,
MTH-WP-004, poison the feed the plugin trusts,
the EduAi prompt injection finding,
the sweep ledger.

**This one is aimed at Ahmed's actual fleet.** YZH builds AI and RAG features onto an
education app estate. This card is about the shape those features keep arriving in.

## The technique in one line

In any product that has recently grown an AI feature, review that feature first, because it
is the newest code in the codebase, it was written fastest, and it tends to be wired straight
into the front end with no authentication.

## The discovery signal

The signal is a function name. In the Jobify theme it was `download_image_via_ai`.

Read what that name tells you before reading any code. It says a feature was added to fetch
an image on the user's behalf, as part of an AI workflow, and it says so in a theme where
every other function is about job listings. It is newer than everything around it. It does a
network fetch, which most theme code never does. And the naming style does not match the rest
of the file, which usually means it was written separately and bolted on.

**Generalise it: grep a codebase for the vocabulary of the current hype cycle.** `ai`, `gpt`,
`openai`, `assistant`, `generate`, `prompt`, `completion`, `embed`, `rag`, `chat`. The hits
are, almost by construction, the youngest code in the repository. Youngest code has had the
least review, the fewest eyes, and the shortest time to have its bugs found by somebody else.

The same grep works on a plugin directory, a theme, or a client's own application.

## The mechanism

Three failures in three lines. The whole vulnerable function, as published by Patchstack:

```php
add_action('wp_ajax_nopriv_download_image', 'download_image_via_ai');
function download_image_via_ai() {
    $image_url = $_POST['radioValue'];
    $image_data = file_get_contents($image_url);
```

**Registered `nopriv`.** The `wp_ajax_nopriv_` prefix means logged out visitors can call it.
That was almost certainly not a decision. It is what you write when you are testing a feature
in a browser that is not logged in, and it is what stays in when the feature ships.

**No nonce and no capability check.** Nothing between the hook and the work.

**User input straight into `file_get_contents`.** The function takes whatever the client sent
in `radioValue` and reads it. `file_get_contents` does not only read files. With PHP's
`allow_url_fopen` enabled, which is the default on most hosts, it reads URLs too. So the same
line is arbitrary file read and full response server side request forgery at once, and the
attacker picks which one they want by what they put in the parameter.

The AI part is not the vulnerability. The AI feature is the reason a function that fetches an
arbitrary URL exists in a job board theme at all. **That is the pattern: AI features
legitimise capabilities the product never previously needed**, and those capabilities then sit
behind whatever authentication the person adding them remembered to write.

## Does it transfer to WordPress, and how

It is a WordPress finding already. The transfer worth writing down is to Ahmed's fleet.

An AI or RAG feature needs, by its nature, to do things ordinary application code does not:

* **Fetch a URL**, to pull a document, an image, or a page into a prompt. That is SSRF waiting
  to happen, and on cloud hosting the interesting target is the metadata service.
* **Read a file**, to feed a document into an index. That is arbitrary file read.
* **Write a file**, to cache an embedding or store an upload. That is arbitrary file write.
* **Answer without a session**, because chat widgets get demoed to logged out visitors, so
  `nopriv` is where they start and often where they stay.
* **Take long free text**, which is the input the rest of the application has never had to
  handle, and which is the whole of
  EduAi Finding 1.

Where to look on the education fleet, in order:

1. **Every `wp_ajax_nopriv_` registration added in the last year.** List them, then ask of
   each one why a logged out visitor needs it.
2. **Any handler whose name contains the AI vocabulary above**, regardless of what it claims
   to do.
3. **Anywhere a URL from a request reaches `file_get_contents`, `curl_exec`, `wp_remote_get`
   or `fopen`.** `wp_remote_get` is the safer one and is still SSRF if the URL is attacker
   chosen.
4. **The RAG ingestion path specifically**, because it is designed to read things, which
   means the dangerous capability is the feature rather than a bug in it.

## A safe way to test for it

This is a code review technique before it is a testing technique, and reading is always the
safe half.

For the code review: enumerate `add_action( 'wp_ajax_nopriv_...' )` across the codebase, and
for each one write down the answer to two questions. Who is allowed to call this? What does it
do with what they send? A handler where the second answer involves a network call or a file
path, and the first answer is "anyone", is the finding.

For a live check, in Ahmed's lab only and against nothing else: the safe proof for the read
primitive is a canary file. Put a file with known contents at a known path, ask the endpoint
for that path, and see whether the contents come back. Never point it at a real configuration
file, because a successful read of a real credential is a disclosure you then have to handle.
Prove the primitive with a file you planted.

## The control that would catch a false positive

* **Ask for a path that does not exist.** If the response is identical to the successful case,
  the endpoint is not reading anything and you are looking at a fixed template.
* **Ask for a path you planted, and check the contents match byte for byte.** A response that
  merely differs is not proof of a read. A response containing your canary string is.
* **Test with the AI feature disabled or not configured.** Many of these handlers fail early
  without an API key, which makes a vulnerable build look clean, and makes the whole class
  invisible on a staging site that was never given credentials.
* **Separate the file read from the SSRF.** They are the same line but different findings, and
  `allow_url_fopen` being off kills one and not the other. Check the setting rather than
  assuming.

## Where else this shape appears

* **Any feature added under time pressure to keep up with a competitor.** AI is the current
  one. Before it, this card would have been about REST endpoints, and before that about
  mobile app back ends. The vocabulary changes and the pattern does not: newest code, least
  review, widest permissions.
* **Vendor plugins that gained an AI feature in an update.** The plugin was reviewed once, at
  version 1. The AI feature arrived at version 6 and was reviewed by nobody.
* **Admin only AI tools that forgot the admin part.** The developer tested as an
  administrator, so the missing capability check never showed up in testing.
* **Any function name that does not match the naming style of the file it is in.** That
  mismatch is a reliable marker of code written by a different person, at a different time,
  under different review.

## Provenance

| Field | Value |
|---|---|
| Primary source | `https://patchstack.com/articles/unauthenticated-arbitrary-file-read-vulnerability-in-jobify-theme/` |
| Accessed | 2026-08-13 |
| Researcher | Ananda Dhakal, credited on the article |
| Subject | Jobify theme, 4.2.3 and below, CVE-2024-52481, CVSS 7.5, unpatched at publication, roughly 14,000 sales |
| Found via | `https://dhakal-ananda.com.np/advisories/jobify-file-read/`, accessed 2026-08-13, which is the researcher's own advisory index and links to the Patchstack article for the analysis |
| Licence note | public vendor article and public researcher blog, read only, no account used |

**Why this is a method card and not an entry.** The subject fails the B3 criteria: Jobify is a
commercial ThemeForest theme, so a vulnerable build is not installable without buying it, it
was unpatched at publication so there is no fix to diff, and it is a 2024 disclosure rather
than the 2025 and 2026 window the backfill is working. The mechanism is documented well enough
to state the invariant, which is why the method survives even though the entry does not.

**Injection check.** Neither page carries text addressed to an AI agent or any instruction to
run anything.
</content>
