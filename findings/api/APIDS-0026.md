---
tags: [security, flash, advisories, api, entry, api8, cors, rag, lightrag]
updated: 2026-08-16
sources:
  - "https://github.com/advisories/GHSA-6x6h-qqr7-855w, accessed 2026-08-16"
---

# APIDS-0026, the wildcard and the credentials flag were both true, so every origin was allowed

Related: APIDS-0029 (the other CORS entry of this
run), MTH-API-011,
the ledger.

**The folder's first `API8` as a primary root cause.** That row had been at zero for four runs and
secondary three times. It is also a RAG server, which puts it on the same shelf as Ahmed's AI
routes.

```yaml
id: APIDS-0026
component:
  type: service
  ecosystem: pip
  name: lightrag-hku
  version_scope: the LightRAG API server
affected:
  introduced: ___
  fixed_in: "1.5.4"
  tested_on: ___
identifiers:
  cve: CVE-2026-61736
  ghsa: GHSA-6x6h-qqr7-855w
  osv: ___
  vendor_id: "HKUDS/LightRAG PR 3317, commits 09567a4, df68d75, ebba654"
class:
  owasp_api: API8 security misconfiguration
  owasp_2025: ___
  cwe: CWE-942 permissive cross domain security policy
  family: cross origin policy, the wildcard that is not a wildcard
protocol: rest
auth_required: none (the attacker needs no account; the victim must be logged in and must visit the attacker's page)
entry_point: "any authenticated route on the LightRAG server, reached cross origin from a browser. The advisory names /login and /documents"
object_graph:
  creates: "the victim's session cookie, created by their own login to the LightRAG server"
  owns: "the victim"
  should_reach: "only pages served from origins the operator listed"
  tested_account_got: "any page on the internet, reading and writing as the victim, because the server echoed whatever origin asked"
root_cause: >
  Two configuration values that are individually reasonable and jointly fatal. The default sets
  `CORS_ORIGINS=*`, and the middleware is constructed with `allow_credentials=True`. Starlette's
  CORSMiddleware does not refuse that combination. Its preflight logic reduces to "not
  allow_all_origins or allow_credentials", which is true here, so instead of answering with a
  literal `*` it echoes back the requesting origin. An echoed origin plus credentials is a valid
  credentialed cross origin grant, which a literal `*` never is. The missing decision is a refusal
  at construction time: wildcard and credentials must not both be set.
signal: >
  Read the CORS configuration as two values, not one. A wildcard alone is usually harmless because
  the browser refuses to send cookies to it. The finding is the pair. So the grep is not "star", it
  is "star **and** credentials", and the second half is the one nobody looks at.
safe_proof: >
  Static, no traffic needed: read the server's middleware construction and the default config, and
  confirm both values. If a live check is wanted, in a lab only, load a local page from a different
  port that issues a credentialed fetch for a marker document created for the test, and check
  whether the response carries `Access-Control-Allow-Origin` echoing that port together with
  `Access-Control-Allow-Credentials: true`. Read only, one marker document, nothing destructive.
controls:
  negative: "issue the same fetch without credentials. If it succeeds either way, the finding is weaker than it looks, because the data was public anyway."
  differential: "send an origin the operator did list and one they did not. If the response header echoes both, the allowlist is not being consulted at all."
  false_positive: "a reverse proxy in front may strip or rewrite the CORS headers, so a production check can pass while the application is still wrong. Check the application, then the deployed stack, and report both."
fix:
  commit: "https://github.com/HKUDS/LightRAG/pull/3317 (commits 09567a4, df68d75, ebba654). Not read this run"
  invariant: >
    Stated from the defect, not read from the patch: the server must not present a credentialed
    cross origin grant to an origin the operator did not name. In practice that means refusing to
    start, or dropping credentials, when the origin list is a wildcard.
hardening: >
  Make the pair impossible rather than discouraged. Validate at startup: if the origin list
  contains `*`, force `allow_credentials=False` and log it loudly. An allowlist read from
  configuration should also be non empty by default, so that shipping with no configuration is a
  closed door rather than an open one.
detection: >
  Response headers are the whole tell. `Access-Control-Allow-Origin` that changes with the request
  origin, together with `Access-Control-Allow-Credentials: true`, is the fingerprint. It is visible
  on any single preflight response, which makes it one of the cheapest things to check in a whole
  API review.
variant_rule: >
  Every framework with a CORS helper: Starlette and FastAPI, Express `cors`, Laravel's
  `config/cors.php`, WordPress `rest_send_cors_headers`, Spring's `@CrossOrigin`. Also the
  neighbouring misconfigurations that live in the same file: a regex origin matcher that is not
  anchored, an allowlist that matches on `endsWith`, and `Vary: Origin` missing so a cache serves
  one origin's grant to another. **On Ahmed's fleet: every custom REST route that a browser front
  end calls, and anything standing up a FastAPI or Starlette service next to the AI providers.**
lab:
  install: "pip install lightrag-hku==1.5.3 in a disposable venv, bind loopback"
  snapshot: "none needed"
  teardown: "delete the venv"
provenance:
  source: "GitHub Security Advisory GHSA-6x6h-qqr7-855w"
  accessed: 2026-08-16
  license_note: "advisory text summarised, not reproduced"
```

## What happens

A logged in user visits any web page. That page runs a script that calls the LightRAG API with the
user's cookies attached. The API answers. The page reads the answer.

That should be impossible. The browser is supposed to ask the server first, and the server is
supposed to say no to origins it does not know. Here it says yes to everyone.

## Why it works

The operator set the allowed origin list to `*`, meaning "anywhere". They also turned on
`allow_credentials`, meaning "cookies are fine".

A browser will not send cookies to a literal `*`, so on its own the wildcard is mostly harmless.
But the middleware sees that credentials are enabled and, instead of answering `*`, it copies the
asking origin into the answer. A copied origin is a specific origin. A specific origin plus
credentials is a real grant. The browser obeys.

So the wildcard, which was supposed to be the safe lazy setting, became a per origin allowlist of
everything.

## How to reproduce

Read the config. That is genuinely enough for the finding. Two lines: the origins default and the
`allow_credentials` argument. If both are set, it is present.

## The fix, and why the obvious fix would not work

Set a real origin list.

The obvious fix is to remove the wildcard and leave credentials on. That is correct here but it is
not the general lesson, because the same server is one careless deploy away from having the
wildcard back. The durable fix is the startup refusal: the two settings are not allowed to be true
at once, and the process says so out loud rather than quietly resolving it in the attacker's
favour.
</content>
