---
tags: [security, flash, advisories, api, method, api8, cors, origin]
updated: 2026-08-16
sources:
  - "https://github.com/advisories/GHSA-6x6h-qqr7-855w, accessed 2026-08-16"
  - "https://github.com/advisories/GHSA-6cqp-g7gg-8hr5, accessed 2026-08-16"
  - "https://github.com/advisories?query=type%3Areviewed+CORS, accessed 2026-08-16"
---

# MTH-API-011, read the CORS config as a pair, then attack the origin comparison as a parse

Related: APIDS-0026,
APIDS-0029,
APIDS-0028,
MTH-API-008.

**The `API8` method.** That coverage row sat at zero for four runs, and one keyword query against
the GitHub advisory listing produced twelve candidates in a single fetch. The class was not hard.
It had simply never been hunted.

## The technique in one line

A CORS review has exactly two halves, and both are cheap: first check whether the policy grants
credentials to a wildcard, then check whether the origin comparison can be tricked into matching
something the operator never listed.

## The discovery signal

**Half one: nobody reads the second setting.** A wildcard origin list on its own is mostly harmless,
because a browser will not attach cookies to a literal `*`. Everybody knows this, so everybody stops
reading at the wildcard and calls it low severity. The finding is the pair. In
APIDS-0026 the config was `CORS_ORIGINS=*` **and**
`allow_credentials=True`, and Starlette's own preflight logic responds to that pair by echoing back
whatever origin asked, which is a real per origin grant rather than a wildcard. So the grep is not
`*`. It is `*` and `credentials` in the same constructor.

**Half two: a sentinel value in the lookup.** In
APIDS-0029 the Netty handler's origin lookup had a
special branch for the literal string `null` that returned a configuration object before checking
whether null origins were authorised. The gate then read "non null configuration" as "allowed". The
signal is any allowlist lookup whose return value cannot distinguish **recognised** from
**permitted**.

## The mechanism

Cross origin policy is enforced by the browser, on the strength of headers the server sends. Two
things can go wrong and they fail in opposite directions.

The first is a policy that is too generous by construction. `Access-Control-Allow-Origin` echoing
the request origin, together with `Access-Control-Allow-Credentials: true`, is a valid grant to
every site on the internet. It looks like a wildcard in the config file and behaves like an
allowlist of everyone on the wire.

The second is a policy that is correct on paper and wrong in the comparison. The allowlist is real,
but the code that matches an incoming origin against it uses a string operation that admits more
than it should: an unanchored regex, an `endsWith`, a `startsWith`, a special case for a sentinel,
or a subdomain pattern that an attacker can occupy. This run's listing showed the shape twice more:
Coder's workspace app origin check bypassed by UUID based subdomain spoofing (CVE-2026-55438), and
9router's local only gate bypassed by spoofing the `Host` header (CVE-2026-49353).

There is a third member of the family worth naming, because it is the same reasoning applied to a
server that has no CORS at all: **no Origin check plus a loopback bind is DNS rebinding.**
APIDS-0028 is that case, and so are the MCP Ruby SDK
(GHSA-rjr6-rcgv-9m7m) and Serena (CVE-2026-49471). Binding to localhost is not an authorisation
decision, because a web page can make the browser resolve a name to `127.0.0.1`.

## Which OWASP API class

`API8` security misconfiguration, primarily. It becomes `API2` or `API5` in effect, because what
the attacker gets is the victim's authenticated session against routes that were function gated.

## Which protocols

REST and GraphQL over HTTP, anything a browser can reach. Also Server Sent Events and WebSocket,
where the check is the `Origin` header on the upgrade rather than a preflight, and where people
forget it entirely because there is no preflight to remind them.

## Does it reach Ahmed's surface, and how

Yes, in three places, and all three are cheap to check.

1. **EduAi's seven custom REST routes.** If a browser front end calls them from a different origin,
   there is a CORS decision somewhere. WordPress sends its own CORS headers through
   `rest_send_cors_headers`, and plugins override it. Reading what the deployed site actually sends
   is one response header away. **Note the scope rule: an entry about a WordPress REST defect belongs
   to the WordPress sweep. Reading the fleet's own configuration is not writing an entry.**
2. **Any Laravel service.** `config/cors.php` has both settings in one file, `allowed_origins` and
   `supports_credentials`, six lines apart.
3. **Local AI tooling on developer machines.** Any MCP server or agent dashboard bound to loopback,
   with no `Origin` check, is reachable from any page the developer visits. The office LAN reaches
   it directly.

## A safe way to test for it

**Static, and static is the whole method for half one.** Read the config and the middleware
construction. Two values. Write the finding.

For half two, read the matching function, not the list. Ask what it does with: the empty string,
`null`, a listed origin with a suffix appended, a listed origin as a subdomain of an attacker
domain, a different scheme, a different port, and an uppercase variant.

Dynamic, in a lab only: one preflight request per origin variant, reading only the response headers.
No state is changed and nothing is enumerated. Against a live company system this would still be
probing and sits behind the authorisation gate, so it does not happen.

## The control that catches a false positive

**Two controls, and skipping either produces a wrong report.**

1. **Repeat the request without credentials.** If the data comes back either way, the resource was
   public and the CORS policy is not what is exposing it.
2. **Check the deployed stack, not just the application.** A reverse proxy or CDN in front may strip,
   add or overwrite CORS headers, so the application can be wrong while the deployment is safe, or
   the reverse. Report the code default and the deployed behaviour as two separate facts. Merging
   them is how a real defect gets closed as "cannot reproduce".

## Where else this shape appears

Every framework ships a CORS helper and every one of them has this pair of settings: Starlette and
FastAPI, Express `cors`, Django `corsheaders`, Laravel's `config/cors.php`, Spring `@CrossOrigin`,
WordPress `rest_send_cors_headers`. The neighbours in the same file are worth reading while you are
there: a missing `Vary: Origin` (a cache serves one origin's grant to another), an
`Access-Control-Allow-Headers` that echoes the request, and a preflight that is cached for hours by
`Access-Control-Max-Age`.

And the wider rule, which is the same one as
APIDS-0029's variant note: **any sentinel value in
any allowlist.** `*`, `null`, the empty string, `0.0.0.0`, `localhost`, `::`, `.`, `..`. Each is a
value some lookup handles in its own branch, and the question is always whether that branch
short circuits the authorisation test.

## Provenance

* GHSA-6x6h-qqr7-855w, LightRAG CORS wildcard with credentials, accessed 2026-08-16.
* GHSA-6cqp-g7gg-8hr5, Netty CORS short circuit failure, accessed 2026-08-16.
* GHSA-x227-pf99-vffg, PraisonAI MCP SSE with no Origin validation, accessed 2026-08-16.
* The GitHub advisory listing for `CORS`, accessed 2026-08-16, which supplied the Coder, 9router,
  FiftyOne, MCP Ruby SDK and Budibase sightings named above. Those five were read as listing rows
  only, not opened.
</content>
