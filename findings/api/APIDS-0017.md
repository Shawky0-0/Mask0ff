---
tags: [security, flash, advisories, api, entry, api4, rate-limit, ipv6, better-auth]
updated: 2026-08-13
sources:
  - "https://github.com/advisories/GHSA-p6v2-xcpg-h6xw, accessed 2026-08-13"
---

# APIDS-0017: the rate limiter counted IPv6 addresses one at a time, and the client had 18 quintillion of them

Related: APIDS-0018, the same class keyed on a
different attacker controlled value, MTH-API-007,
the method both produced, APIDS-0023, the
business flow that a rate limit was supposed to be protecting.

```yaml
id: APIDS-0017
component:
  type: library
  ecosystem: npm
  name: better-auth
  version_scope: "< 1.4.17, and >= 1.5.0-beta.1 < 1.5.0-beta.9"
affected:
  introduced: ___
  fixed_in: 1.4.17, and 1.5.0-beta.9 on the beta line
  tested_on: not tested, reading only
identifiers:
  cve: CVE-2026-45364
  ghsa: GHSA-p6v2-xcpg-h6xw
  osv: ___
  vendor_id: ___
class:
  owasp_api: API4:2023 unrestricted resource consumption
  owasp_2025: ___
  cwe: CWE-307
  family: the rate limit key is chosen by the caller
protocol: rest
auth_required: none
entry_point:
  routes: sign in, sign up, and password recovery, all authentication endpoints
  parameter: the x-forwarded-for header, or whichever IP bearing header is configured
  function: getIp(), which returned the leftmost x-forwarded-for value unchanged after
    validation, then the key was built by string concatenation with no normalisation
object_graph:
  creates_the_object: the rate limit counter row, created on first request under a given key
  owns_it: nominally the client, identified by IP
  should_reach_it: every request from that one client, so the count accumulates
  tested_account_got: a brand new counter on every request, because the client chose the key
root_cause: >
  Two missing decisions, both inside key construction. First, no prefix masking: the key was the
  exact textual address, so a client holding a normal /64 allocation could "rotate through 2^64
  distinct source addresses without exhausting the per-address counter". Second, no
  normalisation: one address written in uppercase, compressed, IPv4 mapped or hex encoded forms
  produced "multiple distinct keys" for the same machine. The limit itself was correct. The
  identity it counted against was not.
signal: >
  Read what the rate limit key is made of, and ask who controls each part. If any part is
  attacker chosen, the limit counts attackers rather than attempts. An IPv6 address is the trap
  case, because it looks like an identity and is really an allocation: the ISP hands out the
  /64, and everything inside it is free.
safe_proof: >
  Lab only. Stand up the library in the affected range with a low limit, say five attempts. Send
  five requests from one address to confirm the limit engages. Then send five more, each with a
  different address inside the same /64, and confirm none of them are refused. The proof is the
  second five all succeeding. Use deliberately wrong credentials throughout, so nothing
  authenticates and no account is touched.
controls:
  negative: >
    repeat the second batch with all requests using the identical address. If they are still not
    refused, the limiter is off or misconfigured and the finding is not what you think it is
  differential: >
    run the same batch over IPv4. If IPv4 is also unlimited, the defect is broader than the
    IPv6 keying and the report should say so
  attribution: >
    confirm the header the deployment actually trusts. If the proxy in front overwrites
    x-forwarded-for, the client does not control the key and the bypass does not apply to that
    deployment. This is the control most likely to turn a finding into a non finding
fix:
  commit_url: >
    https://github.com/better-auth/better-auth/commit/43e719bcc0c223c7079fa0c611a9cf7ea1188254
    and https://github.com/better-auth/better-auth/commit/57af0f7b910dcf7b1a5c0615d10b9bd56bb69bef
    (referenced in the advisory, not opened by this sweep)
  invariant: >
    Stated in the advisory: a normalizeIP step that "expands compressed IPv6 forms, lowercases
    hex digits, collapses IPv4-mapped IPv6 to plain IPv4, and applies a default /64 prefix
    mask", plus explicit separators in the key so two different inputs cannot concatenate into
    one string. In one line: the key must be a canonical form of an allocation, not a
    caller supplied string.
hardening: >
  Rate limit on something the caller cannot mint. An account id, a verified session, or a
  network prefix rather than an address. Where the only identity available is the network,
  choose the prefix the ISP allocates, not the address the client picks inside it.
detection: >
  A burst of authentication failures spread across many addresses that share a /64 or /56.
  Grouped by prefix it is obviously one attacker. Grouped by address it looks like background
  noise, which is exactly why it survives.
variant_rule: >
  Anywhere a counter has a key. Login throttles, one time password verification, password
  reset, coupon redemption, signup, and anything sold as abuse protection. Ask what the key is
  made of. On Ahmed's fleet this reaches WordPress login throttling plugins and any Laravel
  route using throttle middleware behind a proxy.
lab:
  install: disposable node project pinning an affected version
  snapshot: not required, no persistent state worth keeping
  teardown: delete the project
provenance:
  source: https://github.com/advisories/GHSA-p6v2-xcpg-h6xw
  accessed: 2026-08-13
  license_note: short quoted fragments for the technical description only
  credit: reported by @nexryai
```

## What happens

A rate limiter counts your attempts and cuts you off at some number. To count, it needs to know
which requests are yours, so it keeps a tally per IP address.

With IPv4 that mostly works, because an address is scarce and you probably have one.

With IPv6 it collapses. A home connection is not given one address, it is given a block, usually
a /64. That is more addresses than there are grains of sand on earth, and they are all yours.
The limiter counts each one separately, so every request can arrive on a fresh address with a
fresh counter set to zero. The limit never triggers.

There was a second, smaller version of the same problem. The same address can be typed several
different ways, and the limiter treated each spelling as a different machine.

## Why it works

Nothing here is broken in the sense of throwing an error. The limiter does exactly what it was
written to do. It counts per address, correctly, forever.

The mistake is a category one. The code treats an address as an identity. In IPv6 an address is
not an identity, it is one of an enormous number of labels the client can put on itself. The
identity, as close as the network gets to one, is the prefix.

The advisory is honest that this "does not directly compromise any account". It removes a
defence rather than granting access. That still matters, because everything behind it, credential
stuffing, reset flooding, account enumeration by timing, was priced on the assumption the
defence worked.

## How you would reproduce it

Lab, wrong passwords only. Prove the limit works from one address. Then walk across the /64 and
watch it stop working. Nothing authenticates, so nothing is at risk.

## What the fix is, and why the obvious fix would not work

The obvious fix is to lower the limit. It does nothing: the limit was never reached.

The second obvious fix is to normalise the text so different spellings of one address collapse
together. Necessary, and on its own useless, because the attacker was never relying on
respellings. They were using genuinely different addresses that they genuinely hold.

The fix that works masks to the prefix, so the whole /64 shares one counter, and normalises on
top of that so the spellings cannot split it again. Both halves, in that order of importance.

## The control that matters most here

The attribution control, above, is the one that decides whether this is real on a given site.
If a reverse proxy or a CDN overwrites `x-forwarded-for` before the application sees it, the
client cannot choose the key and the bypass dies at the edge. **Check the proxy before writing
this up as exploitable anywhere.** That check is the difference between a finding and an
embarrassment.
