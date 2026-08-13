---
tags: [security, flash, advisories, api, entry, ssrf, api7, ai-endpoint, langflow]
updated: 2026-08-13
sources:
  - "https://github.com/advisories/GHSA-fqv5-gx59-2xgv, accessed 2026-08-13"
  - "https://github.com/langflow-ai/langflow/releases, accessed 2026-08-13"
---

# APIDS-0015: Langflow validates an AI provider key by fetching a URL the caller supplies

**The folder's first `API7`.** Related: the API folder,
APIDS-0016, the same class with an incomplete fix,
APIDS-0011 and
APIDS-0010, the other two Langflow entries,
MTH-API-006, the validate route method that
predicted this shape.

```yaml
id: APIDS-0015
component:
  type: service
  ecosystem: python, self hosted AI workflow builder
  name: IBM Langflow OSS
  version_scope: 1.0.0 through 1.10.3
affected:
  introduced: ___ (advisory states the range from 1.0.0, no earlier bound given)
  fixed_in: ___
  tested_on: not tested, reading only
identifiers:
  cve: CVE-2026-9081
  ghsa: GHSA-fqv5-gx59-2xgv
  osv: ___
  vendor_id: IBM support node 7282650, page not read, IBM returns HTTP 403 to this sweep
class:
  owasp_api: API7:2023 server side request forgery
  owasp_2025: ___
  cwe: CWE-918
  family: SSRF via an unvalidated outbound base URL
protocol: rest
auth_required: user
entry_point:
  function: validate_model_provider_key()
  provider: Ollama
  parameter: OLLAMA_BASE_URL, caller supplied
  sink: requests.get()
  route: ___ (the advisory names the function, not the HTTP route)
object_graph:
  creates_the_object: the caller submits a provider configuration containing a base URL
  owns_it: the Langflow user who submits it
  should_reach_it: the caller's own configured Ollama host, and nothing else
  tested_account_got: whatever host the caller names, including 127.0.0.1, RFC1918 addresses,
    link local addresses such as 169.254.169.254, and any internal service the Langflow server
    can reach
root_cause: >
  The missing decision lives inside validate_model_provider_key(). The advisory states the
  function "accepts a user-supplied OLLAMA_BASE_URL parameter and passes it directly to
  requests.get() without validation, scheme/host allowlisting, or filtering of private IP
  ranges". There is no check between the parameter arriving and the request going out.
signal: >
  A route whose whole job is to confirm that a credential works. To confirm it, the server must
  make an outbound request. If the caller also supplies the destination, the caller controls
  where the server points. Any field named base_url, endpoint, host or api_base on a settings
  or validation route carries this question.
safe_proof: >
  Lab only, and never against a live host. Stand up a disposable Langflow in the range, run a
  canary listener on a port the Langflow container can reach but the tester cannot reach from
  outside, and set OLLAMA_BASE_URL to that canary. The proof is one line in the canary log
  showing the request arrived from the server, not from the browser. Nothing is read, nothing
  is written, nothing is destroyed.
controls:
  negative: >
    Point the base URL at a host that does not exist. If the canary still logs a hit, the hit
    came from somewhere other than the tested parameter.
  differential: >
    Make the same request from the tester's own machine directly. If the destination is
    reachable from outside anyway, reaching it through the server proves nothing. The finding
    is only real when the server reaches something the tester cannot.
  attribution: >
    Confirm the source IP in the canary log is the Langflow server, not the tester. Without
    that line, this is a browser making a request and not SSRF.
fix:
  commit_url: ___
  invariant: >
    Not read. IBM's bulletin is the vendor record and returns HTTP 403 to this sweep. The
    invariant that the class requires, stated from the defect rather than from the patch: an
    outbound URL taken from a caller must be resolved and then checked against an allowlist of
    scheme and host, with loopback, RFC1918, link local and CGNAT ranges refused, and the check
    must sit between parsing and the request rather than before parsing.
hardening: >
  Kill the class rather than the instance. Send every outbound call from the application through
  one egress helper that resolves the host, refuses private and metadata ranges, and refuses
  redirects to them. Then the question stops being "does this route validate" and becomes "does
  this route use the helper", which is greppable.
detection: >
  Outbound connections from the application server to 169.254.169.254, to loopback on a port the
  application does not normally use, or to RFC1918 addresses it has no reason to reach. On the
  request side, a settings or validation POST carrying a base URL that is not the tenant's own.
variant_rule: >
  Langflow ships one of these per provider. The v1.11.3 release notes carry
  "fix(security): protect OpenAI model discovery requests", which is the same defect on a
  different provider, fixed separately. So the rule is: when one provider's validation path is
  found unguarded, check every other provider's path, because they were written by copying.
  Read across to any product that validates a credential by calling out: CRM connectors, SMTP
  testers, webhook testers, and RAG source configuration.
lab:
  install: disposable container of a version in the affected range, on an isolated network
  snapshot: before any test
  teardown: destroy the container, do not reuse
provenance:
  source: https://github.com/advisories/GHSA-fqv5-gx59-2xgv
  accessed: 2026-08-13
  license_note: advisory text quoted in short fragments for the technical description only
```

## What happens

Langflow lets a user plug in an AI provider. Before saving, it offers to check the key works.
To check it, the server calls the provider. For Ollama, the user also gets to say where Ollama
lives, in a field called `OLLAMA_BASE_URL`.

The server takes that address and calls it. It does not ask whether the address is sensible.

So a user who has an account, but no business touching the server's internal network, writes
an internal address into that field. The server calls it and reports back. The user has just
used the server as a telephone into a network they cannot dial themselves.

## Why it works

The check the code performs is "did the request succeed", and that is a real check. The check
the code skips is "should I be making this request at all". Those are different questions, and
only the first one was asked.

CVSS puts privileges required at low, so this needs an account, not an administrator. On a
Langflow instance where any team member can add a provider, any team member has this.

## How you would reproduce it

In a lab, on a throwaway instance in the affected range. Put a listener somewhere the server
can reach and you cannot. Set the base URL to the listener. Look at the listener's log. If the
connection came from the server's address, that is the finding, and you stop there. You do not
go on to read a cloud metadata endpoint, because the log line already proves it.

## What the fix is, and why the obvious fix would not work

The obvious fix is a string check: refuse anything containing `127.0.0.1` or `localhost` or
starting `192.168.`. That fails, and it fails in four separate ways.

A hostname can resolve to a private address, so the string looks fine and the packet still goes
inside. `0.0.0.0` and IPv6 forms and decimal encoded addresses all reach loopback without
matching the pattern. A redirect can send an allowed URL to a refused one after the check has
already passed. And the CGNAT range `100.64.0.0/10` is private in practice and is in nobody's
first draft blocklist, which is exactly the hole
APIDS-0016 documents in a different product.

The fix that holds resolves the name first, checks the resolved address, refuses redirects to
anything that would have been refused, and lives in one shared place rather than in each
provider's validation function.

## The honest gap

`fixed_in` is `___`. Langflow v1.11.0 is the first release above the 1.10.3 ceiling, so it is
the obvious guess, and it stays a guess: no advisory states it and IBM's bulletin, which would,
returns HTTP 403. **Guessed version numbers are how a report gets a fleet patched to the wrong
release, so this stays `___`.** Same reason as
APIDS-0010, same vendor, same 403.
