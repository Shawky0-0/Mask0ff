---
tags: [security, flash, advisories, entry, web, llm, ai, rce, kev, exploited, langflow]
updated: 2026-08-12
sources:
  - "CISA KEV JSON feed, https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json accessed 2026-08-12"
  - "SentinelOne vulnerability database and Indusface writeup for CVE-2026-9198, via web search, accessed 2026-08-12"
---

# WEBDS-0010: Langflow mints a SUPERUSER token for anyone, then runs the Python you send it

**Known exploited.** Added to the CISA KEV catalogue on 2026-08-04. Related:
the AI testing systems page,
the web advisories folder.

```yaml
id: WEBDS-0010
component: { type: service, ecosystem: other, name: "IBM Langflow OSS, a visual builder for LLM pipelines", version_scope: "the 1.x line" }
affected: { introduced: "1.0.0", fixed_in: "1.10.1", tested_on: "not tested, desk research only" }
identifiers: { cve: CVE-2026-9198, ghsa: ___, osv: ___, snyk: ___, vendor_id: "IBM advisory, disclosed 2026-07-17" }
class: { owasp_2025: "injection", owasp_api: "API2, broken authentication, for the first half of the chain", owasp_llm: "the AI supply chain and tooling surface rather than a model attack", cwe: "CWE-94, improper control of generation of code", family: "an authentication endpoint that authenticates nobody, chained to an evaluation endpoint", corpus_directory: 10-llm-web-security }
auth_required: none
entry_point: "/api/v1/auto_login to obtain a SUPERUSER token, then /api/v1/validate/code with attacker supplied Python"
root_cause: >
  Two separate missing decisions that are only fatal together. First, /api/v1/auto_login issues
  a SUPERUSER token to any network caller, so the endpoint named for authentication performs
  none. Second, /api/v1/validate/code passes its input to exec(), so a feature described as
  validation is in fact evaluation. Either alone is bad practice that a deployment could
  survive. Chained, an unauthenticated request reaches arbitrary Python as the highest
  privileged user. CVSS 9.8.
signal: >
  Developer convenience endpoints that were never meant to face a network: auto_login, debug,
  validate, preview, playground, and anything whose name promises a check rather than an
  action. In AI tooling specifically, look for anything that accepts code, an expression, or a
  template, because these products exist to let users compose logic and evaluation is the
  product rather than an accident. The second signal is the word validate. Validating code
  usually means running it.
safe_proof: >
  In an isolated lab container with no network egress and no API keys present. Call the token
  endpoint and observe that a token is returned without credentials, which is the whole first
  half of the finding and requires no code execution at all. If the second half must be shown,
  evaluate an expression that only computes a canary, for example a string concatenation
  producing WEBDS0010CANARY, and stop there. Never a shell command, never a file read, never a
  network call.
controls:
  - "Negative control: the same two requests against 1.10.1 must fail."
  - "Differential control: send inert input to the code endpoint and confirm it is parsed rather than executed, which separates evaluation from a syntax check."
  - "False positive to rule out: an instance already configured with authentication enabled in front of it. Record what the deployment looked like, because the finding is about the default and the default is the claim being tested."
fix: { commit_url: ___, invariant: "___, not read. The fix shipped in 1.10.1 on the day of disclosure, 2026-07-17. Reading that diff is carried debt: it is the only way to know whether auto_login was removed, gated, or merely defaulted off" }
hardening: >
  No exec on network input, ever, with no exception for a validation feature. Around the
  product: keep tools of this kind off the internet entirely, behind an authenticating reverse
  proxy or a VPN, which is IBM's own guidance. The general control is that an AI orchestration
  tool is a code execution engine by design, so it should be treated with the threat model of a
  CI runner rather than of a web dashboard.
detection: >
  Any request to /api/v1/auto_login from outside the expected network, and any request to
  /api/v1/validate/code at all. Both are clean signatures. Public exploit code exists on GitHub,
  so opportunistic scanning traffic should be expected rather than treated as targeting.
variant_rule: >
  Every AI pipeline builder, notebook server, low code platform and workflow engine has a code
  or expression node, and the security of the whole product collapses onto the authentication
  in front of it. Check the auth on Jupyter, on n8n and similar workflow tools, on any
  self hosted RAG builder, and on template or formula fields in low code tools. The paired
  question, which is the transferable one: which endpoints does this product expose by default,
  and does any of them hand out credentials.
lab: { install: "docker run a pinned Langflow image below 1.10.1, on an isolated network, with no real API keys in the environment", snapshot: "docker commit the container", teardown: "docker rm the container and delete the image. Never point a lab instance at a real model provider account" }
provenance: { source: "CISA KEV catalogue plus public vulnerability databases, via web search. The IBM advisory itself was not read this run", accessed: 2026-08-12, license_note: "public government catalogue and public vulnerability databases" }
```

## What happens

Langflow is a visual builder for LLM pipelines: you drag nodes around and it wires up a chain.
Two of its HTTP endpoints combine into unauthenticated remote code execution. `/api/v1/auto_login`
hands a SUPERUSER token to whoever asks, and `/api/v1/validate/code` runs the Python it is
given through `exec()`. Chain them and an anonymous request owns the host. CVSS 9.8, affecting
1.0.0 through 1.10.0, fixed in 1.10.1, and on the KEV catalogue since 2026-08-04, which means
it is being used rather than merely published.

## Why it works

Both endpoints are features. `auto_login` exists so that a developer running Langflow on their
laptop does not have to log in every time, and it is genuinely convenient on a laptop. The code
endpoint exists because the product's whole purpose is letting users write logic into nodes,
and checking that logic means running it. The defect is that neither was designed for a
reachable network, and the product ships in the state that assumes it is not.

This is the recurring failure of the AI tooling wave and it is worth naming plainly: these
tools are code execution engines with a friendly interface, and they are deployed with the
casualness of a dashboard. The vulnerability class is not new. The rate at which it is being
shipped is.

## What the fix is, and why the obvious fix is not enough

Upgrade to 1.10.1. The more durable answer is deployment shape: IBM's own guidance is to take
these instances off the internet and put an authenticating proxy or a VPN in front. That is the
honest control, because the next version of this class of tool will ship its own convenience
endpoint and the same reasoning will apply before any CVE exists for it.

**Carried debt on this entry:** the IBM advisory and the 1.10.1 diff were not read. The fields
here come from the KEV catalogue and public vulnerability databases, and the `fix.invariant` is
unknown until that diff is read.
