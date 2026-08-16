---
tags: [security, flash, advisories, api, entry, api4, ai-endpoint, vllm]
updated: 2026-08-16
sources:
  - "https://github.com/advisories/GHSA-87x5-vmc3-756j, accessed 2026-08-16"
  - "https://github.com/vllm-project/vllm/commit/675f4295cdfe0d870471c2b51bfeca3a68a9569e, accessed 2026-08-16"
---

# APIDS-0025, one completion request, a thousand engine requests, because the prompt field takes a list

Related: APIDS-0021 (the same shape in GraphQL
aliases), MTH-API-007,
the ledger.

**This is the entry the folder has been hunting for four runs: `API4` on an AI route as the
primary root cause, with a real CVE and a real version range.** Not an essay about AI cost risk.
A named product, a named field, a named missing limit, and a patch that adds it.

```yaml
id: APIDS-0025
component:
  type: service
  ecosystem: pip
  name: vllm
  version_scope: the OpenAI compatible HTTP server, /v1/completions
affected:
  introduced: ">= 0.19.0"
  fixed_in: "0.26.0"
  tested_on: ___
identifiers:
  cve: CVE-2026-73559
  ghsa: GHSA-87x5-vmc3-756j
  osv: ___
  vendor_id: PR 47845
class:
  owasp_api: API4 unrestricted resource consumption
  owasp_2025: ___
  cwe: ___ (the advisory names no CWE; the shape is CWE-770 allocation without limits)
  family: request amplification, one HTTP request into many backend work units
protocol: rest
auth_required: user
entry_point: "POST /v1/completions, the `prompt` field of CompletionRequest, and the same for `prompt_embeds`"
object_graph:
  creates: "one HTTP request creates one CompletionRequest object"
  owns: "the authenticated API client"
  should_reach: "one request should buy one unit of engine work, or a bounded number of them"
  tested_account_got: "engine request slots, async generators and response buffers proportional to a list length the caller chose"
root_cause: >
  The request schema accepts `prompt` as `list[str] | list[list[int]] | str | None` with no upper
  bound on the list length. `prompt_to_seq()` leaves a list shaped input unchanged and only wraps
  a scalar, `OnlineRenderer.preprocess_completion()` expands the whole sequence, and the serving
  layer then creates one async generator and one response slot per element. The missing decision
  is a count check on the outer list, and it belongs in request validation, before preprocessing.
signal: >
  A request field whose type union includes a list, on a route whose cost is per element. Read the
  schema, not the docs. If the field can be a list and nothing in the validator counts it, one
  request is worth as many as the caller writes.
safe_proof: >
  In a disposable lab, send one request with a short marker prompt repeated a countable number of
  times (say 50 copies of the string `canary-apids-0025`), `max_tokens: 1`, `n: 1`. Count the
  engine requests the server logs. If it logs 50 for one HTTP request, the fan out is proved. The
  proof is the count, not the load, so keep the number small enough to be harmless.
controls:
  negative: "send the same prompt as a scalar string. One engine request. That rules out a per token effect."
  differential: "send 2 elements, then 4, then 8, and read the engine request count each time. Linear in the list length is the finding; flat is not."
  false_positive: "a gateway or reverse proxy in front may itself cap the body size, which hides the defect without fixing it. Test against the server directly in the lab."
fix:
  commit: "https://github.com/vllm-project/vllm/commit/675f4295cdfe0d870471c2b51bfeca3a68a9569e"
  invariant: >
    Read from the patch, not inferred. A `@model_validator(mode="before")` on `CompletionRequest`
    rejects the request when `len(prompt)` exceeds `VLLM_MAX_COMPLETION_PROMPTS`, a new environment
    variable defaulting to 1024, and applies the same check to `prompt_embeds`. It raises
    `VLLMValidationError`. **The check runs before preprocessing**, so no generator and no response
    slot is ever allocated for an oversized list.
hardening: >
  Count the work units a request buys, and cap the count at the edge of validation rather than
  inside the worker. Any field that may be a list is a multiplier, so the schema is where the cap
  belongs. On a paid model call, add a per caller spend ceiling as well as a per request count
  ceiling, because a bounded fan out repeated often is the same bill.
detection: >
  One access log line for many engine or inference log lines is the signature. A gateway keys on
  request body size, which is a poor proxy: a thousand one character prompts is a small body. The
  better key is the engine side count grouped by request id.
variant_rule: >
  Every batch shaped field on every AI route: `input` on an embeddings endpoint, `messages` on a
  chat endpoint, `texts` on a rerank endpoint, `documents` on an ingest endpoint. Also the same
  shape outside AI: a GraphQL alias list (APIDS-0021), a REST batch envelope (APIDS-0002,
  APIDS-0020), a webhook fan out. **On Ahmed's fleet the target is any route that forwards to
  Anthropic, Groq or ZAI: if the caller supplies a list, the caller sets the bill.**
lab:
  install: "pip install vllm==0.25.x in a disposable venv, serve a tiny model on loopback only"
  snapshot: "none needed, the defect is in request handling"
  teardown: "delete the venv"
provenance:
  source: "GitHub Security Advisory GHSA-87x5-vmc3-756j, and the linked fix commit"
  accessed: 2026-08-16
  license_note: "advisory text summarised, not reproduced"
```

## What happens

The completions route takes a field called `prompt`. It can be one string, or it can be a list of
strings. The server does not count the list. It just walks it, and for every element it starts a
separate piece of engine work.

So one HTTP request goes in and a thousand engine requests come out. Any budget that counts
requests is now wrong by a factor the caller picked.

## Why it works

The type says the field may be a list. Nothing in the validator says how long a list. The code
that turns a request into work treats a list as already a sequence and passes it straight through.
By the time anything downstream could push back, the generators and the response slots are already
allocated.

The reporter's own words, quoted from the advisory: one request can consume CPU, memory, async
task scheduling, engine request slots and response buffering proportional to an attacker chosen
outer prompt list.

## How to reproduce

Stand up an affected version in a lab on loopback. Send one request with a list of fifty marker
prompts and `max_tokens: 1`. Read the server log. Fifty engine requests for one HTTP request is
the whole finding. Then send the same prompt as a plain string and confirm you get one.

## The fix, and why the obvious fix would not work

The patch adds `VLLM_MAX_COMPLETION_PROMPTS`, default 1024, checked before preprocessing.

The obvious fix would be a body size limit at the proxy. That does not work here. A thousand one
character prompts is a tiny body. The cost is not in the bytes, it is in the element count, so the
limit has to be on the count and it has to live where the schema is parsed.

The second obvious fix would be a per request rate limit. That does not work either, and this is
the point worth carrying: **the rate limiter counts requests, and this bug changes what a request
is worth.** A limit of ten requests a minute is a limit of ten thousand engine calls a minute the
moment one request can carry a thousand. See
MTH-API-007.
