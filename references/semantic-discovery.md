# Semantic discovery: hunt unexpected routes to old primitives

Adapts the Zero-Day Discovery Engine (ZDE) operational framework to mask0ff. The core shift: do not organize research only around sink patterns (`exec`, `eval`, deserialization, template injection). Reconstruct where information changes meaning and where that changed meaning acquires authority.

Central query:

> Can externally influenced information survive one or more changes of representation, trust, time, grammar, consumer, repository, or identity until it acquires a capability that another subsystem can turn into greater authority?

The weirdest high-value vulnerabilities are usually not a new execution primitive; they are an unexpected route to an old one.

## Operating principles

1. **Trust is provenance, not location** — DB rows, queues, caches, artifacts, internal RPC, generated files, and AI memory retain their original trust history.
2. **Meaning is state** — record whether a value changed from data to path, configuration, expression, object type, tool argument, build input, etc.
3. **Authority is explicit** — every execution context has a principal, tenant, privileges, reachability, and capabilities.
4. **Environment is part of reachability** — a path is valid only if runtime/version/plugin/feature/IAM/deployment predicates are satisfiable.
5. **Weak primitives compose** — file creation, path control, SSRF, configuration control, stored injection, parser confusion, or workflow influence are not dismissed because they are not independently RCE. Effects of one primitive can satisfy the requirements of the next.
6. **Evidence outranks model confidence** — hypotheses are generated and challenged; deterministic analysis and isolated reproduction decide survival.

## Semantic-route checklist (before selecting a test)

Ask for the target's most interesting flows:

- Where does externally influenced data cross a **store** (DB, queue, cache, artifact, memory) and later get consumed as something else?
- Which **metadata** (branch names, titles, filenames, labels, headers, tags) can become executable content — CI scripts, generated config, expressions, class identifiers?
- Where is data **validated for one grammar** (JSON, HTML, URL) but consumed under another (shell, template, SQL, expression, loader)?
- Which consumer runs with **higher authority** than the origin (worker, runner, admin, service identity, cron)?
- Which **fallback/error path** (default resolver, unknown type, auto-detect, legacy, retry) bypasses the checks of the normal path?
- Which **generated artifacts** (config, scripts, manifests, Dockerfiles, workflows) are produced from untrusted inputs without destination-grammar validation?
- Which **framework convenience** (data binding, expression routing, reflection, plugin discovery, ORM callbacks, auto-import) silently performs a semantic transition?
- Which **assumption** is the code implicitly making ("only internal callers", "sanitized", "already validated", "cannot happen") — and can it be falsified?
- Which **weak primitive** (controlled file name, SSRF, config write, stored value) can compose into a stronger capability later?

## Using the `weird` command

Run the Weird-Surface Score on every candidate before investing in evidence gates:

```powershell
.\scripts\mask0ff.cmd weird --candidate candidate.json --finding E:\research\finding-work\finding-record.json
```

It reports:

- `weird_surface_score` (0-100): search priority from attacker control, semantic mutability, context changes, privilege delta, grammar mismatch, deferred processing, interpreter proximity, attention asymmetry, fallback behavior, novelty. This is a search priority, never a severity.
- `semantic_transitions`: detected role pairs such as `STORED_DATA -> TEMPLATE_DATA` or `METADATA -> CLASS_IDENTIFIER` — these are the routes to investigate.
- `evidence_confidence`: from the finding-record gates (0-1). Evidence outranks model confidence: never present a high WSS / low evidence candidate as equivalent to a reproduced one.
- `final_priority` = WSS × evidence confidence.

Use it to rank hypotheses and to decide where the next recon effort goes; do not use it to claim severity.

## Semantic transition vocabulary

High-value transitions (source role → capability role):

| From | To |
|---|---|
| RAW_DATA / STORED_DATA / METADATA | TEMPLATE_DATA, EXPRESSION, CONFIGURATION, COMMAND_ARGUMENT |
| PATH_COMPONENT / FILESYSTEM_OBJECT | MODULE_IDENTIFIER, CONFIGURATION, COMMAND_ARGUMENT |
| METADATA | WORKFLOW_INSTRUCTION, BUILD_INSTRUCTION, TOOL_ARGUMENT |
| GENERATED_CONFIGURATION | any second parser or interpreter |

The transition is interesting when the consumer's authority exceeds the origin's, the validating grammar differs from the consuming grammar, or the explicit meaning differs from the effective meaning. Never infer a vulnerability from a transition alone: build the evidence chain and demonstrate impact.

## Composition: weak primitives into chains

Do not reject a primitive because it is not RCE. Model each primitive as requirements → effects, and compose when `Effects(A) ⊨ Requirements(B)` under satisfiable environment guards:

- controlled file creation → loader discovers file → module loaded as service identity
- SSRF or callback → metadata fetch → generated config → second parser
- stored injection → async worker → generated artifact → privileged consumer
- config control → feature flag flip → unsafe default path

Chain depth starts at 2-3 primitives; each link needs its own evidence floor. A chain hypothesis is still just a hypothesis until P1-C1 evidence demonstrates each link.

## Assumption falsification

Instead of asking "is this code vulnerable?", ask: "what security claim does this code make, and can the evidence disprove that claim?" Convert natural-language assumptions into falsifiers:

- "only internal callers can influence this value" → find an external-origin path to it.
- "already sanitized" → check the consumer grammar, not the producer validator.
- "cannot happen" → find the fallback or state transition where it does.

A falsifier that survives becomes the H1 hypothesis; a falsifier that succeeds refutes the claim. Record refuted assumptions; they are the negative evidence that makes the next hypothesis sharper.

## False-positive taxonomy (apply to every candidate)

Classify refutations precisely instead of a generic "false positive":

| Code | Failure |
|---|---|
| FP-SOURCE | attacker does not actually control the alleged source |
| FP-STRUCTURE | schema/type system prevents the proposed structure |
| FP-FLOW | static call/data-flow edge is infeasible |
| FP-GRAMMAR | final consumer uses a safe typed API or destination-grammar validation |
| FP-PRIV | no meaningful authority increase exists |
| FP-ENV | required environment predicates cannot coexist |
| FP-TIME | stored value is revalidated or provenance is correctly constrained later |
| FP-SINK | alleged sink is not execution/capability-relevant in this deployment |
| FP-IDENTITY | action occurs only under the attacker's existing equivalent authority |
| FP-RACE | required timing/state condition is not practically satisfiable |
| FP-ASSUMPTION | inferred security assumption unsupported by the implementation |
| FP-DUPLICATE | same root cause as a known finding |
| FP-MODEL | hypothesis contains unsupported invented behavior |

Record the code with each refuted hypothesis. The taxonomy is also the training signal: if the same code keeps recurring, adjust the method card.

## Validation ladder mapping

ZDE proof levels align with mask0ff gates:

| ZDE | Meaning | mask0ff equivalent |
|---|---|---|
| P0 | plausible path, graph anchors | H1 hypothesis |
| P1 | anchored source and sink | A1 target model + H1 evidence |
| P2 | complete static path, satisfiable guards | B1 + P1 |
| P3 | dynamically observed (stub/canary) | P1 + C1 |
| P4 | benign capability proof | C1 + R1 |
| P5 | target-equivalent proof in an isolated replica | X1 |
| P6 | remediation verified | F1 + D1 + Q1 |

P0/P1 are research leads; P3/P4 is normally enough to call a vulnerability technically demonstrated; P6 is disclosure-quality closure. Never present a P0/P1 lead as a demonstrated finding.
