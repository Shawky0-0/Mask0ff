# Race-condition operations

Use this reference when timing, concurrency, idempotency, TOCTOU, double-spend, partial construction, or hidden state transitions are part of the hypothesis. Use the long-form `techniques/08-business-logic-race-operations/race_conditions.md` only for the smallest relevant pattern or protocol section.

## Contents

1. Entry criteria
2. Invariant and collision model
3. Five-phase workflow
4. Delivery selection
5. Evidence contract
6. False-positive controls
7. White-box and hybrid route
8. Safety and stopping rules

## Entry criteria

Before active execution, record:

- exact target and written authorization;
- whether race or concurrency testing is prohibited or specially limited;
- request-rate, concurrency, attempt, and testing-window limits;
- researcher-owned accounts, objects, balances, inventory, tokens, and side effects;
- the authoritative state source and how it can be reset;
- the transport, proxy/CDN path, session model, asynchronous completion signal, and expected secure invariant.

Do not treat ordinary host scope as permission for stress, resource exhaustion, or high-concurrency work. Prefer a local lab or staging environment. In production, start with two lanes and two attempts and increase only when the written rules, observed load, and minimum-safe proof require it.

Generate a structured plan first:

```powershell
.\scripts\mask0ff.cmd race plan --work-mode active-authorized --assessment-mode black-box --surface api --protocol auto --pattern state-machine --max-concurrency 2 --max-attempts 2
```

## Invariant and collision model

Name the security property before sending concurrent requests:

| Field | Question |
|---|---|
| Actor | Which owned identity initiates each lane? |
| Object | Which account, order, invite, token, resource, or record is shared? |
| Precondition | What must be true before the transition begins? |
| Check | Which limit, authorization, balance, uniqueness, or lifecycle decision is made? |
| Use/write | Which side effect assumes the checked state stayed unchanged? |
| Hidden sub-state | What temporary state can exist inside one request or across services? |
| Authority | Which database, ledger, job status, or downstream system defines final truth? |
| Invariant | What must remain true after every legal interleaving? |
| Reset | How is each run returned to fresh synthetic state? |

Prioritize collisions involving one-time tokens, counters, balance or inventory updates, invitations, role changes, account recovery, object construction, idempotency keys, payment/webhook reconciliation, queue consumers, retries, rollback, cache invalidation, or authorization revocation.

## Five-phase workflow

### 1. Learn and predict

- Search comparable reports, advisories, patches, tests, and framework transaction or session-lock behavior.
- Extract the failed state assumption, required interleaving, authoritative state, safe proof, common false positives, and fix invariant.
- Diagram checks, writes, locks, transactions, caches, queues, webhooks, retries, compensating actions, and irreversible effects.
- Write one falsifiable collision hypothesis. Do not begin with a large concurrent burst.

### 2. Benchmark sequentially

- Reset to clean synthetic state.
- Send the exact request group sequentially at least twice.
- Measure connection setup, endpoint latency, job completion, session locking, retries, and final state.
- Preserve each request and response, monotonic timing, correlation IDs, downstream events, and authoritative pre-state/final state.
- If the sequential baseline is unstable, fix the test design before adding concurrency.

### 3. Synchronize with the correct primitive

- Fingerprint the negotiated protocol rather than assuming it.
- For HTTP/2, prefer Burp Repeater parallel groups or Turbo Intruder's BURP2 single-packet gate when allowed.
- For HTTP/1.1, use a reviewed last-byte synchronization implementation when network jitter matters.
- Use the bundled barrier runner only for low-volume preliminary evidence; it releases client threads together but is not a wire-level synchronization primitive.
- For WebSocket, gRPC, queues, workers, or local code, use a protocol-aware barrier or deterministic scheduler and correlate server-side events.
- Warm connections only with harmless requests and only when the program rules allow it.

### 4. Probe and discriminate

- Reset state before each attempt and change only delivery timing.
- Compare sequential versus synchronized requests, not just one successful response.
- Test shared versus separate sessions to identify session serialization.
- Compare unique versus reused idempotency keys and client-generated versus server-generated identifiers.
- Wait for asynchronous jobs to settle, then query the authoritative store or lifecycle endpoint.
- Minimize the group to the smallest interleaving that preserves the effect.

### 5. Prove and hand off

- Require an owned-data invariant violation in authoritative final state, not timing or response variation alone.
- Repeat from clean state in a separate run and preserve contradictory outcomes.
- Bound impact to the demonstrated actor, object, quantity, role, and transition.
- Give the X1 validator a blind packet, reset instructions, raw artifacts, and environmental limitations.
- The validator must create a fresh baseline, reproduction, state check, and controls. Discovery artifacts cannot pass X1.

## Delivery selection

| Target behavior | Preferred delivery | Required control |
|---|---|---|
| HTTP/2 single endpoint | Single-packet gate | Sequential group and final-state comparison |
| HTTP/2 multiple endpoints | Single-packet group plus measured alignment | Endpoint latency and connection-warming control |
| HTTP/1.1 | Last-byte synchronization | Compare against ordinary barrier delivery and network jitter |
| Session-locked framework | Separate owned sessions plus same-session control | Prove whether serialization masks the collision |
| Async job or webhook | Barrier at producer plus event/job correlation | Wait for terminal state and deduplicate retries |
| Local source | Inserted barrier, deterministic scheduler, fault injection, or debugger | Fixed seed, clean datastore, and patched/locked differential |
| WebSocket or gRPC | Protocol-aware concurrent client | Message/RPC IDs and server-side ordering |

Do not claim that a thread pool, Nuclei race template, or simultaneous button click provides single-packet synchronization. Record the exact delivery primitive and its limitations.

## Evidence contract

For every run, preserve:

- run and attempt ID;
- clean-state/reset evidence and pre-state hash;
- lane ID, actor/session, method, endpoint, object, idempotency key classification, and body hash;
- wall-clock timestamp plus monotonic start and duration;
- delivery primitive, negotiated protocol, connection count, concurrency, timeout, retry policy, and tool version;
- response status, length, body hash, correlation ID, and error class;
- job, queue, webhook, email, ledger, or datastore events when applicable;
- authoritative final-state value or hash after the system settles;
- expected invariant, observed delta, and whether the run supports or contradicts the hypothesis.

Use `assets/evidence-bundle/race-run-config.json` as a local-only starting template. Run a validation-only pass before network execution:

```powershell
.\scripts\mask0ff.cmd race run .\assets\evidence-bundle\race-run-config.json --dry-run
```

The built-in runner rejects non-loopback `local-lab` targets, stored authorization/cookie/API-key headers, unsupported redirects, a lane group above the recorded `configured_concurrency_limit`, more than 10 lanes, more than 5 attempts, or more than 100 planned requests. For an active target, it also requires a current authorization receipt whose target and allowed action or action group pass the authorization gate and which does not explicitly prohibit race/concurrency testing.

## False-positive controls

Actively rule out:

- client, proxy, SDK, or load-balancer retries;
- duplicate responses without duplicate committed effects;
- stale reads, eventual consistency, replica lag, cache variance, or delayed UI refresh;
- expected idempotent replay or documented at-least-once delivery;
- session-level locking that serializes same-session requests;
- WAF/rate-limit interference, connection setup skew, and network jitter;
- background work still pending when state is inspected;
- contaminated accounts, prior grants, reused tokens, or incomplete resets;
- synthetic harness behavior that cannot occur in the deployed configuration.

A response anomaly is a clue. A candidate requires a repeatable state invariant violation. Verification additionally requires clean repeats, bounded impact, and independent X1 reproduction.

## White-box and hybrid route

- Locate the check and side effect and identify the shared resource or stale snapshot between them.
- Inspect transaction isolation, lock scope/order, compare-and-swap behavior, uniqueness constraints, idempotency storage, job acknowledgment, retry, and rollback semantics.
- Search sibling transitions that share the same counter, authorization snapshot, ledger row, queue consumer, or compensating action.
- Add deterministic barriers or fault-injection hooks around the suspected window in a local regression.
- Run the same schedule against the patched design. The fix control should preserve the invariant for every tested interleaving, not merely narrow the timing window.
- Use language/runtime race detectors for memory races where applicable, but do not confuse a data-race warning with a remotely reachable security impact.

## Safety and stopping rules

Stop active execution on unexpected load, error amplification, resource exhaustion, third-party effects, unintended emails/messages, financial movement, real inventory changes, authentication leakage, scope drift, or an invalid session. Do not use dummy traffic to exhaust a rate/resource limit merely to align a race window unless the written authorization explicitly permits that exact technique.

Stop discovery once the smallest safe invariant violation is proven. Continue with passive root-cause analysis, fix testing, duplicate research, evidence review, and independent validation.
