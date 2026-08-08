# WebSocket security research methodology

Use this reference to investigate WebSocket and WebSocket-adjacent behavior in an authorized target. It intentionally contains method, evidence, and control guidance rather than exploit payload collections.

## Research objectives

- Discover WebSocket endpoints and their HTTP upgrade routes.
- Map authentication, origin, session, subprotocol, and message-level authorization.
- Compare WebSocket behavior with REST, GraphQL-over-HTTP, SSE, mobile, and internal API channels.
- Model connection lifecycle, account state, role changes, subscription state, and reconnect behavior.
- Identify parsing, proxy, cache, and HTTP-version boundaries around the upgrade.
- Validate message-handling candidates with owned accounts, synthetic data, and clean connections.

## Endpoint discovery

Combine multiple sources and retain provenance:

- browser developer tools and signed-in proxy history;
- JavaScript and source searches for WebSocket constructors, client libraries, subscription clients, and upgrade handlers;
- API and event documentation;
- GraphQL subscription configuration;
- mobile/desktop clients and configuration;
- archived URLs and supplied inventories;
- common application route patterns only when allowed and rate bounded.

Normalize each candidate as host, path, scheme, HTTP version, subprotocol, authentication state, source, and scope status. A failed upgrade is still useful evidence about routing, authorization, or proxy behavior.

## Handshake and connection model

Record:

- HTTP method, version, route, and upgrade response;
- origin and site context;
- cookies, tokens, client certificates, or initial-message authentication by reference only;
- requested and selected subprotocol;
- reverse proxy/CDN/WAF path;
- server or framework version when defensibly fingerprinted;
- connection identity and tenant binding;
- whether authorization occurs at handshake, initialization, subscribe, message, and event-delivery time.

Build controls with fresh sessions:

- intended authenticated connection;
- unauthenticated connection;
- invalid or expired session;
- wrong role, tenant, or account state;
- allowed and disallowed origin;
- missing, invalid, and alternate subprotocol;
- initialization before and after messages;
- role revocation while a connection remains open;
- reconnect and session refresh.

Do not infer cross-site hijacking from a permissive upgrade alone. Prove whether browser credentials accompany the connection, whether attacker-controlled origin context is accepted, and whether a consequential read or action occurs with owned data.

## Message and object authorization

Create an operation matrix:

| Dimension | Examples to record |
|---|---|
| Actor | anonymous, member, privileged member, administrator, service |
| Tenant/object | owned, same-tenant foreign, cross-tenant synthetic, nonexistent |
| Operation | subscribe, read, publish, mutate, join, leave, acknowledge |
| State | new, initialized, authenticated, revoked, expired, reconnected |
| Channel | WebSocket, HTTP/REST, GraphQL, SSE, mobile/client |

For each message, preserve connection/run ID, direction, opcode or message type, correlation ID, actor/tenant, object, pre-state, expected policy, response/event, post-state, and artifact hash.

High-value questions:

- Does the server authorize the room, topic, object, or field for every operation?
- Are opaque channel IDs treated as authorization?
- Does a shared backend or service token cause a confused deputy?
- Are nested fields or subscription events filtered differently from the initial query?
- Does authorization happen only when subscribing rather than for each event?
- Does revocation, deactivation, password expiry, tenant change, or logout terminate effective access?
- Can messages be accepted before authentication or initialization completes?
- Do batch, alias, replay, reconnect, or resume features bypass per-message policy?

Use two researcher-owned accounts or tenants when authorization differentials are relevant. Never test with guessed third-party objects.

## Client and rendering boundaries

Trace incoming event data through parsers and UI sinks. Record origin, renderer, browser context, sanitization/encoding, CSP or Trusted Types behavior, and any privileged action caused by rendering.

Reflection in a frame is not browser execution. Use inert markers, DOM/runtime evidence, controlled callbacks, and clean-browser controls. Compare the same content across ordinary user, staff/admin, notification, export, mobile, and embedded renderers where authorized.

## Parser and protocol boundaries

Identify the message format and its implementation:

- JSON or custom JSON envelopes;
- GraphQL subscription protocols;
- text commands;
- XML;
- binary formats such as protobuf or MessagePack;
- compressed or fragmented frames;
- application-level multiplexing.

Compare validation and interpretation across client, proxy, gateway, framework, message broker, and backend. Focus on observed differences in type handling, normalization, duplicated fields, message ordering, fragmentation, compression, and error behavior. Do not send unbounded malformed frames or resource-exhaustion cases unless exact authorization permits them.

## HTTP upgrade and infrastructure boundaries

Map the connection path from browser/client to edge, proxy, gateway, and backend. Determine whether HTTP/1.1 and HTTP/2 extended-connect paths share the same:

- authentication and origin policy;
- routing and host validation;
- request normalization;
- logging and rate limits;
- message inspection;
- backend connection pool and timeout behavior.

Treat request-smuggling, desynchronization, high-volume connection, and resource-exhaustion hypotheses as separately authorized high-risk work. Prefer passive configuration review, source analysis, or an owned local proxy/backend lab.

## State, replay, and race analysis

Model the connection state machine:

```text
disconnected -> upgrading -> connected -> initialized -> authenticated -> subscribed -> revoked/expired -> closed/reconnected
```

Challenge transitions and asynchronous events:

- message before initialization;
- subscribe before authentication;
- authorization change after subscribe;
- replay after reconnect;
- duplicated acknowledgements;
- resume token bound to the wrong actor or tenant;
- event delivery after object deletion or access revocation;
- concurrent join/leave, publish/delete, or permission-change flows.

Use bounded concurrency and synthetic state. Record authoritative final state, not only responses.

## Tool-led workflow

Use `toolbox --surface websocket` to inventory available capabilities. Typical stages are:

1. Search source and clients for endpoint and protocol definitions.
2. Capture representative signed-in connections through a browser or proxy.
3. Normalize frames and connection metadata into structured records.
4. Build role/object/state/channel baselines.
5. Replay one controlled change at a time with a WebSocket-capable client or small auditable harness.
6. Correlate runtime behavior with handler, middleware, broker, and policy source paths.
7. Preserve clean repeats and independent controls.

Record tool/client versions, exact commands or scripts, TLS/proxy configuration, timestamps, connection IDs, and raw output paths. Automated endpoint or issue matches remain leads.

## Source review

Search for:

- upgrade routing and middleware order;
- origin and subprotocol validation;
- cookie/token extraction and audience/tenant checks;
- connection context construction;
- initialization state;
- room/topic membership checks;
- message dispatch and per-operation authorization;
- subscription filtering and event fanout;
- role/session revocation listeners;
- shared service credentials;
- serializer/parser configuration;
- logging/redaction and rate limits;
- alternate HTTP and WebSocket callers of the same business function.

Trace controlled fields to database queries, templates, URL fetchers, file operations, interpreters, queues, and privileged internal APIs. Search sibling handlers by the missing invariant rather than a payload string.

## Validation controls

- Baseline: intended role, object, state, and message.
- Negative: invalid object, operation, origin, protocol state, or credentials.
- Differential: wrong owner/tenant/role and alternate transport.
- Fresh-state: new connection, clean browser/session, no prior grant.
- Replay: reconnect, resume, duplicate message, and stale authorization.
- Source/runtime: local regression mapped to the deployed revision.
- Fix: corrected policy or parser behavior preserves legitimate operation and blocks the candidate.

Pass R1 only with two clean run artifacts. Pass X1 only when a separate validator receives a blind packet and independently reproduces with new evidence while challenging alternative explanations and every essential chain link.

## Common false positives

- permissive upgrade followed by message-level denial;
- public or intentionally shared channels;
- reflected text that is never rendered or executed;
- client-side mock or cached events mistaken for server behavior;
- stale browser/session authorization;
- proxy-generated errors mistaken for backend parsing;
- test harness sending an invalid frame the real client cannot produce;
- heartbeat, acknowledgement, or broadcast behavior mistaken for cross-user data;
- source path absent from the deployed revision;
- development configuration assumed to match production.

## Reporting

State the endpoint and subprotocol, actor/tenant/object/state, exact lifecycle step, expected policy, observed boundary failure, raw frame/connection evidence, clean controls, source/runtime mapping, independent validation, impact boundary, and safe stopping point. Redact cookies, tokens, session identifiers, private messages, and third-party data.

Verify current protocol, framework, browser, and proxy behavior against primary documentation during a real engagement.
