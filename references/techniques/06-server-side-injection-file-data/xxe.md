# XML external-entity and parser-boundary research

Use this reference for authorized analysis of XML parsers, entity resolution, transformation pipelines, and related file or network boundaries. It intentionally omits exploit payload collections.

## Scope the XML surface

Identify every path that may parse XML directly or indirectly:

- XML request bodies and legacy SOAP services;
- SAML, SVG, office/document formats, feeds, manifests, and configuration imports;
- file uploads, archive extraction, converters, previewers, and report generators;
- background workers, queues, integrations, and mobile/desktop clients;
- XSLT, XPath, schema validation, and XML-to-object mapping;
- third-party libraries that unwrap a container before XML parsing.

Record the entry point, actor, content type, file/container type, parser and version, configuration, transformation steps, execution identity, filesystem boundary, network egress, and response visibility.

## Learn the implementation first

For the exact language, framework, and parser version, verify from current official documentation:

- whether DTD processing is enabled;
- whether external general or parameter entities are resolved;
- whether schemas or transforms may fetch external resources;
- whether XInclude or equivalent inclusion is enabled;
- whether network and file access are separately controlled;
- secure defaults and configuration changes across versions;
- wrapper-library behavior and deployment overrides.

Do not infer safety from a framework name or a modern default. Trace the actual parser instance and options used by the reachable path.

## Tool-led source and dependency analysis

Combine:

- repository search for parser construction, factory options, resolver callbacks, transforms, schema loading, inclusion, and document converters;
- dependency and lockfile inspection for exact parser versions;
- call-graph or dataflow analysis from upload/request/message sources to parser and resource-loading sinks;
- local runtime logging, network capture, filesystem sandboxing, or custom resolver instrumentation;
- route, schema, content-type, file-format, and worker inventory.

Search sibling callers by the invariant: untrusted XML must not resolve attacker-selected external resources or cross the intended file/network boundary. One secure caller does not prove shared helpers or background workers are safe.

## Hypothesis families

Generate a candidate only when target evidence supports it:

- external resource resolution reaches a researcher-owned callback;
- local resource resolution crosses the process's intended file boundary;
- blind parser behavior is observable through controlled network or timing evidence;
- XSLT, schema, inclusion, or document-conversion stages re-enable resource access after an earlier check;
- a container or content-type mismatch routes attacker input to a weaker parser;
- validation and execution use different parsers or configurations;
- asynchronous workers run with broader filesystem or network authority;
- error handling exposes sensitive parser or filesystem details;
- an attempted fix blocks one declaration while leaving another resource-loading capability enabled.

## Minimum-safe validation

Prefer an owned local lab or a researcher-controlled callback.

1. Capture a normal XML baseline.
2. Confirm the input reaches the expected parser with an inert structural change.
3. Use a synthetic local marker or owned callback to test resource resolution.
4. Run negative controls with resolution disabled, an unreachable owned resource, invalid structure, and a patched or secure configuration.
5. Repeat from a clean process or worker state with distinct evidence.
6. Bound impact from the proven parser identity and execution boundary.

Do not read operating-system files, cloud metadata, application secrets, or third-party resources when a synthetic marker proves the same primitive. Do not cause large expansions or resource exhaustion unless exact authorization explicitly permits that separate risk.

## False-positive controls

Rule out:

- client-side parsing or validation;
- proxy/WAF callbacks rather than application-parser callbacks;
- application-generated outbound traffic unrelated to the submitted marker;
- cached conversion results;
- generic upload rejection or content sniffing;
- a development parser/configuration that differs from deployment;
- a callback caused by schema validation tooling outside the target process;
- reflection of XML text without resource resolution;
- source code that is absent from the deployed revision.

Record callback token, timestamp, source IP context, process/worker identity when available, run ID, parser configuration, and artifact hash. Correlate the callback with the exact input and a negative control.

## Container and transformation boundaries

For SVG, office, archive, or other container formats, model each stage:

```text
upload -> type detection -> extraction -> XML parser -> schema/transform/include -> renderer/storage -> cleanup
```

Check whether limits and resource-resolution policy remain consistent across stages and workers. Use small synthetic files and record decompressed size, file count, nested depth, selected parser, and cleanup behavior. Keep archive/resource-exhaustion testing separate from entity-resolution proof.

## Authorization and impact reasoning

Differentiate:

- parser feature enabled but unreachable;
- controlled outbound request;
- controlled local resource access using synthetic data;
- blind response or error oracle;
- access under a privileged worker identity;
- downstream credential or internal-service risk as bounded inference.

Stop once the parser crosses the intended file or network boundary safely. Do not escalate to secrets or internal services to make the report dramatic.

## Variant and fix review

Search:

- all parser factories and helper wrappers;
- synchronous and asynchronous paths;
- API, file upload, import, preview, and administrative channels;
- alternate parsers selected by content type or extension;
- schema, transform, inclusion, and resolver code;
- version/configuration-specific defaults;
- fixes that disable only one syntax instead of all untrusted external resource loading.

A robust fix enforces the invariant in the parser/resource resolver, rejects unnecessary XML features, limits filesystem/network authority, and includes regression tests across sibling paths.

## Evidence and reporting

State the exact parser/version/configuration, reachable entry point, controlled XML source, resolution or transformation sink, execution identity, baseline, synthetic proof, negative/patched controls, clean repeats, source/deployment mapping, observed impact, bounded inference, and safe stopping point.

Treat scanner matches and parser-error messages as leads. Require independent X1 validation from a blind packet and new reproduction/control artifacts before calling the issue verified.
