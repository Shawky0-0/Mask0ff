# Practitioner research operations

Use this reference when a terminal, repository, proxy, browser, cloud CLI, or large target list is available. The model plans, selects, correlates, and challenges; tools produce observable coverage and evidence.

## Contents

1. Operating contract
2. Toolchain inventory
3. Staged reconnaissance
4. Output correlation
5. Adaptive technology onboarding
6. Prior-art method mining
7. Large-scope controls
8. Decision rules

## Operating contract

Do not default to conversational inspection when deterministic collection or analysis can answer the question. Begin with:

1. Normalize scope, exclusions, rate limits, accounts, data rules, and testing window.
2. Inspect the actual environment with `toolbox`; do not assume a binary is installed.
3. Select the smallest tool set that covers the current stage and produces preservable output.
4. Run collection in stages, normalize results, and join them through stable keys.
5. Use model reasoning to identify gaps, contradictions, high-value intersections, and falsifiable hypotheses.
6. Treat every automated match as a lead until the evidence gates pass.

Run:

```powershell
.\scripts\mask0ff.cmd toolbox --assessment-mode hybrid --surface web --surface source --focus "remote code execution" --scale large-scope
```

On Linux use `./scripts/mask0ff.sh` with the same arguments.

## Toolchain inventory

Select by capability, not brand loyalty. Prefer an already installed equivalent when it produces the required artifact.

| Capability | Common tool examples | Required output |
|---|---|---|
| Workspace search/normalization | `rg`, `jq`, `yq`, Python, Git | Stable text/JSON plus exact revision |
| Passive assets and archives | Subfinder, Amass, assetfinder, gau, waybackurls | Candidate + provenance + timestamp |
| DNS and reachable services | dnsx, dig, httpx, naabu, nmap | Host/IP/port/protocol/status/version |
| Crawling and endpoint discovery | Katana, hakrawler, gospider, feroxbuster | URL/method/parameter/source |
| Bounded request fuzzing | ffuf, wfuzz, Radamsa, small custom harnesses | Mutation + baseline/result signatures |
| Template/rule leads | Nuclei, Semgrep, CodeQL, ecosystem scanners | Rule/template version + match location |
| Authenticated/browser analysis | A signed-in browser, proxy, Playwright, mitmproxy, ZAP | Role-bound request/response and DOM/runtime evidence |
| Source/dependency analysis | `rg`, Semgrep, CodeQL, lockfile/SBOM tools | Entry point, transforms, guard, sink, reachable version |
| Runtime/local lab | Test framework, Docker/Podman, strace, debugger, packet capture | Clean run ID, environment, effect, hashes |
| Cloud/infrastructure | Provider CLIs, kubectl, Terraform, Helm, Trivy | Resource, identity, tenant, route, configuration |
| Web3 | Slither, Echidna, Medusa, Foundry, local chain/fork tools | Contract revision, actor, call trace, invariant, state delta |

Verify living usage and safety flags in official documentation before a real engagement. Tool names above are routing examples, not mandatory dependencies.

Never install tools, update templates, or fetch wordlists implicitly during an engagement. Installation and updates change the environment and may require user direction, network access, or provenance review. Record missing capabilities and use an auditable fallback.

## Staged reconnaissance

### 1. Scope and seed normalization

- Convert target exports into an allowlist and explicit denylist.
- Label each seed by asset type, source, ownership confidence, and scope status.
- Reject wildcard expansion that crosses the program's stated organizational boundary.
- Preserve the input export and its hash.

### 2. Passive enumeration

- Combine certificate, DNS, archive, repository, mobile-client, documentation, and supplied inventory leads.
- Preserve which source produced each candidate.
- Deduplicate before any active request.
- Do not equate discoverability with scope or ownership.

### 3. Resolution and infrastructure map

- Resolve only allowed candidates.
- Correlate hostnames, IPs, certificates, ports, protocols, redirects, CDN/WAF edges, cloud providers, and apparent technologies.
- Separate shared infrastructure from target-controlled infrastructure.
- Use low concurrency until baselines and rate limits are understood.

### 4. Endpoint and application map

- Merge crawler results, JavaScript references, source routes, API schemas, mobile/desktop clients, archive URLs, proxy history, GraphQL, WebSocket, gRPC, SSE, webhooks, and documentation.
- Normalize method, path, parameter, content type, authentication state, role, tenant, object type, and response signature.
- Identify endpoints found by multiple independent sources and endpoints reachable through only one channel.

### 5. Focused enumeration and fuzzing

- Start from an observed gap, not a generic payload spray.
- Change one request dimension at a time: path, method, parameter name, serialization, encoding, role, object, order, timing, or transport.
- Establish wildcard/soft-404, auth redirect, rate-limit, cache, and error baselines before filtering output.
- Bound wordlists, recursion, time, concurrency, and request rate.
- Save structured results and the exact command/configuration; do not rely on terminal scrollback.

### 6. Source, dependency, and runtime correlation

- Map runtime endpoints to source entry points and the deployed revision.
- Trace controlled input through parsers, canonicalizers, serializers, policy checks, queues, templates, interpreters, process launchers, database APIs, URL fetchers, and other sinks.
- Search sibling callers by the missing invariant rather than the original string.
- Confirm scanner paths manually and build a focused local regression or differential harness.

## Output correlation

Do not read each tool's output in isolation. Normalize records and join on:

- scope status;
- hostname, IP, port, protocol, certificate, and cloud resource;
- URL, route template, method, parameter, content type, and response signature;
- technology, package, version, repository revision, and source symbol;
- account, role, tenant, object owner, workflow state, and session freshness;
- run ID, changed variable, tool version, timestamp, and artifact hash.

Prioritize intersections such as:

- an archived endpoint still reachable on a current host;
- a client-only route that maps to an unguarded source handler;
- a version fingerprint that matches a reachable dependency path;
- a public resolver that reaches a powerful sink under an anonymous or shared service identity;
- a role/tenant differential that appears across REST but not GraphQL or WebSocket;
- an infrastructure identity whose privileges exceed the externally reachable service's intended job;
- a static Web3 warning that also breaks a protocol invariant under a concrete call sequence.

Preserve both confirming and contradictory outputs. Contradictions often identify proxy splits, deployments, feature flags, caching, or incorrect assumptions.

## Adaptive technology onboarding

Before testing an unfamiliar technology, create a compact onboarding record:

1. Exact product, framework, protocol, language, package, version, deployment mode, and enabled features.
2. Official architecture and security model: identities, trust boundaries, lifecycle, extension points, parsers, storage, and failure behavior.
3. Default versus deployed configuration and environmental differences.
4. Current release history, security advisories, patches, migration notes, and relevant tests.
5. Typical sources, policy checks, security-sensitive sinks, and debugging or administrative surfaces.
6. Ecosystem-specific tooling available locally and the artifacts each tool can produce.
7. Known false-positive traps and a safe local validation strategy.

Pause hypothesis execution long enough to complete this record when the technology is materially unfamiliar. Then update the target model, tool stages, and hypotheses. Never bluff framework semantics from a name alone.

## Prior-art method mining

When the user names a vulnerability class, research how that class has appeared in comparable products before direct testing.

Search in this order:

1. Bundled techniques, CVE/GHSA datasets, and redacted methodological cases.
2. Target/vendor advisories, source history, patches, tests, issues, release notes, and public disclosures.
3. Framework, runtime, dependency, and protocol advisories and documentation.
4. High-quality technical write-ups as leads, traced back to primary artifacts where possible.

Extract a method card, not a payload list:

- attacker-controlled source and required reachability;
- transforms, validation, canonicalization, and policy decisions;
- security-sensitive sink or violated business invariant;
- configuration and state prerequisites;
- discovery signal and why it was surprising;
- proof technique and minimum-safe marker;
- negative controls and common false positives;
- sibling/variant search rule;
- fix invariant and known incomplete fixes.

Use the method card to generate target-specific hypotheses. Similar technology or CWE is not proof that the target is vulnerable.

## Large-scope controls

- Choose `large-scope` only when the supplied scope and rate limits support it.
- Apply the allowlist at every stage, including redirects, resolved IPs, virtual hosts, archives, and scanner-generated URLs.
- Use checkpoints and deterministic filenames so a run can resume without repeating traffic.
- Deduplicate before network interaction and before expensive analysis.
- Start with passive and low-impact coverage, then narrow active work to high-value intersections.
- Record concurrency, rate, timeout, retries, recursion depth, and total requests.
- Stop a stage on unexpected load, blocking, scope drift, authentication leakage, or third-party data.

## Decision rules

- Missing tool: record the capability gap; use an equivalent or a small reviewed script.
- Noisy output: improve baselines and normalization before increasing volume.
- Conflicting tools: preserve both, identify different assumptions, and run a discriminating control.
- Scanner match: create `H1`; never promote it directly to a finding.
- Unfamiliar technology: complete onboarding before further testing.
- New signal: correlate it with the target model and prior-art method cards before selecting the next tool.
- Candidate proof: stop discovery ownership at the handoff and route the blind packet to independent X1 validation.
