# Black-, gray-, white-, and hybrid-box testing

Select the assessment mode from the evidence actually available. Change modes when the user adds code, schemas, credentials, or runtime access; do not restart the investigation.

## Black-box

Use observable requests, responses, clients, roles, objects, workflows, and protocol behavior. Build unauthenticated and authenticated baselines, then test one falsifiable boundary hypothesis at a time. Root cause and affected range may be `not_applicable` only with a written reason.

## Gray-box

Use supplied documentation, schemas, traffic, logs, test credentials, configuration excerpts, or limited source. Correlate declared contracts with observed behavior, and use controlled role/tenant/object differentials.

## White-box

Record repository and dependency revisions, build/test commands, deployment mapping, identities, entry points, policy checks, data flows, sinks, queues, integrations, and error paths. Search sibling call sites using the root-cause invariant. Prefer a focused failing test or local harness before production validation, then prove only the minimum production boundary needed.

## Hybrid

Combine source analysis with live behavior. Use runtime evidence to prioritize source paths and source invariants to generate targeted live controls. Preserve the mapping between source revision and deployed version.

Generate a plan dynamically:

```powershell
.\scripts\mask0ff.cmd plan E:\research\program-profile.json `
  --session E:\research\member-session.json --session E:\research\admin-session.json `
  --target app.example.com --surface web --surface api --focus "authentication bypass" `
  --signal "unexpected cross-tenant object response" --scale multi-asset
```

The plan inventories the current tool environment and returns a staged correlation workflow. It is a routing artifact, not proof. Update it when roles, code, configuration, tools, scale, or signals change. Every finding still requires baseline, proof, controls, clean repeats, independent X1 validation, bounded impact, duplicate review, and assessment. Read [research-operations.md](research-operations.md) before large-scope or tool-heavy work.
