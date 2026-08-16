---
tags: [security, flash, advisories, api, method, api9, inventory, ai-endpoint]
updated: 2026-08-16
sources:
  - "https://github.com/advisories/GHSA-x8cv-xmq7-p8xp, accessed 2026-08-16"
  - "https://github.com/advisories/GHSA-x227-pf99-vffg, accessed 2026-08-16"
  - "https://github.com/advisories?query=debug+endpoint, accessed 2026-08-16"
---

# MTH-API-012, count what is listening, not what you wrote

Related: APIDS-0027,
APIDS-0028,
APIDS-0030,
MTH-API-008.

**The `API9` method.** That row was at zero for four runs. The reason is in the class name:
improper inventory management is a bug about a list, and you cannot review a list you do not have.

## The technique in one line

Build the route list from what the process actually exposes, not from what the application declared,
because the routes that get skipped in review are the ones nobody wrote.

## The discovery signal

**A library call whose name is a verb about running, not about serving.** `launch()`, `serve()`,
`start()`, `run()`, `deploy()`, `--transport http`, `debug=True`. Each of these can stand up a
listener, register routes, and bind an interface, and none of them reads like route definition, so
none of them gets a permission review.

APIDS-0027 is the pure case: `AgentTeam.launch()`
starts a FastAPI server and registers three routes, one of which lists every agent and two of which
invoke them. The developer wrote no route, so there was no route to put a check on, and the
framework did not put one there either.

Three sharper tells:

* **The framework's own default bind address.** `0.0.0.0` in a helper described as a developer
  convenience. APIDS-0028 had it in two functions.
* **A second route to something a setting was supposed to close.**
  APIDS-0030 is this: introspection was switched off
  and a spec resolver served the same schema. The operator's inventory said one exposure. There were
  two.
* **The vendor's own incomplete fix.** APIDS-0027's advisory notes that sibling server surfaces in
  the same product had already been hardened with tokens or loopback binding, and this one had not.
  Somebody enumerated the surfaces they knew about. A surface missing from that enumeration is
  exactly what this class is.

## The mechanism

Review works on declarations. A reviewer opens the routes file, reads each entry, and asks what
guards it. That process is sound and it is complete with respect to the file.

The process is running more than the file. A framework attaches a metrics endpoint. A profiler
attaches `/debug/pprof`. A dev tool attaches a dashboard. A convenience helper attaches an entire
HTTP API. A documentation feature attaches a spec route that reconstructs the schema. An old version
of the service is still deployed at a path nobody removed.

Each of those is a real route with real reach and no line in the file. So the gap is not a missing
check. **It is a missing entry in the list of things that need checking**, and that is a strictly
harder problem, because a check can be added by review and a list cannot be completed by it.

## Which OWASP API class

`API9` improper inventory management, primarily, with `API8` and `API5` following. It is worth
holding the distinction: `API5` is the admin route that forgot its check, `API9` is the route that
was never on anybody's list. Same missing check, different reason it was missed, different fix.

## Which protocols

All of them, and the non HTTP ones are the ones most often missed: a gRPC reflection service, a
WebSocket upgrade path, an MCP SSE transport, a metrics scrape port, a debugger port, a Redis or
database port bound wider than intended.

## Does it reach Ahmed's surface, and how

**Yes, and it is the question the fleet has never been asked.** The repo's API surface table lists
what the fleet declares. It does not list what the fleet runs.

Three concrete reads, in order of cheapness:

1. **The WordPress `/wp-json/` root document lists every registered route on the site.** That is the
   inventory, published by the product, free to read on a site Ahmed owns. EduAi has 13 active
   plugins and the table already says the plugin routes are present and unreviewed. **Under the scope
   rule an entry about a WordPress REST defect belongs to the WordPress sweep. Reading the fleet's
   own route inventory is not writing an entry, and this lane tracks the surface.**
2. **Tutor LMS.** Named in the repo as entirely unreviewed by anyone. Its route list is in the
   `/wp-json/` document from step 1, which makes step 2 nearly free once step 1 is done.
3. **Developer machines.** Any MCP server, agent dashboard, notebook, or framework dev server on a
   laptop is on the office LAN. `netstat` on a machine Ahmed owns is the whole method here, and it
   needs no authorisation gate because it is his own machine.

## A safe way to test for it

**Static and local only, which is what makes this card usable at all.**

* Read the framework source for what the helper registers and what it binds. That produced
  APIDS-0027 and APIDS-0028 with no traffic.
* On a machine you own, list listening sockets and map each to a process. Anything you cannot name
  the owner of is the finding.
* Read the product's own published inventory where it has one: `/wp-json/`, `/openapi.json`,
  `/swagger.json`, `/.well-known/`, a GraphQL schema or SDL route, a service registry.
* Read the deployment manifests: which ports are published, which services are exposed, which
  ingress rules exist that nobody remembers writing.

**Never scan a host you do not own.** Enumeration is exactly the activity behind the lane's
authorisation gate, and reading a published document is not enumeration.

## The control that catches a false positive

**Separate the code default from the deployment, always, and report both.** A framework that binds
`0.0.0.0` by default may be running in a container with no published port, which makes the defect
real and the exposure nil. The reverse also happens: a safe default overridden in a compose file.

Two facts, stated separately: what the code does, and what this deployment does. Merging them
produces either a scare or a miss, and both cost credibility.

Second control: confirm the route is genuinely undeclared rather than declared somewhere you did not
look. Check the docs, the OpenAPI spec, and the routes file before calling something undocumented.

## Where else this shape appears

`/debug/pprof` on any Go service, and this run's listing showed it twice: NVIDIA DCGM Exporter
(CVE-2026-47483) and Tilt's HUD server (CVE-2026-55882). Framework dashboards: Nuxt DevTools
(already this folder's APIDS-0007), the `nx graph` dev
server (CVE-2026-54753), atomic-agents-stack's dashboard, Token Optimizer MCP's dashboard. Actuator
endpoints in Spring, Django's debug toolbar, Rails `/rails/info`, Laravel Telescope and Horizon,
phpMyAdmin left in a webroot, an old API version still routed, and a staging host still resolving.

The unifying line: **somebody else decided this would be running, and the decision was made at
import time.**

## Provenance

* GHSA-x8cv-xmq7-p8xp, PraisonAI `AgentTeam.launch()`, accessed 2026-08-16.
* GHSA-x227-pf99-vffg, PraisonAI MCP SSE transport, accessed 2026-08-16.
* GHSA-wxwm-3fxv-mrvx, Directus GraphQL SDL disclosure, accessed 2026-08-16.
* The GitHub advisory listing for `debug endpoint`, accessed 2026-08-16, which supplied the NVIDIA
  DCGM, Tilt, GPUStack and atomic-agents-stack sightings. Those were read as listing rows only, not
  opened.
</content>
