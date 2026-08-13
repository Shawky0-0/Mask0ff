---
tags: [security, flash, advisories, webds, recon, nuxt, information-disclosure, dev-server]
updated: 2026-08-13
sources:
  - "https://github.com/advisories/GHSA-7c4v-fwgw-9rf7, accessed 2026-08-13"
---

# WEBDS-0018, the Nuxt dev server hands out the project path to anyone on the LAN

**The first entry in the recon and cloud infrastructure class.** That class sat at
zero for three runs. Related: the web advisories
folder,
WEBDS-0007, the other "we trusted a header" bug,
MTH-WEB-007, did the patch fix the bug or the class.

```yaml
id: WEBDS-0018
component:
  type: framework
  ecosystem: npm
  name: nuxt
  version_scope: the development server only, production builds are not affected
affected:
  introduced: "4.4.7 and 3.21.7, the versions that shipped the previous incomplete fix GHSA-rq7w-g337-39qq"
  fixed_in: "4.5.1 and 3.21.10"
  tested_on: ___
identifiers:
  cve: "none assigned"
  ghsa: GHSA-7c4v-fwgw-9rf7
  osv: ___
  snyk: ___
  vendor_id: "supersedes GHSA-rq7w-g337-39qq, the first attempt at the same bug"
class:
  owasp_2025: security misconfiguration
  owasp_api: ___
  owasp_llm: not applicable
  cwe: "CWE-200, exposure of sensitive information to an unauthorised actor"
  family: development surface exposed on a network interface
  corpus_directory: 01-recon-cloud-infrastructure/
auth_required: none
entry_point: >
  GET /.well-known/appspecific/com.chrome.devtools.json on the Nuxt dev server,
  port 3000 by default. Reachable from any address the dev server is bound to.
  Requires experimental.chromeDevtoolsProjectSettings, which is on by default.
root_cause: >
  The endpoint was meant to answer only the local browser, and the first fix
  decided that by reading request headers. Headers are written by the client.
  The missing decision is: nobody decided where the request physically came
  from. The check lived in the header parsing layer, where the attacker has a
  vote, instead of in the socket layer, where they do not. The advisory's own
  example is curl -H 'Host: localhost' sent from a LAN address.
signal: >
  A development server answering on anything other than 127.0.0.1. Then the
  endpoint itself: a 200 with JSON on
  /.well-known/appspecific/com.chrome.devtools.json. The reply names the
  absolute project root on the developer's disk, for example
  C:\work\clientname-portal, plus a persistent workspace UUID.
safe_proof: >
  On a Nuxt app you own, started with --host so it binds the LAN, request the
  endpoint from a second machine on the same lab network. The canary is the
  project root string in the JSON reply, which you already know because it is
  your own directory. Reading one JSON document is the whole proof. Nothing is
  written and no file is fetched.
controls: >
  Negative control: request the same endpoint from the loopback address and
  confirm it also answers, so you know the endpoint exists rather than guessing.
  Then, after upgrading past the fix, repeat the LAN request and confirm it is
  refused while loopback still works. Differential control: send the request
  with and without the Host: localhost header. On the vulnerable build both
  succeed, which is what proves the header was never the gate. If only the
  spoofed one works you are looking at the older bug, not this one.
fix:
  commit_url: "nuxt/nuxt@00f71bb for 4.5.1 and nuxt/nuxt@e30c611 for 3.21.10"
  invariant: >
    The peer address of the TCP socket must be a loopback address, localhost,
    127.0.0.1 or ::1. The check no longer reads any header, so no header can
    change the answer. Stated plainly: identity comes from the connection, not
    from the request.
hardening: >
  Bind development servers to 127.0.0.1 and reach them over an SSH tunnel when
  you need them from elsewhere. That kills every bug in this family at once,
  including the ones not found yet, because there is no listener for a stranger
  to talk to.
detection: >
  Access logs showing a request for a /.well-known/appspecific/ path with a
  source address outside loopback. A WAF will not see this because a dev server
  is not usually behind one, which is the actual point.
variant_rule: >
  Every development and introspection surface that assumes it is only ever
  reached from the same machine. Vite's dev server and its /@fs/ path, webpack
  dev server, the Laravel and Symfony debug toolbars, Spring Boot actuator
  endpoints, /debug/pprof on Go services, Node inspector on 9229, and any
  .well-known path added by a tool rather than by the application. Same question
  every time: is the guard reading the socket or reading a header.
lab:
  install: "npx nuxi init in a throwaway directory, pin nuxt to 4.4.7, run with --host"
  snapshot: "not needed, nothing is written"
  teardown: "delete the directory, no third party involved at any point"
provenance:
  source: "GitHub Security Advisory GHSA-7c4v-fwgw-9rf7"
  accessed: 2026-08-13
  license_note: "public advisory, no licence restriction on reading"
```

## What happens

Nuxt's development server answers a special URL that Chrome DevTools asks for.
The reply says where the project lives on disk and gives a long random workspace
identifier.

That URL was supposed to answer only the browser sitting on the same machine.
Instead it answers anyone who can reach the port. If the developer started the
server so that colleagues can see the site, everyone on that network can read
the path.

## Why it works

This bug has been fixed twice, and the first attempt is the interesting part.

The first fix looked at the request headers to work out whether the caller was
the local browser. But headers are just text the caller types. Anyone can send
`Host: localhost` from anywhere. So the first fix asked the attacker whether the
attacker was allowed in.

The second fix asks a different question, and it is not a question the caller
can answer. It looks at the actual network connection and reads which address
the packets came from. You cannot type a source address into a request the way
you type a header, because the reply has to travel back to you.

That is the general rule, and it is worth keeping:

**A header is a claim. A socket address is a fact.**

## What the leak is actually worth

Two things, and neither one is a break in.

The absolute project path is reconnaissance. It usually carries the operating
system, the username, and very often the client's name, because directories get
named after clients. On a shared office network that is a free map.

The workspace UUID is worse in principle, because it is the token DevTools uses
when it writes files back into a project. The advisory is clear that this
version leaks the identifier only, with no file access and no code execution.
Record that as read, not as reasoned.

## How you would reproduce it

Make your own Nuxt project on the vulnerable version, start it with `--host`,
then from a second machine on your lab network request
`/.well-known/appspecific/com.chrome.devtools.json`. If your own directory name
comes back, you have it. Upgrade, repeat, and it should be refused while the
same request from the machine itself still works.

## What the fix is, and why the obvious fix would not work

The fix checks the socket's peer address against the loopback addresses.

The obvious fix, and the one that was actually shipped first, is to check
headers. It fails for the reason above. A second obvious fix is to keep checking
headers but check more of them, `Origin`, `Sec-Fetch-Site`, a user agent. That
fails the same way, only slower: adding more attacker written fields to a
decision does not make the decision less attacker written.

A third tempting fix is to turn the feature off by default. That helps, but it
leaves the endpoint wrong for everyone who turns it on, so it moves the problem
rather than solving it.
