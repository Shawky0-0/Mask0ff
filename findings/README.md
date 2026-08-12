# findings

Vulnerability entries and discovery method cards produced by four daily security
intelligence sweeps. Built to be readable on their own and to replay straight into a
mask0ff evidence bundle, since the entry schema mirrors the finding record.

## Categories

| Folder | Scope |
|--------|-------|
| `wordpress/` | WordPress core, plugins and themes |
| `web-application/` | frameworks, languages, servers, databases, package ecosystems, protocol and cache, client side, AI and LLM surfaces |
| `api/` | the OWASP API Security Top 10 classes, plus GraphQL, WebSocket, webhooks and AI endpoint authorisation |
| `web3/` | weighted to the web2 and web3 seam: dApp frontends, RPC, indexers, metadata, signing flows. Contract logic second |

## What an entry contains

A YAML block in a fixed schema, then prose. Two schema fields carry most of the value and
are usually missing from a CVE record:

* **`root_cause`**, the missing decision named where it actually lives, not a CWE label.
* **`controls`**, the negative and differential tests that stop a reflection being reported
  as an execution.

Method cards (`MTH-*`) hold a discovery technique rather than a bug. The field that matters
there is the **discovery signal**: what made the researcher look in that place to begin
with. Most writeups bury it. A payload teaches one bug; a method card teaches a class.

## Provenance and verification status

Every entry carries a `provenance` block with the source URL and the access date. **Read
it.** These are desk research entries built from published advisories and writeups. Unless
an entry says otherwise:

* nothing here was reproduced in a lab,
* no fix commit diff was read, so `fix.commit` is often `___`,
* `___` means unknown and never guessed.

**An entry is a hypothesis with a citation, not a verified finding.** Treat it as the
starting point for a bundle, not as a conclusion.

## What is deliberately not in here

The sweeps also produce ledgers, watchlists and daily run files. Those stay out, and the
`.gitignore` beside this file enforces it.

The reason is worth stating: those files carry **operational context about a specific
organisation's estate**, including which components are deployed, which are only assumed,
and which surfaces nobody has reviewed yet. That is a map of where one company is weak. It
has no value to a reader of this repository and real cost if it travels.

Entries here are written from public sources and carry no such context.

## Contributing back

If you reproduce one of these and the root cause or the affected range is wrong, that is
worth more than a new entry. Say so.
