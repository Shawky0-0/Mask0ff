---
tags: [security, flash, advisories, webds, mariadb, database, command-execution, galera, stack]
updated: 2026-08-13
sources:
  - "https://bugzilla.redhat.com/show_bug.cgi?id=2488458, accessed 2026-08-13"
---

# WEBDS-0025, a MariaDB setting that is really a command line

**The first database layer entry in this reference, and MariaDB is one of the few
components on Ahmed's stack that is verified rather than merely stated.** Related:
the web advisories folder,
the ledger's stack table.

```yaml
id: WEBDS-0025
component:
  type: database
  ecosystem: os
  name: MariaDB server
  version_scope: "Galera cluster state snapshot transfer, the joiner node"
affected:
  introduced: "10.6.1, 10.11.1, 11.4.1, 11.8.1 and 12.3.1, per branch"
  fixed_in: "10.6.27, 10.11.18, 11.4.12, 11.8.8 and 12.3.2"
  tested_on: ___
identifiers:
  cve: CVE-2026-48165
  ghsa: ___
  osv: ___
  snyk: ___
  vendor_id: "Red Hat bug 2488458"
class:
  owasp_2025: injection
  owasp_api: not applicable
  owasp_llm: not applicable
  cwe: "___, not stated on the record read"
  family: configuration value used as a command
  corpus_directory: 06-server-side-injection-file-data/
auth_required: privileged
entry_point: >
  The global system variables wsrep_sst_receive_address and wsrep_sst_donor, set
  over a normal database connection by a user holding the privilege to change
  global variables. The command runs on Galera joiner nodes during a state
  snapshot transfer.
root_cause: >
  Those variables are passed into the shell script that performs the state
  snapshot transfer, and they were not treated as untrusted text on that
  journey. A value carrying shell metacharacters therefore stops being an
  address and becomes a command, running as the mariadbd process user. The
  missing decision is: nobody decided that a global variable set at runtime by a
  database user is untrusted input on its way into a shell.
signal: >
  A database account with SUPER or the equivalent global variable privilege, on
  a cluster. The signal is architectural rather than observable from outside: if
  the application connects as a highly privileged user and any application bug
  lets an attacker run arbitrary SQL, then this variable turns that into
  operating system code execution on a cluster node.
safe_proof: >
  Not proven here and it should not be proven on anything shared. In a lab
  cluster you own, set the variable to a value whose payload writes a marker file
  into a temporary directory, then trigger a state snapshot transfer and check for
  the marker. Marker only. No reverse shell, no outbound connection, no
  persistence. Two nodes minimum, both disposable, both on an isolated network.
controls: >
  Negative control: set the variable to an ordinary address and confirm the state
  snapshot transfer completes normally, so you know the transfer path is
  exercised at all. Differential control: run the same test on a patched version
  and confirm the marker does not appear. Precondition control: confirm the node
  is genuinely a Galera joiner performing a transfer, because on a single node
  install with no cluster there is nothing to trigger and a negative result would
  mean nothing.
fix:
  commit_url: "___, not located this run"
  invariant: >
    ___. The Red Hat record names the affected and fixed versions but does not
    state what the fix enforces. The repair for this shape is normally to
    validate the value against an address grammar, or to stop passing it through
    a shell at all.
hardening: >
  The application's database user should not hold the privilege to set global
  variables. That single control removes the whole path regardless of this or any
  future variable, and it is the one worth checking on the YZH fleet because it
  is checkable from the application side without touching the database
  configuration. Then run mariadbd as an unprivileged user with no shell, so
  even successful execution lands somewhere useless.
detection: >
  Audit log entries for SET GLOBAL on any wsrep_ variable from an application
  account. On the host, a process spawned by mariadbd that is not the expected
  transfer script. Both need auditing to be on, which on most installs it is not.
variant_rule: >
  Any configuration value that is consumed by a shell script or an external
  program rather than by the server itself. In MariaDB and MySQL the family
  includes the state snapshot transfer variables, wsrep_notify_cmd, and anything
  naming an external helper. In PostgreSQL, archive_command and the equivalent
  restore command. In Redis, the config set plus save trick that writes files.
  Outside databases the same shape is everywhere a settings screen accepts a path
  or a command: backup destinations, webhook shell hooks, image conversion
  binaries in a CMS, and log rotation targets. The question is always whether a
  setting is data to the program or an argument to a shell.
lab:
  install: "two MariaDB 11.4 containers below 11.4.12 configured as a Galera cluster, isolated bridge network"
  snapshot: "container snapshots before any variable is set"
  teardown: "drop both containers and the network. Never run this against any shared or company database"
provenance:
  source: "Red Hat Bugzilla 2488458 for CVE-2026-48165"
  accessed: 2026-08-13
  license_note: "public bug tracker record, no licence restriction on reading"
```

## Why this one is here despite needing high privilege

Every other entry in this folder is an application bug. This one needs a database
account that can already change global settings, which is a lot of privilege, and
it needs a Galera cluster, which many deployments do not run. On its own that
makes it a low priority item.

It is written up for two reasons.

MariaDB is one of the few things on Ahmed's stack table marked **verified
locally** rather than stated. Most of that table is repo claims. When something
lands against a verified component it gets written down properly, whatever the
preconditions.

And it teaches a shape that the application side of the fleet will meet again:
**a setting that is not really a setting, because something downstream hands it
to a shell.**

## What happens

MariaDB clusters copy a whole database from one node to another when a new node
joins. That copy is done by a helper script, not by the server itself, and the
script is told where to send things by a couple of settings.

Those settings can be changed at runtime by a sufficiently privileged database
user. Put shell syntax in one and the helper script runs it. The code runs as
whatever user the database process runs as.

## Why it works

The value crosses a boundary that nobody marked.

Inside the server it is a string in a variable, which is harmless. Then it is
handed to a shell script as an argument, and inside a shell, characters like
`;` and `$(` are not text, they are punctuation that starts a new command.

Nothing validated it on the way across, because from the server's point of view
it was only ever a setting.

## What it means for testing an application

The realistic route to this is a chain, not a direct attack. It matters when the
application connects to the database as a very privileged user, which is
extremely common and is almost never questioned, and when some application bug
gives an attacker the ability to run arbitrary SQL.

Ordinarily SQL injection gets you the data. On a cluster where the application
user can set global variables, it can get you the host.

The practical, checkable question for the YZH fleet, and it is an application side
question rather than a database one:

**What privileges does the application's database user actually hold, and does it
need them.**

That check needs no exploit and no cluster. It is a `SHOW GRANTS` on a system
Ahmed is authorised to look at, and it improves the answer to a whole family of
findings, not just this one.

## What is unknown here

The CWE, the CVSS score, the fix commit and the invariant the patch enforces are
all `___`. The record read was the Red Hat tracker entry, which carries the
version ranges and the description and not those fields. No upstream MariaDB
advisory page was reached this run: two MariaDB security URLs were opened and
neither carries a CVE list.

There is a second, unresolved MariaDB question in today's run file: an X account
published what it describes as an unpatched MariaDB 13 remote code execution
proof of concept on 2026-08-07. That is a separate claim from this CVE, it is
uncorroborated by any vendor page reached this run, and it is recorded as debt
rather than as fact.
