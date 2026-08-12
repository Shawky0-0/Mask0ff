#!/usr/bin/env python3
"""Create, use and destroy one Docker container per assessment job.

The container is the containment argument. Work happens inside it, not on the
host. One container is created for a job, every step of that job shares it so
cookies, wordlists and downloaded files survive across steps, and it is removed
when the job ends. The shape comes from MAPTA section 2.5.

What the container does contain, and what it does not
------------------------------------------------------
It contains the host filesystem. No path from this machine is handed in, because
create passes no -v and no --mount, so a command inside cannot read or write the
files on this disk. The manifest records that as host_bind_mounts, read back from
a live docker inspect rather than assumed. It also records "mounts", the whole
mount table, because an image can declare a volume of its own and Docker will
attach an anonymous one without being asked. That volume is Docker managed
storage, not a path from here, and destroy removes it with --volumes.

It does not, by itself, contain the network. Attaching to a network says which
containers can be reached by name. It does not say that nothing else can be
reached. A normal Docker bridge network has Internal false and hands the
container a default route to the Docker host, so traffic can be routed and NAT'd
outward. "create" therefore reads the route table, the hosts file and the
network flags, and writes them into the manifest under "egress". That reading is
marked as configured, never as observed, because reading a route table is not the
same as sending a packet. A job that must not reach anything outside its named
containers needs a network created with --internal, and the manifest will then
say so.

Passing a command in
---------------------
There are three ways to say what should run inside the container, and only one
of them is safe on Windows:

  --argv-b64 <base64>   base64 of a UTF-8 JSON array of strings. SAFE. Base64
                        uses only letters, digits, plus, slash and equals, so
                        cmd.exe has nothing to react to and the command arrives
                        byte for byte.
  --argv-file <path>    a file holding the same JSON array. SAFE for the same
                        reason: the text never travels on a command line.
  -- <command and args> the plain way. Fine on Linux and macOS. On Windows it
                        travels through cmd.exe, which rewrites ampersands,
                        pipes and carets. The router refuses those before this
                        script is reached, so a rewritten command is never run,
                        but a command that needs them has to use base64.

One residual on Windows, stated plainly because it cannot be fixed here. If a
wrapper argument contains a pipe, cmd.exe has already started the other side of
that pipe in its own process by the time anything of ours runs. Nothing in the
container will run, and the refusal is printed on stderr, but the text after the
pipe still executes on the Windows host and the exit code the caller sees belongs
to the pipeline, not to us. No .cmd file can prevent that. An automated caller
should invoke scripts/mask0ff.py with Python directly, or use --argv-file.

The budget
----------
"create" opens the job's usage ledger, so the clock runs from the moment the
container exists. "exec" takes one call out of that budget BEFORE it starts
anything, and refuses with exit 3 if a cap is breached.

Reserve first, run second. That order is the fix for two separate holes found by
a red agent. Checking the budget, then running a docker exec for hundreds of
milliseconds, then recording the call, let three parallel execs all pass the same
check and all run on one call of remaining budget. The same gap meant a job killed
during a call never counted that call, while the command carried on inside the
container. The call is now written to the ledger, under a lock, before docker is
touched, and what it cost is attached afterwards.

Which ledger a job uses is decided by the container, not by anything an operator
can edit. At create, a random bind token, the ledger path and the job directory
are stamped into Docker labels, which cannot be changed on an existing container.
"exec" reads them back from a live docker inspect and refuses when the job
directory it was pointed at, the job id in manifest.json, or the bind token in the
ledger disagrees with them. Copying manifest.json into a second directory, editing
the job id inside it, or deleting the ledger all used to hand the same container a
fresh budget. Each of those is now a refusal.

Past a breach the only way on is "usage raise", which writes the raise to the
ledger.

Exit codes:
  0    the operation succeeded
  N    for "exec" only, the exit code the command returned inside the container
  3    for "exec" only, a usage cap is breached and nothing was run
  4    the usage ledger failed its integrity check, so nothing was run
  124  for "exec" only, the command was still running at the timeout
  125  this script itself failed, for example a missing network or a name clash

An exec exit code and a script failure can both be 125, so read the "status"
field in the JSON rather than the exit code alone when you need certainty.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import usage_tracker


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_JOBS_DIR = ROOT.parent / "jobs"
DEFAULT_IMAGE = "wordpress:cli-php8.3"
CONTAINER_WORKDIR = "/job"
NAME_PREFIX = "mask0ff-job-"
JOB_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,48}$")
STEP_FILE_PATTERN = re.compile(r"^(\d{4})\.json$")
TOKEN_PATTERN = re.compile(r"^[0-9a-f]{32}$")
DOCKER = os.environ.get("MASK0FF_DOCKER", "docker")
DOCKER_TIMEOUT = 120
KILL_TIMEOUT = 30
SCRIPT_FAILURE_CODE = 125
TIMEOUT_EXIT_CODE = 124
USAGE_BREACH_EXIT_CODE = 3
USAGE_TAMPER_EXIT_CODE = 4
# Written at create, read back at every exec. Docker has no command that changes a
# label on an existing container, so these are the one part of a job's identity the
# operator cannot edit afterwards.
LABEL_BIND = "mask0ff.usage.bind"
LABEL_LEDGER = "mask0ff.usage.ledger"
LABEL_JOBDIR = "mask0ff.usage.jobdir"
LABEL_JOB = "mask0ff.job"
SCHEMA_VERSION = 1
KEEPALIVE = "while true; do sleep 3600; done"
STEP_TOKEN_VARIABLE = "MASK0FF_STEP_TOKEN"


class SandboxError(Exception):
    """A failure of this script, as opposed to a failure inside the container."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def save_json(path: Path, data: dict[str, Any]) -> None:
    # The temporary name carries this process id. Two copies of this script writing
    # the same manifest used to collide on one shared .tmp name, and on Windows the
    # loser died with WinError 32 after its command had already run inside the
    # container, so its exit code told the caller nothing had happened.
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def run_docker(arguments: list[str], *, timeout: int = DOCKER_TIMEOUT) -> subprocess.CompletedProcess[bytes]:
    """Call the docker client once. Never uses a shell."""
    try:
        return subprocess.run([DOCKER, *arguments], capture_output=True, timeout=timeout)
    except FileNotFoundError as error:
        raise SandboxError(f"docker client not found on PATH as {DOCKER!r}") from error
    except subprocess.TimeoutExpired as error:
        raise SandboxError(f"docker call timed out after {timeout} seconds: docker {' '.join(arguments)}") from error


def text(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace").strip()


def container_name_for(job_id: str) -> str:
    if not JOB_ID_PATTERN.match(job_id):
        raise SandboxError(
            f"job id is not usable: {job_id!r}. Allowed: letters, digits, dot, underscore and dash, "
            "starting with a letter or digit, at most 49 characters."
        )
    return f"{NAME_PREFIX}{job_id}"


def guard_owned(name: str) -> str:
    """Refuse to touch any container this script did not create.

    Ahmed's own containers are live on this machine. This check is the reason a
    typo cannot reach them.
    """
    if not name.startswith(NAME_PREFIX) or len(name) <= len(NAME_PREFIX):
        raise SandboxError(f"refusing to touch a container outside our namespace: {name!r}")
    return name


def container_exists(name: str) -> bool:
    guard_owned(name)
    completed = run_docker(["ps", "--all", "--no-trunc", "--filter", f"name=^{re.escape(name)}$", "--format", "{{.Names}}"])
    if completed.returncode != 0:
        raise SandboxError(f"docker ps failed: {text(completed.stderr) or 'no stderr'}")
    return name in text(completed.stdout).splitlines()


def inspect_container(name: str) -> dict[str, Any] | None:
    guard_owned(name)
    completed = run_docker(["inspect", name])
    if completed.returncode != 0:
        return None
    parsed = json.loads(text(completed.stdout))
    return parsed[0] if parsed else None


def network_inspect(network: str) -> dict[str, Any]:
    completed = run_docker(["network", "inspect", network])
    if completed.returncode != 0:
        raise SandboxError(f"network does not exist or cannot be inspected: {network}")
    parsed = json.loads(text(completed.stdout))
    if not parsed:
        raise SandboxError(f"network inspect returned nothing for: {network}")
    return parsed[0]


def network_members(network: str) -> list[dict[str, Any]]:
    members = []
    for container_id, details in sorted(network_inspect(network).get("Containers", {}).items(), key=lambda item: item[1].get("Name", "")):
        members.append(
            {
                "name": details.get("Name", ""),
                "container_id": container_id[:12],
                "ipv4_address": details.get("IPv4Address", ""),
            }
        )
    return members


def require_network(network: str) -> list[dict[str, Any]]:
    """Fail loudly when the named network is absent.

    Falling back to an isolated container would make a later step report
    "target unreachable" when the truth is "it was attached to nothing".
    """
    completed = run_docker(["network", "ls", "--format", "{{.Name}}"])
    if completed.returncode != 0:
        raise SandboxError(f"docker network ls failed: {text(completed.stderr) or 'no stderr'}")
    available = text(completed.stdout).splitlines()
    if network not in available:
        raise SandboxError(
            f"network does not exist: {network}. Known networks: {', '.join(available) or 'none'}. "
            "Refusing to create an unattached container."
        )
    return network_members(network)


def job_directory(args: argparse.Namespace) -> Path:
    return (args.workdir / args.job).resolve()


def manifest_path(job_dir: Path) -> Path:
    return job_dir / "manifest.json"


def container_identity(details: dict[str, Any], job_dir: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    """Read the job's identity off the container itself, and refuse every disagreement.

    The budget used to hang on two things an operator can write: the job_id field
    inside manifest.json, and the --workdir on the command line. Copying the manifest
    into a second directory, or changing one word inside it, gave the same running
    container a second ledger with a fresh budget, while the original ledger sat there
    still reading "breached" so an auditor would conclude the job had stopped.

    These four labels are written once, at create, and Docker offers no way to change
    a label on an existing container. So they are the authority here and the files on
    disk are not. Any mismatch is refused rather than repaired, because the shape of
    every one of those tricks is a mismatch.
    """
    labels = (details.get("Config", {}) or {}).get("Labels") or {}
    bind = labels.get(LABEL_BIND)
    ledger = labels.get(LABEL_LEDGER)
    jobdir = labels.get(LABEL_JOBDIR)
    job_id = labels.get(LABEL_JOB)
    if not (bind and ledger and jobdir and job_id):
        raise SandboxError(
            f"container {details.get('Name', '')!r} carries no usage labels, so it cannot be tied "
            "to a ledger and its spending cannot be counted. It was created before this check "
            "existed, or by something other than 'sandbox create'. Destroy the job and create it "
            "again. Nothing was run."
        )
    if Path(jobdir).resolve() != job_dir.resolve():
        raise SandboxError(
            f"this container's job directory is {jobdir}, and this command was pointed at "
            f"{job_dir}. Refusing to run. A second directory for the same container would be a "
            "second budget, and the first ledger would go on saying the job had stopped."
        )
    if str(manifest.get("job_id", "")) != job_id:
        raise SandboxError(
            f"this container's job id is {job_id!r}, and the manifest in {job_dir} says "
            f"{manifest.get('job_id')!r}. The manifest was edited. Refusing to run, because a "
            "renamed job id opens a fresh ledger for a container that already has one."
        )
    ledger_file = Path(ledger)
    if not ledger_file.is_file():
        raise SandboxError(
            f"the usage ledger for this job is missing at {ledger_file}. It was deleted or moved. "
            "Refusing to run: a deleted ledger is not a fresh budget, and restarting the clock is "
            "the easiest way to defeat the seconds cap. Destroy this job and create a new one."
        )
    return {"bind": bind, "ledger": ledger_file, "job_id": job_id, "job_dir": Path(jobdir)}


def claim_step_number(steps_dir: Path, placeholder: dict[str, Any]) -> tuple[int, Path]:
    """Take the next step number and write the file that claims it, in one go.

    Choosing the number by scanning for the highest existing file and then writing it
    later is the same check then act pattern as the old budget gate. Three commands
    racing all picked step 2, and only one transcript survived. The caller holds the
    job lock around this, and the file is created with O_EXCL as well, so a number is
    claimed the moment it is chosen.
    """
    steps_dir.mkdir(parents=True, exist_ok=True)
    highest = 0
    for item in steps_dir.iterdir():
        match = STEP_FILE_PATTERN.match(item.name)
        if match:
            highest = max(highest, int(match.group(1)))
    while True:
        step_number = highest + 1
        step_path = steps_dir / f"{step_number:04d}.json"
        try:
            handle = os.open(step_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            highest = step_number
            continue
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump({**placeholder, "step": step_number}, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        return step_number, step_path


def load_manifest(job_dir: Path) -> dict[str, Any]:
    path = manifest_path(job_dir)
    if not path.is_file():
        raise SandboxError(f"no job manifest at {path}. Run 'sandbox create' first.")
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    guard_owned(str(manifest.get("container_name", "")))
    return manifest


def bind_mounts_of(details: dict[str, Any]) -> list[str]:
    return [
        str(mount.get("Source", ""))
        for mount in details.get("Mounts", [])
        if mount.get("Type") == "bind"
    ]


def mounts_of(details: dict[str, Any]) -> list[dict[str, Any]]:
    """Record every mount, not only the bind mounts.

    host_bind_mounts answers one question, "did a path from this machine get handed
    in", and it is the one that matters for the host. It is not the whole mount
    table. An image can declare a VOLUME of its own, and Docker then attaches an
    anonymous volume with no help from us, which a bind mount only list does not
    show. Recording all of them means the manifest cannot be read as saying the
    container has no writable storage when it does.
    """
    return [
        {
            "type": mount.get("Type"),
            "name": mount.get("Name"),
            "source": mount.get("Source"),
            "destination": mount.get("Destination"),
            "read_write": mount.get("RW"),
        }
        for mount in details.get("Mounts", [])
    ]


EGRESS_PROBE_SCRIPT = (
    "echo '#ROUTE'; cat /proc/net/route 2>/dev/null; "
    "echo '#HOSTS'; cat /etc/hosts 2>/dev/null; "
    "echo '#RESOLV'; cat /etc/resolv.conf 2>/dev/null"
)
EGRESS_PROBE_METHOD = (
    "Read only. docker network inspect on the host, plus /proc/net/route, /etc/hosts and "
    "/etc/resolv.conf read inside the container. No packet was sent to test any of it, and no "
    "name was resolved, so nothing here is an outbound request."
)
EGRESS_CAVEAT = (
    "Configured, not observed. These are the container's own route table, hosts file, resolver "
    "config and the network's flags. They say what the kernel would do with an outbound packet. "
    "They do not prove that a packet leaves, because none was sent from here. Settling it needs "
    "one outbound request from inside a sandbox, run by somebody holding authorisation for the "
    "target of it."
)
EGRESS_NOT_MEASURED = [
    "No outbound request was sent, to anything, so no reachability here is observed.",
    "No name was resolved. hosts_file_docker_internal is what /etc/hosts contains and nothing "
    "more. An empty list there does not mean host.docker.internal fails to resolve, because "
    "Docker can answer that name from its embedded resolver without any hosts file entry.",
    "Whether the gateway address actually forwards traffic, and where to, was not tested.",
]


def little_endian_hex_ip(value: str) -> str | None:
    """Turn a /proc/net/route address field into dotted quad.

    The kernel prints these as little endian hex, so 010012AC is 172.18.0.1 and not
    1.0.18.172. Getting the byte order wrong here would put a plausible but wrong
    gateway address into the record, which is worse than leaving it out.
    """
    try:
        raw = int(value, 16)
    except ValueError:
        return None
    octets = [(raw >> shift) & 0xFF for shift in (0, 8, 16, 24)]
    return ".".join(str(octet) for octet in octets)


def parse_proc_net_route(block: str) -> list[dict[str, Any]]:
    routes = []
    for line in block.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4:
            continue
        destination = little_endian_hex_ip(fields[1])
        gateway = little_endian_hex_ip(fields[2])
        if destination is None or gateway is None:
            continue
        routes.append(
            {
                "interface": fields[0],
                "destination": destination,
                "gateway": gateway,
                "is_default": destination == "0.0.0.0" and gateway != "0.0.0.0",
            }
        )
    return routes


PROBE_MARKERS = {"#ROUTE": "route", "#HOSTS": "hosts", "#RESOLV": "resolv"}


def split_probe_sections(output: str) -> dict[str, str]:
    """Split the probe output on the three exact markers, and nothing else.

    Only these three literals start a section. /etc/hosts and /etc/resolv.conf both
    contain their own comment lines starting with a hash, and treating one of those
    as a section header would silently drop the rest of a file from the record.
    """
    sections: dict[str, list[str]] = {}
    current = None
    for line in output.splitlines():
        marker = PROBE_MARKERS.get(line.strip())
        if marker is not None:
            current = marker
            sections[current] = []
        elif current is not None:
            sections[current].append(line)
    return {key: "\n".join(value) for key, value in sections.items()}


def probe_egress(name: str, network: str, network_details: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Record what this container's egress is configured to be, and say so honestly.

    The reason this exists: the manifest used to claim that the attached network was
    the complete statement of what the container could reach. That is false for any
    ordinary bridge network. Internal is false, there is a default route to the
    Docker host, and NAT applies, so the network names what can be reached by name
    and nothing more. A containment argument built on that sentence was resting on
    something untrue, so the sentence is gone and this measurement replaces it.
    """
    guard_owned(name)
    internal = bool(network_details.get("Internal"))
    gateways = [
        entry.get("Gateway", "")
        for entry in (network_details.get("IPAM", {}).get("Config") or [])
        if entry.get("Gateway")
    ]
    egress: dict[str, Any] = {
        "method": EGRESS_PROBE_METHOD,
        "caveat": EGRESS_CAVEAT,
        "not_measured": list(EGRESS_NOT_MEASURED),
        "network_internal": internal,
        "network_driver": network_details.get("Driver"),
        "network_gateways": gateways,
        "default_routes": [],
        "routes": [],
        "hosts_file_docker_internal": [],
        "nameservers": [],
        "resolver_forwards_to": [],
        "beyond_network": "unknown",
        "probe_error": None,
    }
    raw = ""
    try:
        completed = run_docker(["exec", name, "sh", "-c", EGRESS_PROBE_SCRIPT], timeout=KILL_TIMEOUT)
    except SandboxError as error:
        egress["probe_error"] = str(error)
        return egress, raw
    raw = text(completed.stdout)
    if completed.returncode != 0:
        egress["probe_error"] = text(completed.stderr) or f"egress probe exited {completed.returncode}"
        return egress, raw

    sections = split_probe_sections(raw)
    routes = parse_proc_net_route(sections.get("route", ""))
    egress["routes"] = routes
    egress["default_routes"] = [route for route in routes if route["is_default"]]
    egress["hosts_file_docker_internal"] = [
        line.strip()
        for line in sections.get("hosts", "").splitlines()
        if "docker.internal" in line
    ]
    egress["nameservers"] = [
        line.split()[1]
        for line in sections.get("resolv", "").splitlines()
        if line.startswith("nameserver") and len(line.split()) > 1
    ]
    # Docker writes the upstream resolvers it forwards to into a comment in
    # resolv.conf. It is a comment, so nothing reads it as config, but it is a
    # plain statement that name lookups leave this network, which is one more
    # reason the network is not a boundary.
    egress["resolver_forwards_to"] = [
        line.strip()
        for line in sections.get("resolv", "").splitlines()
        if line.strip().startswith("# ExtServers")
    ]
    if egress["default_routes"] or not internal:
        egress["beyond_network"] = "configured_open"
    elif internal and not egress["default_routes"]:
        egress["beyond_network"] = "configured_closed"
    egress["summary"] = (
        f"This container has {len(egress['default_routes'])} default route(s) and the network "
        f"{network} reports Internal={str(internal).lower()}. beyond_network is "
        f"{egress['beyond_network']}: "
        + (
            "traffic to an address outside this network has somewhere to go, so the network is not "
            "an egress boundary."
            if egress["beyond_network"] == "configured_open"
            else "no default route and an internal network, so there is no configured path out."
            if egress["beyond_network"] == "configured_closed"
            else "the probe did not return enough to say either way."
        )
    )
    return egress, raw


def decode_argv(values: Any, origin: str) -> list[str]:
    if not isinstance(values, list) or not values:
        raise SandboxError(f"{origin} must hold a non empty JSON array of strings.")
    for item in values:
        if not isinstance(item, str):
            raise SandboxError(f"{origin} must hold strings only, found {type(item).__name__}: {item!r}")
    return list(values)


def resolve_command(args: argparse.Namespace) -> tuple[list[str], str]:
    """Work out what to run, from exactly one of the three ways of saying it."""
    trailing = list(args.command)
    while trailing and trailing[0] == "--":
        trailing.pop(0)

    chosen = []
    if args.argv_b64:
        chosen.append("argv_b64")
    if args.argv_file:
        chosen.append("argv_file")
    if trailing:
        chosen.append("argv_inline")
    if not chosen:
        raise SandboxError(
            "no command given. Use one of: --argv-b64 <base64 JSON array>, --argv-file <path>, "
            "or -- <command and args>."
        )
    if len(chosen) > 1:
        raise SandboxError(f"give the command exactly one way, not {len(chosen)}: {', '.join(chosen)}")

    source = chosen[0]
    if source == "argv_b64":
        try:
            decoded = base64.b64decode(args.argv_b64, validate=True)
        except (binascii.Error, ValueError):
            try:
                decoded = base64.urlsafe_b64decode(args.argv_b64)
            except (binascii.Error, ValueError) as error:
                raise SandboxError(f"--argv-b64 is not valid base64: {error}") from error
        try:
            parsed = json.loads(decoded.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SandboxError(f"--argv-b64 did not decode to UTF-8 JSON: {error}") from error
        return decode_argv(parsed, "--argv-b64"), source
    if source == "argv_file":
        path = Path(args.argv_file)
        if not path.is_file():
            raise SandboxError(f"--argv-file does not exist: {path}")
        parsed = json.loads(path.read_text(encoding="utf-8-sig"))
        return decode_argv(parsed, f"--argv-file {path}"), source
    return trailing, source


WINDOWS_PATH_PATTERN = re.compile(r"^[A-Za-z]:[\\/]")


def argument_warnings(command: list[str], source: str) -> list[str]:
    """Notice arguments that a Windows shell layer has already rewritten.

    Git Bash rewrites anything that looks like a Unix path into a Windows path
    before the argument leaves the shell, so /etc/hosts arrives as
    C:/Program Files/Git/etc/hosts and /dev/null arrives as nul. The container is
    Linux, so neither means anything there. This is not caught by the router's
    check, because it happens before cmd.exe is involved at all. Recorded as a
    warning rather than a refusal, because a Windows path could in principle be
    what someone meant.
    """
    if source != "argv_inline":
        return []
    warnings = []
    for argument in command:
        if WINDOWS_PATH_PATTERN.match(argument) or argument in {"nul", "NUL"}:
            warnings.append(
                f"argument {argument!r} looks like a Windows path, so a shell probably rewrote a Unix "
                "path before this script saw it. Pass the command with --argv-b64 or --argv-file, or "
                "set MSYS_NO_PATHCONV=1, and check what the record says was run."
            )
    return warnings


def process_scan_script(token: str, *, kill: bool) -> str:
    """A shell one liner that finds every process in the container carrying our token.

    Each step is started with a unique token in its environment, and every child
    it spawns inherits that environment. So reading /proc/<pid>/environ finds the
    step's whole family, including a sleep that outlived the shell that started it.
    """
    if not TOKEN_PATTERN.match(token):
        raise SandboxError(f"step token is not a plain hex token: {token!r}")
    action = 'kill -9 "$pid" 2>/dev/null;' if kill else ""
    return (
        'for d in /proc/[0-9]*; do '
        'pid=${d#/proc/}; '
        '[ -r "$d/environ" ] || continue; '
        f'if tr "\\0" "\\n" < "$d/environ" 2>/dev/null | grep -q "^{STEP_TOKEN_VARIABLE}={token}$"; then '
        f'echo "$pid"; {action} '
        'fi; '
        'done'
    )


def scan_step_processes(name: str, token: str, *, kill: bool) -> tuple[list[str], str | None]:
    guard_owned(name)
    try:
        completed = run_docker(
            ["exec", name, "sh", "-c", process_scan_script(token, kill=kill)],
            timeout=KILL_TIMEOUT,
        )
    except SandboxError as error:
        return [], str(error)
    if completed.returncode != 0:
        return [], text(completed.stderr) or f"process scan exited {completed.returncode}"
    return [line.strip() for line in text(completed.stdout).splitlines() if line.strip()], None


def create_job(args: argparse.Namespace) -> int:
    name = container_name_for(args.job)
    job_dir = job_directory(args)
    if manifest_path(job_dir).exists():
        raise SandboxError(
            f"a manifest already exists for this job: {manifest_path(job_dir)}. "
            "A job id is used once. Pick another id, or move the old job directory aside."
        )
    members_before = require_network(args.network)
    if container_exists(name):
        raise SandboxError(f"a container named {name} already exists. Refusing to clobber it. Destroy it first.")

    job_dir.mkdir(parents=True, exist_ok=True)
    (job_dir / "steps").mkdir(exist_ok=True)

    ledger = usage_tracker.ledger_path(args.workdir, args.job)
    if ledger.exists():
        raise SandboxError(
            f"a usage ledger already exists for this job: {ledger}. A job id is used once. "
            "Pick another id, or move the old job directory aside."
        )
    # The token is generated here and stamped into a label. It is what ties this
    # container to this ledger, and it is the reason a second ledger cannot be
    # handed to the same container by editing a file.
    bind = secrets.token_hex(16)

    completed = run_docker(
        [
            "run",
            "--detach",
            "--name",
            name,
            "--network",
            args.network,
            "--workdir",
            CONTAINER_WORKDIR,
            "--user",
            "root",
            "--label",
            f"{LABEL_JOB}={args.job}",
            "--label",
            "mask0ff.owner=sandbox",
            "--label",
            f"{LABEL_BIND}={bind}",
            "--label",
            f"{LABEL_LEDGER}={ledger}",
            "--label",
            f"{LABEL_JOBDIR}={job_dir}",
            "--entrypoint",
            "sh",
            args.image,
            "-c",
            KEEPALIVE,
        ]
    )
    if completed.returncode != 0:
        raise SandboxError(f"docker run failed: {text(completed.stderr) or 'no stderr'}")
    container_id = text(completed.stdout)[:12]

    # Open the ledger straight away, so the wall clock runs from create rather than
    # from the first exec. If this fails the container is removed again, because a
    # container with no ledger is a container with no budget.
    try:
        start_event = usage_tracker.start_for_job(
            ledger,
            args.job,
            {"max_calls": args.max_calls, "max_seconds": args.max_seconds, "max_usd": args.max_usd},
            f"opened by sandbox create for container {name}",
            bind=bind,
        )
    except Exception:
        run_docker(["rm", "--force", "--volumes", name])
        raise

    details = inspect_container(name) or {}
    network_details = network_inspect(args.network)
    egress, egress_raw = probe_egress(name, args.network, network_details)
    egress_probe_path = job_dir / "egress-probe.txt"
    egress_probe_path.write_text(egress_raw + "\n", encoding="utf-8")
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "job_id": args.job,
        "container_name": name,
        "container_id": container_id,
        "image": args.image,
        "network": args.network,
        "container_workdir": CONTAINER_WORKDIR,
        "runs_as": "root inside the container",
        "host_bind_mounts": bind_mounts_of(details),
        "mounts": mounts_of(details),
        "network_members_before_create": members_before,
        "network_members_at_create": network_members(args.network),
        "egress": egress,
        "egress_probe_raw": egress_probe_path.name,
        "created_at_utc": utc_now(),
        "destroyed_at_utc": None,
        "state": "created",
        "step_count": 0,
        "steps": [],
        "usage_ledger": str(ledger),
        "usage_caps": start_event["caps"],
        "usage_identity_note": (
            "The fields above are a copy for reading. They are not what decides which ledger this "
            "job spends from. That comes from the container's own labels, read live at every exec, "
            "because a label cannot be changed on an existing container and this file can."
        ),
        "scope_note": (
            "Scope, stated exactly, with no claim that goes further than what was measured. "
            "FILESYSTEM: no path from this machine is handed into the container, because create "
            "passes no -v and no --mount. host_bind_mounts is what a live docker inspect found, and "
            "mounts lists every mount of any kind, including any anonymous volume the image declares "
            "for itself. NETWORK: "
            f"{args.network} names the containers this one can reach by name, and "
            "network_members_at_create records which ones those were at create time. That network is "
            "NOT a statement of everything this container can reach, and it is not a containment "
            "boundary on its own. Read the egress field: it records what the route table, the "
            "resolver and the network flags say, and its not_measured field says what was left "
            "untested. Do not quote this note as proof of a boundary that egress does not support."
        ),
    }
    save_json(manifest_path(job_dir), manifest)
    emit(
        {
            "schema_version": SCHEMA_VERSION,
            "command": "create",
            "status": "created",
            "job_id": args.job,
            "container_name": name,
            "container_id": container_id,
            "image": args.image,
            "network": args.network,
            "network_members_at_create": manifest["network_members_at_create"],
            "host_bind_mounts": manifest["host_bind_mounts"],
            "mounts": manifest["mounts"],
            "egress": egress,
            "scope_note": manifest["scope_note"],
            "job_directory": str(job_dir),
            "manifest": str(manifest_path(job_dir)),
            "egress_probe_raw": str(egress_probe_path),
            "usage": {
                "ledger": str(ledger),
                "caps": start_event["caps"],
                "cap_source": start_event["cap_source"],
                "clock_starts": "now, at create, not at the first exec",
                "note": (
                    "The caps come from MAPTA section 3.3. Every exec on this job takes one call "
                    "out of this budget before it runs, and refuses with exit 3 once a cap is "
                    "reached. Raising a cap is a separate command that records the raise."
                ),
            },
        }
    )
    return 0


def exec_step(args: argparse.Namespace) -> int:
    command, command_source = resolve_command(args)
    warnings = argument_warnings(command, command_source)

    job_dir = job_directory(args)
    manifest = load_manifest(job_dir)
    name = guard_owned(str(manifest["container_name"]))

    details = inspect_container(name)
    if details is None:
        raise SandboxError(f"container {name} does not exist. The job was destroyed, or it never started.")
    if not details.get("State", {}).get("Running"):
        raise SandboxError(f"container {name} is not running, its state is {details.get('State', {}).get('Status')!r}.")

    # Which ledger this container spends from is decided by the container, not by
    # anything in this directory. Every disagreement is a refusal.
    identity = container_identity(details, job_dir, manifest)
    ledger = identity["ledger"]

    timeout = int(os.environ.get("MASK0FF_SANDBOX_TIMEOUT", "300"))
    token = uuid.uuid4().hex
    steps_dir = job_dir / "steps"

    # Reserve the call and claim the step number together, under one lock, before
    # any docker exec. Reserving after the work ran is what let parallel execs
    # overshoot the cap and what let a killed job leave its call uncounted.
    with usage_tracker.job_lock(ledger):
        usage = usage_tracker.reserve(
            ledger,
            identity["job_id"],
            bind=identity["bind"],
            kind="exec",
            note=f"sandbox exec: {' '.join(command)[:200]}",
        )
        # Refuse when the reservation was refused, not when the job is at its cap
        # after taking it. With a cap of 3 the third call runs and the fourth is
        # refused, which is what the cap means: the size of the budget.
        if not usage["reserved"]:
            emit(
                {
                    "schema_version": SCHEMA_VERSION,
                    "command": "exec",
                    "status": "refused_usage_cap",
                    "job_id": identity["job_id"],
                    "container_name": name,
                    "refused_command": command,
                    "command_source": command_source,
                    "breached_fields": usage["breached_fields"],
                    "caps": usage["caps"],
                    "totals": usage["totals"],
                    "ledger": usage["ledger"],
                    "ran_anything": False,
                    "note": (
                        "Nothing was run. This job has spent its budget. The caps come from MAPTA "
                        "section 3.3, where longer and more expensive runs correlated negatively "
                        "with success. To continue anyway, raise a cap on purpose with "
                        "'mask0ff.cmd usage raise --job <id> --reason <text>', which writes the "
                        "raise to the ledger. The breach already recorded is never removed."
                    ),
                }
            )
            return USAGE_BREACH_EXIT_CODE
        started = utc_now()
        step_number, step_path = claim_step_number(
            steps_dir,
            {
                "schema_version": SCHEMA_VERSION,
                "state": "claimed_and_running",
                "job_id": identity["job_id"],
                "container_name": name,
                "command": command,
                "command_source": command_source,
                "step_token": token,
                "started_at_utc": started,
                "usage_reservation_id": usage["reservation_id"],
                "note": (
                    "This file was written before the command ran, so the step number could not be "
                    "taken twice. If it still says claimed_and_running, the caller never came back: "
                    "the call is on the ledger and the command may still be running in the container."
                ),
            },
        )

    stem = f"{step_number:04d}"
    stdout_path = steps_dir / f"{stem}.stdout.txt"
    stderr_path = steps_dir / f"{stem}.stderr.txt"

    timed_out = False
    kill_report: dict[str, Any] = {
        "attempted": False,
        "killed_pids": [],
        "still_running_pids": [],
        "error": None,
    }
    # The output goes straight to the files rather than into a pipe we read at the
    # end. That way whatever the command printed before a timeout is already on
    # disk, instead of being thrown away with the pipe.
    with stdout_path.open("wb") as out_handle, stderr_path.open("wb") as err_handle:
        try:
            process = subprocess.Popen(
                [
                    DOCKER,
                    "exec",
                    "--workdir",
                    CONTAINER_WORKDIR,
                    "--env",
                    f"{STEP_TOKEN_VARIABLE}={token}",
                    name,
                    *command,
                ],
                stdout=out_handle,
                stderr=err_handle,
            )
        except FileNotFoundError as error:
            raise SandboxError(f"docker client not found on PATH as {DOCKER!r}") from error
        try:
            exit_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            exit_code = TIMEOUT_EXIT_CODE
            # Killing the local docker client only cuts the wire. The command and
            # anything it started keep running inside the container, holding locks
            # and still hitting the target while the next step believes it is alone.
            kill_report["attempted"] = True
            killed, kill_error = scan_step_processes(name, token, kill=True)
            kill_report["killed_pids"] = killed
            kill_report["error"] = kill_error
            try:
                process.wait(timeout=KILL_TIMEOUT)
            except subprocess.TimeoutExpired:
                process.kill()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    kill_report["error"] = (kill_report["error"] or "") + " docker client did not exit after kill"
            survivors, survivor_error = scan_step_processes(name, token, kill=False)
            kill_report["still_running_pids"] = survivors
            if survivor_error and not kill_report["error"]:
                kill_report["error"] = survivor_error
    finished = utc_now()

    stdout_bytes = stdout_path.read_bytes()
    stderr_bytes = stderr_path.read_bytes()
    containment = "clean"
    if timed_out:
        containment = "orphans_remain" if kill_report["still_running_pids"] else "killed_after_timeout"

    # The call was already counted before it ran. This attaches what it actually
    # took, and it never adds a second call. No cost is passed, because nothing here
    # measured one and this script will not invent a dollar figure.
    usage_after = usage_tracker.settle(
        ledger,
        identity["job_id"],
        usage["reservation_id"],
        seconds=max(0.0, (usage_tracker.parse_time(finished) - usage_tracker.parse_time(started)).total_seconds()),
        exit_code=exit_code,
        note=f"sandbox exec step {step_number}: {' '.join(command)[:200]}",
    )

    step_record = {
        "schema_version": SCHEMA_VERSION,
        "state": "finished",
        "step": step_number,
        "job_id": identity["job_id"],
        "container_name": name,
        "container_workdir": CONTAINER_WORKDIR,
        "command": command,
        "command_source": command_source,
        "argument_warnings": warnings,
        "step_token": token,
        "wrapper_command_line": os.environ.get("MASK0FF_RAW_CMDLINE"),
        "started_at_utc": started,
        "finished_at_utc": finished,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "timeout_seconds": timeout,
        "timeout_kill": kill_report,
        "containment": containment,
        "stdout_path": stdout_path.name,
        "stderr_path": stderr_path.name,
        "stdout_bytes": len(stdout_bytes),
        "stderr_bytes": len(stderr_bytes),
        "stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
        "stderr_sha256": hashlib.sha256(stderr_bytes).hexdigest(),
        "usage_ledger": usage_after["ledger"],
        "usage_reservation_id": usage["reservation_id"],
        "usage_reserved_before_the_command_ran": True,
        "usage_caps": usage_after["caps"],
        "usage_totals_after_this_step": usage_after["totals"],
        "usage_breached_after_this_step": usage_after["breached"],
        "usage_breached_fields": usage_after["breached_fields"],
    }
    save_json(step_path, step_record)

    # Read, change and write the manifest under the job lock. Two execs finishing at
    # the same moment used to overwrite each other's step list, and on Windows one of
    # them died renaming the temporary file after its command had already run.
    with usage_tracker.job_lock(ledger):
        manifest = load_manifest(job_dir)
        manifest["step_count"] = max(int(manifest.get("step_count") or 0), step_number)
        manifest.setdefault("steps", []).append(
            {
                "step": step_number,
                "command": command,
                "command_source": command_source,
                "exit_code": exit_code,
                "timed_out": timed_out,
                "containment": containment,
                "started_at_utc": started,
                "record": step_path.name,
            }
        )
        manifest["steps"] = sorted(manifest["steps"], key=lambda entry: int(entry.get("step") or 0))
        save_json(manifest_path(job_dir), manifest)

    emit(
        {
            "schema_version": SCHEMA_VERSION,
            "command": "exec",
            "status": "ran",
            "job_id": identity["job_id"],
            "container_name": name,
            "step": step_number,
            "executed": command,
            "command_source": command_source,
            "argument_warnings": warnings,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "timeout_kill": kill_report,
            "containment": containment,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "record_path": str(step_path),
            "stdout_bytes": len(stdout_bytes),
            "stderr_bytes": len(stderr_bytes),
            "usage": {
                "ledger": usage_after["ledger"],
                "reservation_id": usage["reservation_id"],
                "caps": usage_after["caps"],
                "totals": usage_after["totals"],
                "breached": usage_after["breached"],
                "breached_fields": usage_after["breached_fields"],
                "note": (
                    "This step was counted as one tool call before it ran, and what it took was "
                    "attached afterwards. When breached is true the next exec on this job is "
                    "refused with exit 3."
                ),
            },
            "note": "exit_code is the code the command returned inside the container, and this script exits with it.",
        }
    )
    return exit_code


def status_job(args: argparse.Namespace) -> int:
    job_dir = job_directory(args)
    manifest = load_manifest(job_dir)
    name = guard_owned(str(manifest["container_name"]))
    details = inspect_container(name)
    live: dict[str, Any] = {"exists": details is not None}
    if details is not None:
        state = details.get("State", {})
        live.update(
            {
                "running": bool(state.get("Running")),
                "docker_status": state.get("Status"),
                "started_at": state.get("StartedAt"),
                "image": details.get("Config", {}).get("Image"),
                "networks": sorted(details.get("NetworkSettings", {}).get("Networks", {})),
                "host_bind_mounts": bind_mounts_of(details),
                "mounts": mounts_of(details),
            }
        )
    emit(
        {
            "schema_version": SCHEMA_VERSION,
            "command": "status",
            "status": manifest.get("state"),
            "job_id": manifest["job_id"],
            "container_name": name,
            "network_declared": manifest.get("network"),
            "network_members_at_create": manifest.get("network_members_at_create", []),
            "egress": manifest.get("egress"),
            "scope_note": manifest.get("scope_note"),
            "created_at_utc": manifest.get("created_at_utc"),
            "destroyed_at_utc": manifest.get("destroyed_at_utc"),
            "step_count": manifest.get("step_count", 0),
            "steps": manifest.get("steps", []),
            "job_directory": str(job_dir),
            "container": live,
        }
    )
    return 0


def destroy_job(args: argparse.Namespace) -> int:
    job_dir = job_directory(args)
    manifest = load_manifest(job_dir)
    name = guard_owned(str(manifest["container_name"]))

    was_present = container_exists(name)
    removal_error = None
    if was_present:
        completed = run_docker(["rm", "--force", "--volumes", name])
        if completed.returncode != 0:
            removal_error = text(completed.stderr) or "docker rm failed with no stderr"
    still_present = container_exists(name)
    removed = was_present and not still_present

    manifest["state"] = "destroyed" if not still_present else "destroy_failed"
    manifest["destroyed_at_utc"] = utc_now()
    manifest["destroy_removed_container"] = removed
    manifest["destroy_error"] = removal_error
    save_json(manifest_path(job_dir), manifest)

    emit(
        {
            "schema_version": SCHEMA_VERSION,
            "command": "destroy",
            "status": manifest["state"],
            "job_id": manifest["job_id"],
            "container_name": name,
            "was_present": was_present,
            "removed": removed,
            "still_present": still_present,
            "error": removal_error,
            "job_directory": str(job_dir),
            "note": "The job directory and its step transcripts are kept. Only the container is removed.",
        }
    )
    return SCRIPT_FAILURE_CODE if still_present else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="One Docker container per assessment job: create, exec, status, destroy.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common(target: argparse.ArgumentParser) -> None:
        target.add_argument("--job", required=True, help="Job id. The container is always named mask0ff-job-<id>.")
        target.add_argument(
            "--workdir",
            type=Path,
            default=DEFAULT_JOBS_DIR,
            help=f"Directory on the host holding job records. Default: {DEFAULT_JOBS_DIR}",
        )

    create = subparsers.add_parser("create", help="Create the container for a job.")
    add_common(create)
    create.add_argument("--network", required=True, help="Docker network to attach to. This is the scope of the job.")
    create.add_argument("--image", default=DEFAULT_IMAGE, help=f"Container image. Default: {DEFAULT_IMAGE}")
    create.add_argument(
        "--max-calls",
        type=usage_tracker.argparse_type(usage_tracker.positive_integer, "--max-calls"),
        default=usage_tracker.DEFAULT_MAX_CALLS,
        help=f"Tool call cap for this job. Default: {usage_tracker.DEFAULT_MAX_CALLS} (MAPTA section 3.3).",
    )
    create.add_argument(
        "--max-seconds",
        type=usage_tracker.argparse_type(usage_tracker.positive_number, "--max-seconds"),
        default=usage_tracker.DEFAULT_MAX_SECONDS,
        help=f"Wall clock cap in seconds, from create. Default: {usage_tracker.DEFAULT_MAX_SECONDS}.",
    )
    create.add_argument(
        "--max-usd",
        type=usage_tracker.argparse_type(usage_tracker.positive_number, "--max-usd"),
        default=usage_tracker.DEFAULT_MAX_USD,
        help=f"Cost cap in US dollars. Default: {usage_tracker.DEFAULT_MAX_USD}.",
    )
    create.set_defaults(handler=create_job)

    execute = subparsers.add_parser("exec", help="Run one command inside the job container and record it.")
    add_common(execute)
    execute.add_argument("--argv-b64", help="Base64 of a UTF-8 JSON array of strings. The safe way on Windows.")
    execute.add_argument("--argv-file", help="Path to a file holding a JSON array of strings. Also safe on Windows.")
    execute.add_argument("command", nargs=argparse.REMAINDER, help="The command to run, after a bare --")
    execute.set_defaults(handler=exec_step)

    status = subparsers.add_parser("status", help="Report the job manifest and the live container state.")
    add_common(status)
    status.set_defaults(handler=status_job)

    destroy = subparsers.add_parser("destroy", help="Remove the job container. Transcripts are kept.")
    add_common(destroy)
    destroy.set_defaults(handler=destroy_job)
    return parser


def main() -> int:
    try:
        args = build_parser().parse_args()
        return int(args.handler(args))
    except usage_tracker.LedgerTampered as error:
        print(f"USAGE LEDGER INTEGRITY FAILURE: {error}", file=sys.stderr)
        emit(
            {
                "schema_version": SCHEMA_VERSION,
                "status": "usage_ledger_integrity_failure",
                "error": str(error),
                "ran_anything": False,
                "note": (
                    "The usage ledger for this job does not verify, so how much budget it has spent "
                    "is unknown. Nothing was run. This is not a within caps answer."
                ),
            }
        )
        return USAGE_TAMPER_EXIT_CODE
    except usage_tracker.UsageError as error:
        print(f"USAGE ERROR: {error}", file=sys.stderr)
        emit(
            {
                "schema_version": SCHEMA_VERSION,
                "status": "usage_error",
                "error": str(error),
                "ran_anything": False,
            }
        )
        return SCRIPT_FAILURE_CODE
    except (SandboxError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        emit({"schema_version": SCHEMA_VERSION, "status": "error", "error": str(error)})
        return SCRIPT_FAILURE_CODE


if __name__ == "__main__":
    raise SystemExit(main())
