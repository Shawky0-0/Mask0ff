#!/usr/bin/env python3
"""Count what one assessment job spends, and stop it when the budget is gone.

Why this exists, and it is a measurement rather than a preference. MAPTA ran 104
XBOW benchmark challenges and found that spending more did not mean finding more.
The median solved challenge cost 0.073 US dollars; the median failed one cost
0.357. All four correlations between resource use and success were negative: tool
usage -0.661, cost -0.606, tokens -0.587, time -0.557, every one a point biserial
correlation with N equals 104, significant at p below 0.001. Long and expensive
means losing, not thorough. The paper's own caveat is carried too: correlation is
not causation, and those relationships likely reflect how hard the challenge was
rather than resource use causing the failure. Source: MAPTA section 3.3, digested
at security/research/mapta-multi-agent-pentest.md, read again 2026-08-12.

The three caps below are MAPTA's own early stopping thresholds, section 3.3:
roughly 40 tool calls (the paper states that threshold as the 95th percentile of
successful challenges), 0.30 US dollars per target, and 300 seconds without
significant progress. This script does not implement "without significant
progress", because nothing here can judge progress. It stops on the clock.

What makes this enforcement rather than advice
----------------------------------------------
  1. "check" exits 3 when a cap is breached. An exit code is what a caller can
     act on. A printed warning is not.
  2. "sandbox exec" asks this tracker before it runs anything, and refuses when
     the answer is breached. So the budget stops work, it does not only describe
     it.
  3. A breach is written to the ledger and never removed. There is no flag that
     clears one. Raising a cap is a separate named command that records the
     raise, so the record shows a cap was raised rather than the work being
     cheap.

The ledger
----------
One file per job, <workdir>/<job>/usage-ledger.jsonl, one JSON object per line,
appended and fsynced to disk before the command returns. Nothing is ever
rewritten and nothing lives only in memory. The file is the whole state: the
first line carries the caps, every later line is an event.

Wall clock is measured from the start event to now. It is NOT the sum of the
seconds fields callers pass in. A job that sits idle for ten minutes has burned
ten minutes, and summing self reported durations would hide exactly that. The
sum of the reported seconds is still printed, clearly labelled, because the gap
between the two is useful. It is never what a cap compares against.

Cost is only counted when a caller supplies it with --usd. This script does not
know any model's token price and will not guess one. When nothing supplied a
cost the total is 0.0 and the report says plainly that cost was never reported,
which is not the same as the job being free.

What round 2 changed, and why each change exists
------------------------------------------------
A blind red agent broke round 1 eleven ways. Every route below is closed here,
and each fix is named so a reader can check the fix against the break.

  * Every number is validated at the door. A negative --usd used to subtract from
    the total and lift a breached job back under its cap. Negative costs and
    negative durations are refused. So are "nan" and "inf": argparse's float()
    accepts both strings, one nan made every later comparison false, and the
    dollar cap could never bind again for that job. Refused at the argparse
    layer, refused again inside the functions the sandbox calls, and refused a
    third time when read back off the ledger.
  * The ledger is an HMAC chain, plus a tip marker. Every line carries seq,
    prev_hmac and hmac. A hand edited ledger used to erase a breach with no
    residue at all. Now an edit, a reorder or a removal breaks the chain. Cutting
    the end off does not break a chain, because the front of a good chain is still
    a good chain, so a separate tip file records the last event written and a
    ledger that stops earlier than the tip is refused. Both failures exit 4. Read
    the honest limit below: this raises the cost of tampering, it does not make it
    impossible.
  * Budget is reserved before the work runs, not recorded after it. The old order
    was check, then run for hundreds of milliseconds, then record. Three parallel
    execs with one call of budget left all passed the check and all ran. Now the
    call is written to the ledger under a lock before docker is touched, so a
    racer sees it. The same order fixes a job killed mid call, which used to
    leave the call uncounted while the command carried on inside the container.
  * A breach latches. "breached" is now true if a cap is over now OR a breach
    event for that field was written and that field has not been deliberately
    raised since. Totals cannot walk backwards past a recorded breach.

Honest limits, because a control described better than it behaves is worse than
no control
-----------------------------------------------------------------------------
  * The HMAC chain is keyed by a file that sits next to the ledger by default, and
    so does the tip. An operator who can rewrite the ledger can usually also read
    that key and rewrite that tip, and then forge a consistent ledger. The proof
    run does exactly that, on purpose, so the limit is on the record rather than
    implied. What the chain and the tip buy is that a careless edit, a truncation,
    or a change by anything that does not know about the key is caught. Set
    MASK0FF_USAGE_KEY_DIR to a directory the job cannot write and forging needs
    access this script does not hand out. Deleting the key or the tip does not
    open a bypass: without either one every command refuses.
  * The lock is advisory. It stops two copies of this script from racing. It does
    not stop anything that writes the file without asking for the lock.
  * The caps bind what goes through this tracker. Anything that reaches the
    target without going through the sandbox is not counted, and no code here can
    claim otherwise.

Exit codes:
  0    within caps, or the command was a plain view
  1    this script failed, for example a missing ledger or a bad argument
  3    a cap is breached ("check" and "record")
  4    the ledger failed its integrity check, so no answer about it is trustworthy
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import secrets
import sys
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_JOBS_DIR = ROOT.parent / "jobs"
LEDGER_NAME = "usage-ledger.jsonl"
KEY_NAME = "usage-ledger.key"
TIP_NAME = "usage-ledger.tip"
LOCK_NAME = "usage-ledger.lock"
SCHEMA_VERSION = 2
BREACH_EXIT_CODE = 3
TAMPER_EXIT_CODE = 4

# MAPTA section 3.3, via security/research/mapta-multi-agent-pentest.md.
DEFAULT_MAX_CALLS = 40
DEFAULT_MAX_SECONDS = 300.0
DEFAULT_MAX_USD = 0.30

CAP_FIELDS = ("max_calls", "max_seconds", "max_usd")
# The short name a breach is recorded under, and the cap it belongs to.
CAP_OF = {"calls": "max_calls", "seconds": "max_seconds", "usd": "max_usd"}
KINDS = ("tool-call", "fetch", "exec")
LOCK_TIMEOUT_SECONDS = 60.0
LOCK_STALE_SECONDS = 900.0

# Every cap is compared with >=, so the cap is the size of the budget and not the
# first value that is allowed to exceed it. With max_calls 40 the fortieth call
# runs and the forty first is refused.
COMPARISON_NOTE = (
    "Every cap is compared with >=. The cap is the size of the budget, so reaching it "
    "spends it and the next call is refused."
)
COST_UNREPORTED_NOTE = (
    "Cost was never reported by any caller, so totals.cost_usd is 0.0 because nothing "
    "measured it, not because the job was free. The dollar cap cannot bind until a "
    "caller passes --usd. Nothing here invents a token price."
)
WALL_CLOCK_NOTE = (
    "seconds_elapsed is wall clock from the start event to now. It is not the sum of "
    "the seconds callers reported; that sum is shown separately as seconds_reported_sum "
    "and no cap compares against it."
)
INTEGRITY_NOTE = (
    "Every line carries seq, prev_hmac and hmac, keyed by a secret written when the ledger "
    "was opened, and a tip file records the last event written. An edit, a reorder or a "
    "removal breaks the chain; cutting the end off is caught by the tip, because the front "
    "of a good chain is still a good chain. Either way every command refuses with exit 4. "
    "Limit, stated plainly: whoever can read the key file can forge a consistent chain and "
    "rewrite the tip beside it, so set MASK0FF_USAGE_KEY_DIR to a directory the job cannot "
    "write if that matters."
)
LATCH_NOTE = (
    "breached is true when a cap is over now, or when a breach was recorded for a field "
    "and that field has not been raised since with 'usage raise'. Totals cannot walk "
    "backwards past a recorded breach."
)


class UsageError(Exception):
    """A failure of this script, as opposed to a cap being breached."""


class LedgerTampered(UsageError):
    """The ledger does not verify, so nothing it says can be relied on."""


# --- numbers ---------------------------------------------------------------------


def real_number(value: Any, field: str) -> float:
    """Accept a finite number and nothing else.

    "nan" and "inf" are the reason this exists. Python's float() takes both from a
    command line, and every comparison against nan is false, so one recorded nan
    switches a cap off permanently. inf does the same to a cap value.
    """
    try:
        number = float(value)
    except (TypeError, ValueError) as error:
        raise UsageError(f"{field} must be a number, got {value!r}") from error
    if math.isnan(number) or math.isinf(number):
        raise UsageError(
            f"{field} must be a real number, got {value!r}. nan and inf are refused, because "
            "every comparison against nan is false, so one of them would switch the cap off for "
            "good and the job would look cheap forever."
        )
    return number


def positive_number(value: Any, field: str) -> float:
    number = real_number(value, field)
    if number <= 0:
        raise UsageError(f"{field} must be greater than zero, got {number}")
    return number


def non_negative_number(value: Any, field: str) -> float:
    number = real_number(value, field)
    if number < 0:
        raise UsageError(
            f"{field} must not be negative, got {number}. A negative entry subtracts from a total, "
            "which would carry a breached job back under its cap without any record that a cap "
            "moved. Moving a cap is what 'usage raise' is for, and it writes the raise down."
        )
    return number


def positive_integer(value: Any, field: str) -> int:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError) as error:
        raise UsageError(f"{field} must be a whole number, got {value!r}") from error
    if number <= 0:
        raise UsageError(f"{field} must be greater than zero, got {number}")
    return number


def argparse_type(function: Any, field: str) -> Any:
    """Wrap one of the checks above so argparse prints its reason, not a traceback."""

    def convert(raw: str) -> Any:
        try:
            return function(raw, field)
        except UsageError as error:
            raise argparse.ArgumentTypeError(str(error)) from error

    return convert


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_time(value: Any) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as error:
        raise LedgerTampered(f"ledger holds a timestamp that cannot be read: {value!r}") from error
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False))


def ledger_path(workdir: Path, job_id: str) -> Path:
    return (Path(workdir) / job_id / LEDGER_NAME).resolve()


# --- the lock --------------------------------------------------------------------


_HELD: dict[str, int] = {}


@contextmanager
def job_lock(
    ledger: Path,
    *,
    timeout: float = LOCK_TIMEOUT_SECONDS,
    stale_after: float = LOCK_STALE_SECONDS,
) -> Iterator[None]:
    """Hold one job's ledger while checking and appending, so a racer cannot slip in.

    The old order was check, then run the command, then record. Two commands that
    started together both read the same count, both passed, and both ran, so the cap
    was overshot with no tampering at all. Reserving budget inside this lock is what
    closes that, and the lock has to cover the read and the append together or the
    same race comes back one layer down.

    Made with O_CREAT plus O_EXCL, which is atomic on Windows and on Linux. It is
    advisory: it stops two copies of this script racing, not anything that writes the
    file without asking. A lock left behind by a killed process is taken over after
    stale_after seconds, and that number is deliberately much longer than any command
    this tracker takes.

    Two failures mean "somebody else has it", not "you may proceed": FileExistsError
    everywhere, and PermissionError on Windows while a just released lock file is
    still delete pending. Both wait and ask again until the deadline. The lock is
    never handed out on an error, so a caller either holds it or does not run.
    """
    path = ledger.parent / LOCK_NAME
    key = str(path)
    if _HELD.get(key):
        _HELD[key] += 1
        try:
            yield
        finally:
            _HELD[key] -= 1
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout
    contention: OSError | None = None
    while True:
        try:
            handle = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError as error:
            # Somebody else holds it. Wait and ask again.
            contention = error
        except PermissionError as error:
            # Windows only, and it is the same situation wearing a different error.
            # A lock file that its holder has just unlinked stays on the directory in
            # "delete pending" until the last handle on it closes, and every open of
            # it in that window fails with access denied rather than with file exists.
            # This was measured, it is not a precaution: 272 contended acquisitions
            # across 13 stress rounds produced 3 of these, and each one killed a
            # caller that should have queued. The cap never leaked, because a caller
            # that dies has not reserved anything, but a legitimate exec died at
            # random under parallel pressure, and the same throw inside "settle"
            # would land AFTER the container command had already run, leaving no
            # step record for work that did happen.
            #
            # Retrying is the correct answer because the state is the same state:
            # this process does not hold the lock. Nothing here ever grants the lock
            # on an error, so the serialisation the caps depend on is untouched. A
            # directory that genuinely cannot be written keeps failing this way and
            # is reported when the deadline passes, with the real error attached, so
            # a permissions problem is not silently reshaped into a timeout.
            contention = error
        else:
            try:
                os.write(handle, f"pid {os.getpid()} took this lock at {utc_now()}\n".encode("utf-8"))
            finally:
                os.close(handle)
            break

        try:
            age = time.time() - os.path.getmtime(path)
        except OSError:
            # The holder released it between the failed open and this question, or
            # the file is delete pending and cannot be stat'd. Either way it is not
            # evidence of a stale lock, so treat it as fresh and ask again. The old
            # code restarted the loop here with no deadline and no sleep, which is a
            # busy wait that could not time out.
            age = 0.0
        if age > stale_after:
            try:
                os.unlink(path)
            except OSError:
                pass
        if time.monotonic() > deadline:
            raise UsageError(
                f"could not take the usage lock at {path} within {timeout} seconds. Another command "
                f"is holding it, or this directory cannot be written. The last error from the lock "
                f"file was: {contention!r}. Nothing was recorded and nothing was run."
            )
        time.sleep(0.02)
    _HELD[key] = 1
    try:
        yield
    finally:
        _HELD.pop(key, None)
        try:
            os.unlink(path)
        except OSError:
            pass


# --- the HMAC chain ---------------------------------------------------------------


def key_path(ledger: Path) -> Path:
    """Where the chain key lives. Next to the ledger unless told otherwise.

    MASK0FF_USAGE_KEY_DIR moves it somewhere the job cannot write, which is the
    difference between "an edit is detected" and "an edit cannot be made to look
    clean". The file name is a digest of the ledger path so one directory can hold
    the keys of many jobs without a collision.
    """
    override = os.environ.get("MASK0FF_USAGE_KEY_DIR", "").strip()
    if override:
        digest = hashlib.sha256(str(ledger).encode("utf-8")).hexdigest()[:32]
        return Path(override).expanduser() / f"{digest}.key"
    return ledger.parent / KEY_NAME


def tip_path(ledger: Path) -> Path:
    """Where the last written sequence number is kept.

    The chain alone does not catch a truncation: chop the end off and what is left
    is still a valid chain, which is exactly how a breach could be removed. The tip
    records how far the ledger had got, so a ledger that ends earlier than the tip is
    a ledger with its end cut off. It travels with the key, so MASK0FF_USAGE_KEY_DIR
    moves both out of the job's reach at once.
    """
    override = os.environ.get("MASK0FF_USAGE_KEY_DIR", "").strip()
    if override:
        digest = hashlib.sha256(str(ledger).encode("utf-8")).hexdigest()[:32]
        return Path(override).expanduser() / f"{digest}.tip"
    return ledger.parent / TIP_NAME


def write_tip(ledger: Path, event: dict[str, Any]) -> None:
    path = tip_path(ledger)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": SCHEMA_VERSION,
        "ledger": str(ledger),
        "seq": event["seq"],
        "hmac": event["hmac"],
        "at_utc": utc_now(),
        "note": "The last event written to that ledger. A ledger that ends before this was cut short.",
    }
    temporary = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def read_tip(ledger: Path) -> dict[str, Any]:
    path = tip_path(ledger)
    if not path.is_file():
        raise LedgerTampered(
            f"the ledger tip marker is missing: {path}. Without it a truncated ledger cannot be "
            "told from a short one, so this script refuses rather than guessing. Deleting it is not "
            "a way past a cap."
        )
    try:
        tip = json.loads(path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as error:
        raise LedgerTampered(f"the ledger tip marker at {path} is not JSON: {error}") from error
    if not isinstance(tip, dict) or "seq" not in tip or "hmac" not in tip:
        raise LedgerTampered(f"the ledger tip marker at {path} is not a tip record")
    return tip


def create_key(ledger: Path) -> bytes:
    path = key_path(ledger)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() or tip_path(ledger).exists():
        raise UsageError(
            f"a ledger key or tip already exists at {path} but the ledger does not. Refusing to "
            "reuse them, because a fresh chain under an old key is exactly what a reset looks like."
        )
    material = secrets.token_hex(32)
    handle = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        stream.write(material + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    return material.encode("utf-8")


def load_key(ledger: Path) -> bytes:
    path = key_path(ledger)
    if not path.is_file():
        raise LedgerTampered(
            f"the ledger key is missing: {path}. Without it the chain cannot be verified, so this "
            "script refuses rather than trusting the ledger. Deleting the key is not a way past a "
            "cap."
        )
    material = path.read_text(encoding="utf-8-sig").strip()
    if not material:
        raise LedgerTampered(f"the ledger key at {path} is empty")
    return material.encode("utf-8")


def chain_hmac(key: bytes, previous: str, event: dict[str, Any]) -> str:
    body = {name: value for name, value in event.items() if name != "hmac"}
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hmac.new(key, (previous + "\n" + payload).encode("utf-8"), hashlib.sha256).hexdigest()


def append_event(path: Path, key: bytes, events: list[dict[str, Any]], event: dict[str, Any]) -> dict[str, Any]:
    """Write one chained event and make sure it is on disk before returning.

    Append only, one line, no rewrite. The flush and fsync are the point: a caller
    that dies immediately after a call must still leave that call counted. The
    sandbox now writes the call BEFORE the work runs, so a caller killed during a
    call leaves it counted too, which is the case that used to slip through.

    The caller must be holding the job lock. seq and prev_hmac are read from the
    events list it verified inside that lock, so two racing writers cannot both
    claim the same sequence number.
    """
    previous = str(events[-1]["hmac"]) if events else ""
    record = {"schema_version": SCHEMA_VERSION, "seq": len(events), "prev_hmac": previous}
    record.update(event)
    record["hmac"] = chain_hmac(key, previous, record)
    line = json.dumps(record, ensure_ascii=False)
    if "\n" in line:
        raise UsageError("refusing to write a ledger line containing a newline")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    write_tip(path, record)
    events.append(record)
    return record


def check_numbers(event: dict[str, Any], number: int) -> None:
    """Refuse a ledger that carries an impossible number, whoever put it there."""
    where = f"line {number}"
    if event.get("kind") == "start":
        declared = event.get("caps", {})
        if not isinstance(declared, dict):
            raise LedgerTampered(f"{where}: the start event has no caps object")
        for field in CAP_FIELDS:
            if field in declared:
                positive_number(declared[field], f"{where} caps.{field}")
    if event.get("kind") == "raise":
        positive_number(event.get("to"), f"{where} raise.to")
    if event.get("usd") is not None:
        non_negative_number(event["usd"], f"{where} usd")
    if event.get("seconds") is not None:
        non_negative_number(event["seconds"], f"{where} seconds")


def read_events(path: Path) -> list[dict[str, Any]]:
    """Read the ledger and verify its chain. Any break is refused, not repaired."""
    if not path.is_file():
        raise UsageError(f"no usage ledger at {path}. Run 'usage start --job <id>' first.")
    key = load_key(path)
    events: list[dict[str, Any]] = []
    previous = ""
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise LedgerTampered(f"{path} line {number} is not JSON: {error}") from error
        if not isinstance(event, dict) or "kind" not in event:
            raise LedgerTampered(f"{path} line {number} is not a usage event")
        expected_seq = len(events)
        if event.get("seq") != expected_seq:
            raise LedgerTampered(
                f"{path} line {number} carries seq {event.get('seq')!r} where {expected_seq} was "
                "expected. A line was removed, added or moved."
            )
        if str(event.get("prev_hmac", "")) != previous:
            raise LedgerTampered(
                f"{path} line {number} does not follow the line before it. The chain is broken, so "
                "an event was edited or removed."
            )
        recomputed = chain_hmac(key, previous, event)
        if not hmac.compare_digest(recomputed, str(event.get("hmac", ""))):
            raise LedgerTampered(
                f"{path} line {number} fails its own hmac. This line was edited after it was "
                "written, or it was written by something that does not hold this ledger's key."
            )
        check_numbers(event, number)
        previous = str(event["hmac"])
        events.append(event)
    if not events or events[0].get("kind") != "start":
        raise LedgerTampered(f"{path} does not begin with a start event")

    # The chain alone cannot see a truncation, because the front of a good chain is
    # still a good chain. The tip says how far this ledger had got.
    tip = read_tip(path)
    tip_seq = int(tip["seq"])
    last_seq = int(events[-1]["seq"])
    if last_seq < tip_seq:
        raise LedgerTampered(
            f"{path} ends at event {last_seq}, and this ledger had already written event {tip_seq}. "
            f"{tip_seq - last_seq} event(s) were cut off the end. That is how a recorded breach is "
            "removed, so the ledger is refused rather than read."
        )
    if not hmac.compare_digest(str(events[tip_seq]["hmac"]), str(tip["hmac"])):
        raise LedgerTampered(
            f"{path} event {tip_seq} does not match the tip marker for this ledger, so the file was "
            "rebuilt after that point."
        )
    return events


# --- state ------------------------------------------------------------------------


def caps_from(events: list[dict[str, Any]]) -> tuple[dict[str, float], list[dict[str, Any]]]:
    """The caps in force now, plus every raise that got them there."""
    declared = events[0].get("caps", {})
    caps = {
        "max_calls": positive_number(declared.get("max_calls", DEFAULT_MAX_CALLS), "max_calls"),
        "max_seconds": positive_number(declared.get("max_seconds", DEFAULT_MAX_SECONDS), "max_seconds"),
        "max_usd": positive_number(declared.get("max_usd", DEFAULT_MAX_USD), "max_usd"),
    }
    raises = [event for event in events if event.get("kind") == "raise"]
    for event in raises:
        field = str(event.get("field", ""))
        if field in caps:
            caps[field] = positive_number(event.get("to"), f"raise {field}")
    return caps, raises


def state_of(events: list[dict[str, Any]], *, now: datetime | None = None) -> dict[str, Any]:
    """Work out where the job stands. Reads the ledger, writes nothing."""
    started = parse_time(events[0].get("at_utc"))
    moment = now or datetime.now(timezone.utc)
    caps, raises = caps_from(events)

    records = [event for event in events if event.get("kind") == "record"]
    settles = [event for event in events if event.get("kind") == "settle"]
    calls = len(records)
    priced = [event for event in records + settles if event.get("usd") is not None]
    cost = sum(non_negative_number(event["usd"], "usd") for event in priced)
    seconds_reported = sum(
        non_negative_number(event["seconds"], "seconds")
        for event in records + settles
        if event.get("seconds") is not None
    )
    elapsed = (moment - started).total_seconds()

    over_now = []
    if calls >= caps["max_calls"]:
        over_now.append("calls")
    if elapsed >= caps["max_seconds"]:
        over_now.append("seconds")
    if priced and cost >= caps["max_usd"]:
        over_now.append("usd")

    # A breach latches per field, and only a deliberate raise of THAT field clears
    # the latch. Without this, anything that pulls a total back down (a refund, a
    # clock skew, a route nobody has thought of yet) quietly reopens the job.
    last_raise_for: dict[str, int] = {}
    for index, event in enumerate(events):
        if event.get("kind") == "raise":
            field = str(event.get("field", ""))
            if field in caps:
                last_raise_for[field] = index
    latched: set[str] = set()
    recorded_breaches = []
    for index, event in enumerate(events):
        if event.get("kind") != "breach":
            continue
        recorded_breaches.append(event)
        for field in event.get("fields", []):
            name = str(field)
            cap_field = CAP_OF.get(name)
            if cap_field is None:
                latched.add(name)
                continue
            if index > last_raise_for.get(cap_field, -1):
                latched.add(name)

    breached_fields = sorted(set(over_now) | latched)
    unsettled = sorted(
        {str(event.get("reservation_id")) for event in records if event.get("reservation_id")}
        - {str(event.get("reservation_id")) for event in settles if event.get("reservation_id")}
    )

    return {
        "job_id": str(events[0].get("job_id", "")),
        "started_at_utc": events[0].get("at_utc"),
        "checked_at_utc": moment.isoformat(),
        "caps": {
            "max_calls": int(caps["max_calls"]),
            "max_seconds": round(caps["max_seconds"], 3),
            "max_usd": round(caps["max_usd"], 6),
        },
        "totals": {
            "calls": calls,
            "seconds_elapsed": round(elapsed, 3),
            "seconds_reported_sum": round(seconds_reported, 3),
            "cost_usd": round(cost, 6),
        },
        "cost_reported": bool(priced),
        "cost_reported_by_events": len(priced),
        "breached": bool(breached_fields),
        "breached_fields": breached_fields,
        "over_cap_now": over_now,
        "latched_breaches": sorted(latched),
        "ever_breached": bool(recorded_breaches),
        "breach_events": recorded_breaches,
        "raises": raises,
        "unlatched_breaches": sorted(set(over_now) - latched),
        "unsettled_reservations": unsettled,
        "event_count": len(events),
        "wall_clock_note": WALL_CLOCK_NOTE,
        "comparison_note": COMPARISON_NOTE,
        "latch_note": LATCH_NOTE,
        "integrity_note": INTEGRITY_NOTE,
        "cost_note": None if priced else COST_UNREPORTED_NOTE,
    }


def latch_breach(path: Path, key: bytes, events: list[dict[str, Any]], state: dict[str, Any]) -> dict[str, Any]:
    """Write a breach to disk the first time it is seen, and never remove it.

    A breach that only exists in a return value disappears when the process ends.
    Writing it means the ledger itself carries the fact, so a later report shows a
    cap was hit even if the cap was afterwards raised. Nothing in this file deletes
    a breach event. The caller must hold the job lock.
    """
    if not state["unlatched_breaches"]:
        return state
    append_event(
        path,
        key,
        events,
        {
            "kind": "breach",
            "at_utc": utc_now(),
            "job_id": state["job_id"],
            "fields": state["unlatched_breaches"],
            "totals": state["totals"],
            "caps": state["caps"],
        },
    )
    return state_of(events)


def evaluate(path: Path) -> tuple[list[dict[str, Any]], bytes, dict[str, Any]]:
    """Read, verify, latch any new breach, and return the state. Lock must be held."""
    events = read_events(path)
    key = load_key(path)
    state = latch_breach(path, key, events, state_of(events))
    state["ledger"] = str(path)
    return events, key, state


def start_ledger(
    path: Path,
    job_id: str,
    caps: dict[str, Any],
    note: str,
    *,
    bind: str | None = None,
) -> dict[str, Any]:
    """Open a ledger. Refuses if one already exists, so an id is never reused."""
    if path.exists():
        raise UsageError(
            f"a usage ledger already exists for this job: {path}. "
            "A job id is used once. Pick another id, or move the old job directory aside."
        )
    checked = {
        "max_calls": positive_integer(caps.get("max_calls", DEFAULT_MAX_CALLS), "max_calls"),
        "max_seconds": positive_number(caps.get("max_seconds", DEFAULT_MAX_SECONDS), "max_seconds"),
        "max_usd": positive_number(caps.get("max_usd", DEFAULT_MAX_USD), "max_usd"),
    }
    key = create_key(path)
    return append_event(
        path,
        key,
        [],
        {
            "kind": "start",
            "at_utc": utc_now(),
            "job_id": job_id,
            "bind": bind,
            "caps": checked,
            "cap_source": (
                "MAPTA section 3.3 early stopping thresholds, via "
                "security/research/mapta-multi-agent-pentest.md"
            ),
            "note": note,
        },
    )


# --- what the sandbox calls --------------------------------------------------------


def start_for_job(
    ledger: Path,
    job_id: str,
    caps: dict[str, Any],
    note: str,
    *,
    bind: str,
) -> dict[str, Any]:
    """Open the ledger for a container and tie it to that container's bind token."""
    with job_lock(ledger):
        event = start_ledger(ledger, job_id, caps, note, bind=bind)
    return event


def require_bind(events: list[dict[str, Any]], bind: str) -> None:
    """Refuse a ledger that was not opened for this container.

    The budget used to hang on a job id written in manifest.json and a directory
    named on the command line, both of which an operator can change. Editing either
    one produced a fresh ledger with a fresh budget for the same running container.
    The bind token is generated once, stamped into an immutable Docker label at
    create, and written into the start event. If the two disagree, this is not that
    job's ledger.
    """
    recorded = events[0].get("bind")
    if not recorded:
        raise UsageError(
            "this ledger carries no bind token, so it cannot be matched to a container. It was "
            "opened by hand rather than by 'sandbox create'. Destroy the job and create it again."
        )
    if not hmac.compare_digest(str(recorded), str(bind)):
        raise UsageError(
            "this ledger belongs to a different container. The bind token in the ledger does not "
            "match the one stamped on the container at create. Nothing was run. A budget cannot be "
            "reset by pointing a job at another ledger."
        )


def reserve(
    ledger: Path,
    job_id: str,
    *,
    bind: str,
    kind: str,
    note: str = "",
) -> dict[str, Any]:
    """Take one call out of the budget BEFORE the work runs, or refuse.

    Order matters and this is the whole fix for two separate breaks. Checking, then
    running for hundreds of milliseconds, then recording, let parallel execs all pass
    the same check and blow through the cap. It also meant a job killed during a call
    never counted that call, while the command carried on inside the container. The
    call is written here, under the lock, before docker is touched.
    """
    if kind not in KINDS:
        raise UsageError(f"kind must be one of: {', '.join(KINDS)}")
    with job_lock(ledger):
        events, key, state = evaluate(ledger)
        require_bind(events, bind)
        if state["breached"]:
            state["reserved"] = False
            state["reservation_id"] = None
            return state
        reservation_id = uuid.uuid4().hex
        append_event(
            ledger,
            key,
            events,
            {
                "kind": "record",
                "at_utc": utc_now(),
                "job_id": job_id,
                "event": kind,
                "reservation_id": reservation_id,
                "reserved_before_the_work_ran": True,
                "seconds": None,
                "usd": None,
                "note": note,
            },
        )
        state = latch_breach(ledger, key, events, state_of(events))
        state["ledger"] = str(ledger)
        state["reserved"] = True
        state["reservation_id"] = reservation_id
        return state


def settle(
    ledger: Path,
    job_id: str,
    reservation_id: str,
    *,
    seconds: float | None = None,
    usd: float | None = None,
    note: str = "",
    exit_code: int | None = None,
) -> dict[str, Any]:
    """Attach what the reserved call actually cost. It never adds a second call."""
    with job_lock(ledger):
        events, key, _ = evaluate(ledger)
        known = {str(event.get("reservation_id")) for event in events if event.get("kind") == "record"}
        if reservation_id not in known:
            raise UsageError(f"no reservation {reservation_id} on this ledger")
        append_event(
            ledger,
            key,
            events,
            {
                "kind": "settle",
                "at_utc": utc_now(),
                "job_id": job_id,
                "reservation_id": reservation_id,
                "seconds": None if seconds is None else round(non_negative_number(seconds, "seconds"), 3),
                "usd": None if usd is None else round(non_negative_number(usd, "usd"), 6),
                "exit_code": exit_code,
                "note": note,
            },
        )
        state = latch_breach(ledger, key, events, state_of(events))
        state["ledger"] = str(ledger)
        return state


def record_call(
    ledger: Path,
    job_id: str,
    *,
    kind: str,
    seconds: float | None = None,
    usd: float | None = None,
    note: str = "",
) -> dict[str, Any]:
    """Append one finished call to the ledger and return the state after it."""
    if kind not in KINDS:
        raise UsageError(f"kind must be one of: {', '.join(KINDS)}")
    with job_lock(ledger):
        events, key, _ = evaluate(ledger)
        append_event(
            ledger,
            key,
            events,
            {
                "kind": "record",
                "at_utc": utc_now(),
                "job_id": job_id,
                "event": kind,
                "reservation_id": None,
                "reserved_before_the_work_ran": False,
                "seconds": None if seconds is None else round(non_negative_number(seconds, "seconds"), 3),
                "usd": None if usd is None else round(non_negative_number(usd, "usd"), 6),
                "note": note,
            },
        )
        state = latch_breach(ledger, key, events, state_of(events))
        state["ledger"] = str(ledger)
        return state


# --- commands -----------------------------------------------------------------------


def start_command(args: argparse.Namespace) -> int:
    path = ledger_path(args.workdir, args.job)
    caps = {"max_calls": args.max_calls, "max_seconds": args.max_seconds, "max_usd": args.max_usd}
    with job_lock(path):
        event = start_ledger(path, args.job, caps, args.note or "", bind=args.bind)
    emit(
        {
            "schema_version": SCHEMA_VERSION,
            "command": "start",
            "status": "started",
            "job_id": args.job,
            "caps": event["caps"],
            "cap_source": event["cap_source"],
            "bind": event["bind"],
            "ledger": str(path),
            "key_file": str(key_path(path)),
            "comparison_note": COMPARISON_NOTE,
            "wall_clock_note": WALL_CLOCK_NOTE,
            "integrity_note": INTEGRITY_NOTE,
        }
    )
    return 0


def record_command(args: argparse.Namespace) -> int:
    state = record_call(
        ledger_path(args.workdir, args.job),
        args.job,
        kind=args.kind,
        seconds=args.seconds,
        usd=args.usd,
        note=args.note or "",
    )
    emit(
        {
            "schema_version": SCHEMA_VERSION,
            "command": "record",
            "status": "breached" if state["breached"] else "within_caps",
            **state,
            "exit_code": BREACH_EXIT_CODE if state["breached"] else 0,
        }
    )
    return BREACH_EXIT_CODE if state["breached"] else 0


def check_command(args: argparse.Namespace) -> int:
    path = ledger_path(args.workdir, args.job)
    with job_lock(path):
        _, _, state = evaluate(path)
    emit(
        {
            "schema_version": SCHEMA_VERSION,
            "command": "check",
            "status": "breached" if state["breached"] else "within_caps",
            **state,
            "exit_code": BREACH_EXIT_CODE if state["breached"] else 0,
            "enforcement_note": (
                "This exit code is the enforcement. 3 means the sandbox will refuse to run "
                "anything further for this job until a cap is deliberately raised with "
                "'usage raise', which writes the raise to the ledger."
            ),
        }
    )
    return BREACH_EXIT_CODE if state["breached"] else 0


def raise_command(args: argparse.Namespace) -> int:
    """Raise a cap on purpose, and leave the evidence that it was raised.

    This is the only way past a breach, and it is deliberately loud. It refuses to
    lower a cap, refuses anything that is not a real number, refuses to run without a
    reason, and never touches the breach events already on the ledger. The plan's rule
    is that the parent raises the effort or the cap and records which; doing both
    quietly is how a run drifts into the failure cost profile.

    "nan" used to pass the guard here, because the test was "not greater than the
    current cap" and every comparison against nan is false. A cap of nan is not a
    budget, it is the cap switched off with a paper trail that reads like diligence.
    """
    path = ledger_path(args.workdir, args.job)
    with job_lock(path):
        events, key, _ = evaluate(path)
        caps, _ = caps_from(events)
        wanted = {
            "max_calls": args.max_calls,
            "max_seconds": args.max_seconds,
            "max_usd": args.max_usd,
        }
        asked = {field: value for field, value in wanted.items() if value is not None}
        if not asked:
            raise UsageError("give at least one of --max-calls, --max-seconds, --max-usd")
        if not str(args.reason or "").strip():
            raise UsageError("--reason is required, so the ledger says why the cap moved")
        applied = []
        for field, value in asked.items():
            current = caps[field]
            number = positive_number(value, field)
            if not number > current:
                raise UsageError(
                    f"{field} is already {current}; this command only raises a cap. "
                    "Lowering one, or setting one to a value that cannot be compared, would let a "
                    "breach be hidden by moving the line."
                )
            applied.append(
                append_event(
                    path,
                    key,
                    events,
                    {
                        "kind": "raise",
                        "at_utc": utc_now(),
                        "job_id": args.job,
                        "field": field,
                        "from": current,
                        "to": number,
                        "reason": str(args.reason).strip(),
                    },
                )
            )
        state = latch_breach(path, key, events, state_of(events))
        state["ledger"] = str(path)
    emit(
        {
            "schema_version": SCHEMA_VERSION,
            "command": "raise",
            "status": "raised",
            "applied": applied,
            **state,
            "honesty_note": (
                "The breach events already written stay on the ledger forever. This job "
                "reached a cap and the cap was moved; it was not cheap."
            ),
        }
    )
    return 0


def report_command(args: argparse.Namespace) -> int:
    path = ledger_path(args.workdir, args.job)
    with job_lock(path):
        events = read_events(path)
        state = state_of(events)
    records = [event for event in events if event.get("kind") == "record"]
    by_kind: dict[str, int] = {}
    for event in records:
        key_name = str(event.get("event", "unknown"))
        by_kind[key_name] = by_kind.get(key_name, 0) + 1
    lines = []
    if state["ever_breached"]:
        hit = sorted({str(field) for event in state["breach_events"] for field in event.get("fields", [])})
        lines.append(f"This job breached its caps on: {', '.join(hit)}. That is on the ledger permanently.")
    if state["raises"]:
        lines.append(
            f"A cap was raised {len(state['raises'])} time(s) after the job started. "
            "Read the totals against the raises, not against the original caps."
        )
    if state["unsettled_reservations"]:
        lines.append(
            f"{len(state['unsettled_reservations'])} call(s) were reserved and never settled. That "
            "is a call that started and whose caller did not come back: a kill, a crash, or a "
            "command still running. It is counted against the budget, which is the safe direction."
        )
    if not state["cost_reported"]:
        lines.append(COST_UNREPORTED_NOTE)
    emit(
        {
            "schema_version": SCHEMA_VERSION,
            "command": "report",
            "status": "breached" if state["breached"] else "within_caps",
            **state,
            "calls_by_kind": by_kind,
            "ledger": str(path),
            "key_file": str(key_path(path)),
            "ledger_events": events,
            "plain_reading": lines or ["Within caps, no breach recorded, no cap raised."],
            "exit_code_note": "report is a view and always exits 0. 'check' is the command that enforces.",
        }
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Count tool calls, wall clock and reported cost for one job, and stop it at the caps."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    def add_common(target: argparse.ArgumentParser) -> None:
        target.add_argument("--job", required=True, help="Job id. Must match the sandbox job id.")
        target.add_argument(
            "--workdir",
            type=Path,
            default=DEFAULT_JOBS_DIR,
            help=f"Directory on the host holding job records. Default: {DEFAULT_JOBS_DIR}",
        )

    cap_calls = argparse_type(positive_integer, "--max-calls")
    cap_seconds = argparse_type(positive_number, "--max-seconds")
    cap_usd = argparse_type(positive_number, "--max-usd")

    start = subparsers.add_parser("start", help="Open the ledger for a job and fix its caps.")
    add_common(start)
    start.add_argument("--max-calls", type=cap_calls, default=DEFAULT_MAX_CALLS, help=f"Default: {DEFAULT_MAX_CALLS}")
    start.add_argument("--max-seconds", type=cap_seconds, default=DEFAULT_MAX_SECONDS, help=f"Default: {DEFAULT_MAX_SECONDS}")
    start.add_argument("--max-usd", type=cap_usd, default=DEFAULT_MAX_USD, help=f"Default: {DEFAULT_MAX_USD}")
    start.add_argument("--bind", help="Token tying this ledger to one container. 'sandbox create' sets it.")
    start.add_argument("--note", help="Free text kept with the start event.")
    start.set_defaults(handler=start_command)

    record = subparsers.add_parser("record", help="Append one call to the ledger. Exits 3 if that call breached a cap.")
    add_common(record)
    record.add_argument("--kind", required=True, choices=list(KINDS))
    record.add_argument(
        "--usd",
        type=argparse_type(non_negative_number, "--usd"),
        help="Cost of this call in US dollars, zero or more. Omit it if nothing measured one.",
    )
    record.add_argument(
        "--seconds",
        type=argparse_type(non_negative_number, "--seconds"),
        help="How long this call took. Reported only; no cap uses it.",
    )
    record.add_argument("--note", help="Free text kept with the event.")
    record.set_defaults(handler=record_command)

    check = subparsers.add_parser("check", help="Exit 0 within caps, exit 3 when breached. JSON either way.")
    add_common(check)
    check.set_defaults(handler=check_command)

    raise_parser = subparsers.add_parser(
        "raise",
        help="Deliberately raise a cap and record the raise. The only way past a breach.",
    )
    add_common(raise_parser)
    raise_parser.add_argument("--max-calls", type=cap_calls)
    raise_parser.add_argument("--max-seconds", type=cap_seconds)
    raise_parser.add_argument("--max-usd", type=cap_usd)
    raise_parser.add_argument("--reason", required=True, help="Why the cap is moving. Written to the ledger.")
    raise_parser.set_defaults(handler=raise_command)

    report = subparsers.add_parser("report", help="The whole ledger and the totals.")
    add_common(report)
    report.set_defaults(handler=report_command)
    return parser


def main() -> int:
    try:
        args = build_parser().parse_args()
        return int(args.handler(args))
    except LedgerTampered as error:
        print(f"LEDGER INTEGRITY FAILURE: {error}", file=sys.stderr)
        emit(
            {
                "schema_version": SCHEMA_VERSION,
                "status": "ledger_integrity_failure",
                "error": str(error),
                "exit_code": TAMPER_EXIT_CODE,
                "note": (
                    "The ledger does not verify, so no answer about this job's budget is "
                    "trustworthy and none is given. This is not a within caps answer."
                ),
            }
        )
        return TAMPER_EXIT_CODE
    except (UsageError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        emit({"schema_version": SCHEMA_VERSION, "status": "error", "error": str(error)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
