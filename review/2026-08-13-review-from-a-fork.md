# Mask0ff: a review from a fork that ran it hard

**For the author, and for whichever agent works on the tool next.** Written 2026-08-13 from a
WordPress focused fork. Everything here is reproducible from the repository alone, and the last
section lists the exact commands.

---

## What this is, and how it was produced

This is not a code read with opinions attached. Over 2026-08-11 and 2026-08-12 the tool was
run against real candidates, given a runtime, attacked deliberately, and reviewed by agents
that did not build any of it. This document is what survived that.

Three things make it worth your time rather than just long:

1. **Every claim has a command.** Where a number appears, the command that produced it is
   named. Three probes written for this document are included at the end and run against your
   `origin/main`, unmodified, with no network and no target.
2. **It contains our own mistakes.** The rule the tool enforces about proof and control caught
   this fork's own flagship finding and marked it optimistic. That is reported here, not hidden.
3. **It separates your code from ours.** Section 5 is about a runtime this fork bolted on. It is
   not your work, it has three known critical defects, and you should read it before deciding
   whether you want any of it.

**The tone is direct because that is more useful than polite.** Nothing here is a criticism of
the method. The method is the reason this fork exists.

---

## 1. The short version

**The engine's judgement is good and its measurement is broken.**

Every rule it has about what counts as evidence held up under attack, including when the attack
was aimed at this fork's own work. Every number it produces was wrong, in the same way, for the
same reason.

Three defects carry most of the weight, and all three are cheap to reproduce:

| # | Defect | One line version |
|---|---|---|
| 1 | The scorer scores the candidate's **key names** | `json.dumps({"source_sink": ""})` contains `rce`, so the interpreter factor fires on an empty candidate and hands out 8 free points |
| 2 | Every keyword match is a plain substring test | `ci` fires inside "specified", `acl` inside "oracle", `file` inside "profile", `root` inside "rootkit" is the one you want to keep |
| 3 | A "semantic transition" is two words appearing in the same blob | A candidate whose own text says its two halves are unrelated scores 54.2 with **four** invented transitions and `high_value_route: true` |

And one sentence that is worth more than the three defects together, from an outside reviewer
who read the tree read only and had no stake in it:

> **"The system confuses a well formed record with an independently true event."**

Section 4 unpacks that. It is the honest ceiling of the current design, and it is not a bug
list.

---

## 2. What holds up, and this is not politeness

Each of these was attacked on purpose. They are listed first because they are the reason the
tool is worth patching rather than replacing.

**1. The evidence rules are right, and they are enforced.** The engine refused to accept a
record where the proof and the controls were the same artifact. That refusal landed on this
fork's own flagship finding, whose page claimed `substantiated` and which the engine scored
`candidate` at **33**. Not because the controls were not run. Because they were saved in one
file with the proof, so nobody else can check them independently. **The engine was right and
the page was optimistic.** Do not soften that rule. It caught real sloppiness twice, once ours.

**2. The state caps the score, so a score cannot be talked upward.** This is the single best
design decision in the tool. Writing a better report cannot buy a higher number. Keep it.

**3. `A0` fails closed on the target, and the refusal names nothing.** Seven cases in the first
pass, then twenty target strings in a later adversarial pass, including
`http://host@evil.example/`, `http://host./`, `http://host.evil.example`, `http://[::1]:8080`
and the protocol relative forms. None reached a host the receipt does not name. Deny by default
is the gate's own behaviour rather than something a receipt has to remember to add. Two real
gaps remain and they are in section 3B, but the core of this is sound.

**4. The engine is honest about its own numbers where its users are not.** It prints
`false_positive_risk`, it prints `score_is_severity: false`, and its calibration line says the
score "does not prove objective truth, novelty, exploitability, or severity by itself". That
line is correct and it is routinely ignored by whoever quotes the number, including us. See
section 3A5 for what to do about that.

**5. `probe_egress` refuses to claim a boundary it did not measure.** It reports
`configured_open` or `configured_closed`, names what it read, and says plainly not to quote it
as proof. That honesty is why the containment gap in section 5 was easy to demonstrate rather
than easy to hide. More of the tool should be written like this function.

---

## 3. Defects, worst first

### 3A. The scorer

#### A1. The scorer reads the JSON key names as if they were finding text. CRITICAL for every number the tool has ever produced.

`run()` does this:

```python
text = json.dumps(candidate, ensure_ascii=False)
```

So the text being scored includes `"component"`, `"entry_point"`, `"source_sink"`,
`"primitive"` and `"impact"`, on every candidate, always. Combine that with the substring
matcher in A2 and one keyword lands for free:

**`INTERPRETER_WORDS` contains `rce`. The key name `source_sink` contains the letters `r`, `c`,
`e` in sequence, inside the word "source".**

Measured, running your unmodified `origin/main`:

```
--- A benign layout bug: "the play button sits two pixels too low"
    factors : {'C': 0.6, 'M': 0.0, 'X': 0.0, 'P': 0.0, 'G': 0.0, 'D': 0.0,
               'I': 1.0, 'A': 0.0, 'F': 0.0, 'N': 0.5}
    which interpreter words matched: ['rce']

--- Every value empty, only the key names remain
    factors : {'C': 0.6, ... 'I': 1.0, ...}
    which interpreter words matched: ['rce']
```

`I` carries weight `0.08`. **So 8 of the 100 available points were awarded unconditionally to
every candidate the tool has ever scored, including a candidate with no content at all.** The
interpreter factor has never once measured what it was written to measure.

It costs one word to find and it invalidates every historical number. The probe that produced
this is `review/probes/P-001-key-name-probe.py`, and it runs against your own tree.

**The fix is two changes, and both are small:**

* Score the field **values**, not `json.dumps` of the whole object. Join the fingerprint fields
  the way `novelty()` already does, which is the correct pattern and already in the file.
* Match on word boundaries, per A2.

Either one alone kills this. Both together is right.

#### A2. Every keyword test is a plain substring test.

Two functions, same shape:

```python
def role_matches(text, keywords):
    lowered = text.lower()
    return [keyword for keyword in keywords if keyword in lowered]

def factor(text, words):
    lowered = text.lower()
    return 1.0 if any(word in lowered for word in words) else 0.0
```

Short keywords fire inside unrelated words. All checked, none guessed:

| Keyword | Role | Ordinary words that trigger it |
|---|---|---|
| `ci` | `WORKFLOW_INSTRUCTION` | specified, decision, precision, social, capacity |
| `acl` | `AUTHORIZATION_INPUT` | oracle, miracle, obstacle |
| `arg` | `COMMAND_ARGUMENT` | target, large, charge |
| `tar` | `FILESYSTEM_OBJECT` | start, target, startup |
| `file` | `FILESYSTEM_OBJECT` | profile |
| `row` | `STORED_DATA` | browser, throw, grow |
| `ini` | `CONFIGURATION` | initial, administrator, definition |
| `raw` | `RAW_DATA` | drawn, drawing |
| `tag` | `METADATA` | advantage, stage, vintage |
| `path` | `PATH_COMPONENT` | sympathy, pathology |
| `rce` | interpreter factor | source, resource, and the key name `source_sink` |

**Note the direction of this failure. It does not miss things. It invents them, and the
invented pair prints with the same confidence as a real one.**

**The suggested fix is one line:**

```python
return [k for k in keywords if re.search(r"\b" + re.escape(k) + r"\b", lowered)]
```

Multi word keywords like `function call` and `query string` still work. Only the fragments
change behaviour, and every one of those changes is a fix.

**Now the part that cost this fork four rounds, so you do not repeat it.** A pure word boundary
rule is a **narrowing**. Across 175 keywords and roughly 30 generated forms each, 1,697 forms
matched before and did not match after, and **zero** matched after that did not match before.
That direction is safe in one sense: the change cannot create a new false positive. But it
takes real security vocabulary with it. Measured regressions include `canonical` losing
"canonicalization", `shell` losing "shellcode", `root` losing "rootkit", `cron` losing
"crontab", `parameter` losing "parameterized" and `insert` losing "insertion". Two realistic
findings lost 19.0 and 10.0 points.

The fix that worked in this fork was **a bounded list of real word endings** rather than "any
trailing letters": `upload` plus `ed` is an inflection, `path` plus `ological` is not. That
kills seven of the ten worst false positives while keeping `exec` reaching "executed". It is
still a trade, not a free win, and it is a dictionary problem underneath. Take the one line
first. Treat the ending list as optional.

#### A3. A "semantic transition" is two words in the same blob, not a value that travels.

This is the architectural one, and no keyword list fixes it.

`detected_transitions()` collects which roles matched anywhere in the text, then emits a
transition for **every source role paired with every target role**. There is no check that the
source and the target are the same value, in the same sentence, or connected at all.

Measured, running your unmodified `origin/main`, on a candidate that states in its own text
that its two halves are unrelated and that no impact is claimed:

```
score               : 54.2
transitions invented: 4
    STORED_DATA        -> TEMPLATE_DATA      on keywords ['template']
    STORED_DATA        -> MODULE_IDENTIFIER  on keywords ['plugin']
    FILESYSTEM_OBJECT  -> TEMPLATE_DATA      on keywords ['template']
    FILESYSTEM_OBJECT  -> MODULE_IDENTIFIER  on keywords ['plugin']
high_value_route    : True
```

A blind reviewer in this fork put it in one sentence that is worth carrying into the code as a
comment:

> **"The score has no idea whether the value at the source ever reaches the target. It only
> checks that both words appear somewhere in the same six fields."**

**What this means in practice.** After four rounds of matcher fixes in this fork, a brand new
junk candidate (a video player display bug with no security content) still scored **71.2** with
eight invented transitions, outranking a real remote code execution at **70.4**. The rounds did
help: pairwise ordering on the named suite went from 0.600 to 0.750, precision at the top six
from 3 of 6 to 4 of 6, and one fake that used to sit at rank 2 fell to rank 7. But the ceiling
did not move, because the ceiling is not made of keywords.

**The honest conclusion: matching keywords against prose has a ceiling and the tool is at it.**
Every fix from here trades one error class for another. What the scorer is trying to detect,
whether a value changes meaning and gains authority, is not a property of the words in a
description. It is a property of the system being described.

**Two ways forward, and the second is the interesting one:**

1. **Accept it as a rough queue sorter and say so in the output.** Rename the number in the
   interpretation block to something that cannot be read as a measurement, and document the
   real, measured bar: it moves a real remote code execution into the top few candidates most
   of the time, and it does not reliably beat every junk note. This is nearly free.
2. **Make the operator state the one fact that decides the answer.** Add a small closed field
   to the fingerprint rather than guessing it from prose. See A4, which is the same idea applied
   to the gap that matters most.

Do not delete the scorer. It still narrows a large candidate pool faster than reading all of it
by hand. Stop asking it to be a ranker.

#### A4. `AGENT_INSTRUCTION` and `MODEL_CONTEXT` exist in the paper and in no code, and a keyword list cannot add them.

`grep -rn "AGENT_INSTRUCTION\|MODEL_CONTEXT" .` returns nothing.

The closest available target is `TOOL_ARGUMENT`, whose keywords are `tool`, `function call`,
`mcp`, `agent`, `api call`. **It is not the same thing, and the difference is not cosmetic:**

* **`TOOL_ARGUMENT`**: attacker text becomes a parameter handed to something that then acts.
  The authority belongs to the executing component.
* **`AGENT_INSTRUCTION`**: attacker text becomes an order the model obeys, and nothing executes.
  The authority belongs to the model's own answer, because something downstream treats that
  answer as a decision.

Filing the second as the first sends the reader hunting for an execution primitive that does not
exist. They then either invent one or drop a real finding.

**Why a keyword list will not fix it.** Consider two systems described in almost identical
language:

| | System A | System B |
|---|---|---|
| What happens | user text reaches a model prompt, the model summarises a document, a person reads the summary | user text reaches a model prompt, the model marks an assessment, the mark is written to a database as the institution's result |
| Description keywords | prompt, model, user input, stored | prompt, model, user input, stored |
| Severity | annoying at worst | a real integrity failure |

Identical keywords, completely different findings. What separates them is what happens to the
model's output afterwards, and no word in the description reports that.

**Concrete proposal.** Add one explicit field to the candidate fingerprint and derive the role
from it:

```json
"model_output_consumer": "stored_as_decision"
```

with a small closed set, for example `stored_as_decision`, `parameterises_tool_call`,
`shown_to_user`, `none`. Then `stored_as_decision` implies `AGENT_INSTRUCTION`,
`parameterises_tool_call` implies `TOOL_ARGUMENT`, and `shown_to_user` implies neither and
should probably lower the score rather than raise it.

This keeps the scorer honest: the operator states the fact that decides the severity instead of
the tool guessing it from prose. It fits the existing design, where the fingerprint is a small
set of named fields and the scorer reads them. `MODEL_CONTEXT` fits the same pattern as an
intermediate role, for cases where the data reaches the context window but its consumer is not
yet known.

#### A5. Small, cheap, and currently undocumented

* **The reachable range is 10.8 to 96.4, not 0 to 100.** `X` caps at `0.7` while carrying weight
  `0.12`, and `C` never drops below `0.6`. Worth one comment in the file, because a reader
  calibrating against 100 is calibrating against a number the code cannot produce.
* **`high_value_route` reduces to "any transition was detected".** It is
  `bool(transitions and factors["I"])`, and per A1 `factors["I"]` is `1.0` on every candidate.
  Fixing A1 makes this flag meaningful again, which is a second reason to fix A1.
* **`AUTHORIZATION_INPUT` is defined and can never appear in a transition.**
  `detected_transitions()` iterates sources over five roles and targets over nine, and
  `AUTHORIZATION_INPUT` is in neither tuple. It matches, it lands in the internal hits
  dictionary, and it goes nowhere. For a tool whose largest real category is broken
  authorisation, that is a strange role to leave dead. Either add it to the source tuple or
  delete it so it stops implying coverage.
* **Four role vocabularies exist and no two agree.** The paper declares 13 edge labels,
  `weird_surface.py` declares a different 15, `security_graph.py` a third list including
  `CLASS_IDENTIFIER` and `COMMAND_PROGRAM`, and `references/semantic-discovery.md` a fourth.
  Only six names appear in more than one. Some are near synonyms (`TEMPLATE_DATA` for
  `TEMPLATE_SOURCE`, `BUILD_INSTRUCTION` for `BUILD_INPUT`), which is worse than a clean
  difference, because a reader assumes they are the same thing. **Pick one canonical list and
  have the others import it.**
* **`references/semantic-discovery.md` line 45 documents an example the tool cannot produce**:
  `METADATA -> CLASS_IDENTIFIER`. `CLASS_IDENTIFIER` is not one of `weird_surface.py`'s roles.
  A new operator runs the command, does not see it, and goes looking for what they did wrong.

### 3B. The authorisation gate

The gate is the best part of the tool and these are the three things wrong with it. All three
were verified by reading `scripts/authorization_gate.py` and by running it.

#### B1. `--now` widens authorisation, on three entry points. HIGH.

`--now` is a deliberate feature for deterministic evaluation, and it is handed straight to the
validity window check:

```
authorization_gate.py:128   parser.add_argument("--now", ...)
authorization_gate.py:138   now_value=args.now,
authorization_gate.py:65    now = parse_date(now_value) if now_value else evaluation_time
authorization_gate.py:70    if end and now and now > end: errors.append("authorization window has expired")
evidence_bundle.py:539      authorize.add_argument("--now", ...)
evidence_bundle.py:574      verify.add_argument("--now", ...)
```

Measured directly, one receipt that expired on 2026-07-31:

```
mask0ff auth <expired receipt> --target <authorised host> --action http-get
  without --now                        -> blocked, "authorization window has expired"
  with --now 2026-07-15T12:00:00+00:00 -> pass, no errors
```

**And the record it writes carries the fake clock as if it were real.** `validated_at_utc` is
set to the overridden value, and no field anywhere says an override was supplied. So the
artifact that outlives the run looks authentic. A reader would have to compare it against the
file's own modification time to notice.

In this fork the same flag on a runner sent three real HTTP requests against an expired receipt
while reporting `authorization: pass`. No harm resulted, because the requests went to a host the
receipt had authorised anyway. **The mechanism is the problem: a stale receipt plus a debugging
flag is enough to send unauthorised traffic, from the component whose first job is to refuse.**

**Suggested fix, and it is a design decision rather than a patch, which is why it was not
applied here.** Either the override moves the clock for everything **except** the validity
window, or supplying it is recorded prominently in the verdict and the gate refuses whenever the
override changes the outcome. **`--now` must never widen authorisation.** Deleting it is the
smallest safe option, at the cost of your own test determinism.

#### B2. `A0` ignores the port. MEDIUM.

```python
def target_values(target):
    values = {target.lower().strip()}
    parsed = urlparse(target if "://" in target else f"https://{target}")
    if parsed.hostname:
        values.add(parsed.hostname.lower())
    return values
```

`parsed.hostname` drops the port. So a receipt naming `localhost` authorises `localhost:9999`.
A receipt is a document about what you are allowed to touch, and a different port is usually a
different service.

Related, and it is the same function: because the **full target string** is also matched with
`fnmatch`, a receipt pattern containing a wildcard can match the whole URL including the
userinfo part. Reading the parsed hostname is what makes `http://authorised-host@evil.example/`
fail. Reading the raw string is what could let it pass with a careless pattern. Consider
matching only on parsed components, and requiring a port.

#### B3. An unnamed action rides an allowed group. MEDIUM.

```python
exact_allowed = normalized_action and normalized_action in allowed
group_allowed = normalized_group and normalized_group in allowed_groups
if not exact_allowed and not group_allowed:
    errors.append(...)
```

An action nobody wrote down passes as long as its declared `action_group` is allowed. In this
fork a scenario declaring the action `port-scan-every-service` passed `A0` because its group was
`local-lab`. Since the caller supplies both the action and its group, the group is not an
independent check on the action.

**Suggested fix:** require the exact action when one is supplied, and treat the group as a
narrowing rather than an alternative.

### 3C. Packaging, cheap and worth doing

* **`scripts/mask0ff.cmd` forwards `%*` to Python, and `cmd.exe` parses the line first.** An `&`
  inside a quoted argument becomes a real host command separator. Proven by running: text meant
  for a container printed on the Windows console instead, and a command that **failed** inside
  the container came back as **exit 0** by the same mechanism. **Windows only.** `mask0ff.sh`
  uses `exec ... "$@"`, which preserves argument boundaries exactly, and `mask0ff.ps1` splats an
  array. Only the `.cmd` wrapper is affected. This fork fixed it with a canary token: a mangled
  line is refused with exit 126 and nothing runs. The smaller and safer option is to delete the
  `.cmd` wrapper and tell Windows users to call `mask0ff.py` directly.
* **The repository root has no `.gitignore`**, and running the scripts creates
  `scripts/__pycache__/`. One `git add -A` puts Python bytecode in a commit. Two lines fixes it.
  One warning from doing this in the fork: a pattern broad enough to catch every evidence bundle
  (`*-bundle/`) also caught `assets/evidence-bundle/`, your own template directory, covering ten
  tracked files including the `finding-record.json` template. Nothing broke, because git does not
  untrack what is already tracked, but delete and re add any of them and they vanish silently.
  **The safe rule is placement, not pattern:** write bundles outside the repository.

---

## 4. The one thing worth more than the whole bug list

Found by an outside reviewer, from a different vendor's model family, reading the tree read only
with no stake in the answer. Both claims were verified afterwards by reading the code, and both
hold.

> **"The system confuses a well formed record with an independently true event."**
>
> **"This is an impressive evidence formatting system, but it is not yet an evidence trust
> system. More agents from the same session can make the formatting look increasingly rigorous
> while preserving the same mistaken premise."**

Here is the concrete shape of it. The same person or agent writes the receipt, the scenario, the
target relation, the artifact files, the validator owner names and the evidence ids. **The code
checks those claims against each other. It cannot establish that any one of them is true.** Even
"independence" is currently two different strings not being equal.

That is not a defect to patch. It is the boundary of what the current design can promise, and
the tool would be stronger for saying so out loud. Three suggestions, cheapest first:

1. **Say it in the output.** One line in the interpretation block: this record is internally
   consistent, and internal consistency is not independent verification. The engine already
   does this well for the score. Do it for the record.
2. **Mark which fields are attested and which are asserted.** The receipt hash is attested. The
   claim that a validator was a different party is asserted by the party writing the record.
   A reader cannot currently tell those apart, and the format could tell them.
3. **Make one relation machine checkable.** The highest value candidate is in section 5A: bind
   the control and the proof to the same named resource. That single field turns one of the
   asserted relations into a checked one.

**And a category error in the usage caps, from the same reviewer.** The caps count container
`exec` calls and wall clock seconds. Three HTTP calls count as three. **The tokens spent by the
agents doing the work never enter the ledger at all**, and the dollar cap cannot bind unless a
caller supplies a cost, which nothing does. So "enforced usage caps" means enforced execution
count and wall time, and nothing about model spend. That is fine, and the header says so
honestly, but the phrase "usage caps" reads as the other thing.

---

## 5. If you take our runtime, here is exactly what you inherit

This fork built three new files on branch `ahmed-wordpress`, because the engine could judge
evidence and could not produce any:

| File | Lines | What it does |
|---|---|---|
| `scripts/sandbox.py` | 1244 | a per job container with a docker network and teardown |
| `scripts/usage_tracker.py` | 1212 | a call, time and cost ledger with per line HMAC |
| `scripts/run_assessment.py` | 945 | one command: authorise, create, request, judge, write a bundle |

It works. One command against a local WordPress container produced exit 0, verdict
`bypassable`, and a bundle the engine scored `substantiated` at **47**, against **33** for the
same finding filed by hand.

**Do not take it as it stands.** An adversarial reviewer who did not build it found three
critical defects, all still open. They are ours, not yours, and this is the honest accounting.

### 5A. CRITICAL. The verdict never checks that the control and the proof concern the same resource.

Nothing requires it. The verdict becomes `bypassable` when **any** control step returned a non
2xx without the marker and **any** proof step returned 2xx with the marker. The reviewer wrote a
two step scenario on the first try:

```
control: HEAD /this-path-never-existed-and-gates-nothing   (WordPress issued its ordinary
                                                            trailing slash redirect, 301)
proof:   GET  /                                            (the public home page, 200,
                                                            containing the string "wp-content")
```

Result: exit 0, verdict `bypassable`, and the engine scored the fabricated bundle
`substantiated`, **47**, moderate, **identical component for component to the real finding**.

**Until that relation is required and checked, the word "bypassable" means "two unrelated
requests behaved differently", and the reason string should say that instead.** The fix is a
mandatory stable resource identifier, or a scenario declared pairing that the runner verifies.

This is also the single most valuable thing to fix in the whole document, because it is the one
place where an asserted relation could become a checked one. See section 4.

### 5B. CRITICAL. The target can forge the status the runner records.

`split_response` keeps peeling header blocks off the response while what remains starts with
`HTTP/`, then reads the **last** block. The body is content the system under test controls. A
target that serves a body beginning with a fake status line makes the runner record a status the
server never sent.

Proven as a pure function test, no request sent: a real `200 OK` whose body begins with
`HTTP/1.1 403 Forbidden` is recorded as **403**, with the forged headers, and it satisfies the
control expectations in the shipped scenario.

**This is worse than 5A because it needs nothing from the operator**, and it pushes the error in
the dangerous direction: it turns "served" into "refused", which is the half that manufactures a
finding. **The fix:** take the status from `curl --write-out` on a separate stream, or read
`blocks[0]` and skip only 1xx.

### 5C. CRITICAL. Containment is a default, not a control.

`--network` is a free text argument with a default. Nothing checks that the chosen network is
internal. `sandbox.py` records the egress state honestly and proceeds regardless, the runner
prints it, and **the bundle records neither the network nor the egress state**. `docker network
ls` includes `host`. **The fix:** refuse to start when `probe_egress` reports `configured_open`
unless an explicit flag was given, reject `host` and `none` by name, and write the network and
the egress verdict into the finding record.

### 5D. Three more, lower severity, all worth knowing

* **Exit code 2 is ambiguous.** `AUTHORIZATION_BLOCKED_EXIT_CODE` is 2, and argparse also exits
  2 on any bad argument. A typo in a flag name is indistinguishable from "the gate refused".
  Anything that reads exit codes to decide whether the gate works can be fooled by a
  misspelling. Move the block to a code argparse does not use, and assert on the JSON status.
* **The negative verdict overclaims.** A finished run returns the flat word `not_bypassable`.
  What was established is "this one anonymous GET did not return the marker". The runner can
  express exactly one shape: an unauthenticated GET or HEAD, no session, no POST, proof visible
  as a literal string in the body. That rules out login flows, most access control bugs, header
  leaks, redirects to signed URLs, SSRF, timing and races. **Rename the verdict to carry its own
  scope** and state the method boundary in the summary.
* **A bare receipt entry authorises two ports, not one.** The default port is derived from the
  **target's** scheme rather than the entry's, so `example-host` covers port 80 for an `http`
  target and 443 for an `https` one. Derive it from the entry, or refuse bare entries.

### 5E. What 47 actually means, and it is not what we first wrote

The fork's own note presented "substantiated, 47 against 33 by hand" as the measured answer to
"was this worth it". The number cannot carry that weight, and the engine is more honest about it
than we were:

* `false_positive_risk` on that record is **medium**. The engine says so and the note did not
  repeat it.
* `repeat_independence` is **0** and `adversarial_validation_independence` is **0**. Those are
  15 and 25 of the 100 available. They are zero because the run happened once, by one tool, with
  no second party. **So 47 is close to the ceiling for anything a single unrepeated run can
  produce.**
* The rise from 29 to 39 to 47 came from the runner writing its own `claims` and its own `B1`
  gate. **No new observation entered the record.** The tool asserted more about itself.

The correct framing is "the same evidence, better bookkeeping". Never cite the score without
`false_positive_risk` and the two zero components beside it. Your own calibration line already
says this; it just needs to be printed next to the number rather than below it.

---

## 6. What is worth doing, ranked

| # | Change | Cost | Why now |
|---|---|---|---|
| 1 | **Word boundary matching in `role_matches` and `factor`** | one line each | Removes an entire class of wrong output. Free |
| 2 | **Score the field values, not `json.dumps(candidate)`** | a few lines | Kills the `source_sink` contains `rce` defect at the root, and makes `high_value_route` meaningful again |
| 3 | **Fix the `METADATA -> CLASS_IDENTIFIER` example in `semantic-discovery.md`** | one line | It sends new operators hunting for a bug that is not theirs |
| 4 | **Decide what the `weird` score is for, and write it in the interpretation block** | a decision plus one line | If it is a rough queue sorter and everyone knows it, it is fine as it stands. If anything downstream treats it as a measurement, it needs replacing rather than patching |
| 5 | **Make `--now` unable to widen authorisation** | a design decision, then small | The only one here with a safety consequence |
| 6 | **Add `AUTHORIZATION_INPUT` to the source tuple, or delete the role** | a few lines plus a decision | It currently implies coverage that does not exist |
| 7 | **Require the exact action, and make the port explicit, in `A0`** | small | Two gaps in the best part of the tool |
| 8 | **A `.gitignore`, and fix or delete `mask0ff.cmd`** | minutes | Housekeeping, and one of them is a Windows command injection |
| 9 | **Reconcile the four role vocabularies onto one canonical list** | an afternoon | Cosmetic today, structural once anything else consumes the names |
| 10 | **Add `model_output_consumer` to the fingerprint and derive `AGENT_INSTRUCTION` from it** | a design decision, then small | The only route to the two roles the paper has and the code does not |

**Keep the evidence rules exactly as they are.** They are the reason the tool is worth using.

## What is not worth doing

* **Do not keep patching the matcher past the one line fix.** Four rounds in this fork, each one
  correct on its own terms, and a fresh junk note still outranks a real remote code execution.
  Each round trades one error class for another. The next round buys less than the last one did.
* **Do not add plural forms to the role tables by hand.** It is a list that can never be
  finished, and it makes the vocabulary problem worse rather than better.
* **Do not treat the score as a ranker in anything downstream.** Not because it is bad, but
  because it is measuring word presence and being read as measuring risk.

---

## 7. What this review did not check

Stated plainly, because a review that does not say what it skipped is a claim about everything.

* **The measurements taken inside the fork, as opposed to the ones taken here.** The ranking
  numbers in A2 and A3 (the 1,697 narrowed forms, the 40 regressed probes, 71.2 against 70.4,
  the pairwise ordering moving 0.600 to 0.750) were measured on the fork's own modified copy of
  `weird_surface.py`, not on yours. They describe what happened when the fixes were tried. They
  are not claims about your tree.

  **What was checked against your tree is checked properly.** Everything in `P-001`, `P-002` and
  `P-003` was run against `main` at `4907158` on 2026-08-13, which was your head at the time of
  writing. The probes import `scripts/weird_surface.py` from the repository itself, so re running
  them after you move is one command each.
* **`assess_finding.py`, `verify_finding.py` and `evidence_bundle.py` internals**, beyond the
  score arithmetic and the `--now` arguments cited above.
* **The corpora.** `references/techniques/`, the advisory database and the case database were
  used, not audited. One data gap was found and fixed locally: the `OWASP-AGENTIC-2025` signals
  did not match ordinary chat assistant vocabulary, so that corpus was unreachable for exactly
  the target type it exists for. Adding `chat, assistant, chatbot, rag, retrieval, grounded` to
  its signals fixed the routing. That is a data edit on your file, so it is reported rather than
  proposed as a patch.
* **`program_profile.py`, `race_condition.py`, `triage_report.py`** and the rest of the larger
  scripts. Not read.
* **Anything on Linux or macOS.** Every run was Windows 11, Python 3.12.10, Docker 29.6.2.
* **Whether the runtime defects in section 5 also exist upstream.** They are in files this fork
  wrote, so probably not, but nobody checked the equivalent paths in your code.

---

## 8. How to reproduce everything

Read only. No network, no target, no container. All from the repository root.

```bash
# the three probes shipped with this review. They import scripts/weird_surface.py
# from this repository, so they measure your tree, not the fork's.
python review/probes/P-001-key-name-probe.py    # the key name defect, A1
python review/probes/P-002-transition-probe.py  # invented transitions, A3
cat    review/probes/P-003-code-citations.txt   # every code citation, as command output

# the substring matcher, A2
sed -n '61,63p'  scripts/weird_surface.py     # role_matches
sed -n '92,94p'  scripts/weird_surface.py     # factor
sed -n '51p'     scripts/weird_surface.py     # INTERPRETER_WORDS, note "rce"

# the key names being scored, A1
grep -n 'text = json.dumps(candidate' scripts/weird_surface.py

# the dead role and the transition tuples, A3 and A5
sed -n '66,89p'  scripts/weird_surface.py

# the vocabulary mismatch, A5
grep -rn "AGENT_INSTRUCTION\|MODEL_CONTEXT" .   # returns nothing
sed -n '18,34p'  scripts/weird_surface.py       # the 15 roles
sed -n '15p'     scripts/security_graph.py      # a third list
sed -n '45p'     references/semantic-discovery.md   # the impossible example

# the authorisation gate, B1 to B3
sed -n '128p;138p' scripts/authorization_gate.py    # --now, accepted and passed on
sed -n '62,71p'    scripts/authorization_gate.py    # --now reaching the window check
sed -n '539p;574p' scripts/evidence_bundle.py       # --now on both subcommands
sed -n '25,35p'    scripts/authorization_gate.py    # target_values drops the port
sed -n '96,102p'   scripts/authorization_gate.py    # group_allowed as an alternative

# the Windows wrapper, 3C
tail -3 scripts/mask0ff.cmd                          # the unquoted %* forward
```

The fastest single demonstration of the substring behaviour: put the word **specified** into any
candidate field and watch `WORKFLOW_INSTRUCTION` appear.

---

## 9. Process notes, offered because they cost real time to learn

Not about your code. About working on a tool like this with agents, which is presumably how the
next round happens for both of us.

**1. The blind red agent earned its cost every single time.** Every component built in this fork
had a blocking or serious defect found by the agent that did not write it, and not one of those
defects was found by the agent that did. Not once. Make the adversarial pass its own step, not
an instruction inside the build step.

**2. The docstring said the right thing and the code did something else. Three times.** One
runner's own documentation stated the correct rule for when a finding counts. Its code checked a
field that was trivially true. A reviewer reading the file would have nodded and moved on.
**Documentation is not evidence, and a comment describing a check is not a check.**

**3. A brief is not evidence, even when you wrote it.** This fork reported a race condition in
its own usage meter, measured it, wrote it down as fact, and briefed an agent to fix it. There
was no race. The test had set a cap after the ledger was already open at the default, so six
parallel calls ran against a cap of forty rather than two. **The agent refused the brief**, and
its reason is the standard to hold to: *"Writing one would have meant reporting a repair to
something I could not show broken."* It then found a real defect by applying the pressure
anyway: a Windows lock file in delete pending state raises `PermissionError`, not
`FileExistsError`, which escaped the retry loop three times in 272 contended acquisitions.

**4. "It parses and `--help` exits 0" is not "it works".** A build passed five `--help` checks
and `ast.parse` while crashing on every real run. An interrupted edit leaves half
implementations: a flag deleted from argparse with its reader left behind, a signature changed
with its call site on the old form, a field deleted with the exit code still requiring it. All
three are invisible to a syntax check and obvious on one real scenario.

**5. A size budget in a prompt does not work.** One brief said "under 600 lines, and if it is
longer you are building too much". It shipped at 945 with a reasonable sounding excuse about
comments. What does work is a reviewer step that runs next, because an agent that knows a
reviewer is coming writes differently from one told to be tidy.

**6. Write intermediate artifacts to disk before reporting them.** One agent lost its entire
return value to a network drop. Its work survived completely, because it had written its file
first.

---

## The one sentence to keep

**The engine is an evidence discipline that happens to ship a scorer, and the discipline is the
valuable half.** Every rule it has about what counts as proof held up under attack, including
against its owner's own flagship finding. Every number it produced was wrong. Use the rules,
distrust the numbers, and say which is which when citing it.
