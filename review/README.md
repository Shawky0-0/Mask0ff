# review/

A review of mask0ff written from a WordPress focused fork that ran the tool hard over
2026-08-11 and 2026-08-12, plus the probes that back it.

**Nothing in this folder changes any code.** It adds documents and three read only scripts.
Merge it, cherry pick from it, or read it and delete the branch. All three are fine.

| File | What it is |
|---|---|
| `2026-08-13-review-from-a-fork.md` | the review itself |
| `probes/P-001-key-name-probe.py` | the scorer reads the candidate's key names as finding text |
| `probes/P-002-transition-probe.py` | a detected transition means two words appeared, not that a value travelled |
| `probes/P-003-code-citations.txt` | every code citation in the review, as command output |

## Running the probes

They import `scripts/weird_surface.py` from this repository, so they measure your tree rather
than the fork's. They open no network connection, contact no host, start no container and write
no file.

```bash
python review/probes/P-001-key-name-probe.py
python review/probes/P-002-transition-probe.py
```

## The shortest version of the review

A candidate whose values are all empty strings still scores the interpreter factor at 1.0. The
scorer is fed `json.dumps(candidate)`, so the key name `source_sink` is scored as finding text,
and it contains `rce`. That factor carries weight `0.08`, so 8 of the 100 available points have
been awarded to every candidate the tool has ever scored, including one with no content.

That is one defect out of about a dozen, and the review starts instead with what held up under
attack, because more of the tool did than did not.
