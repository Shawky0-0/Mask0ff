#!/usr/bin/env python3
"""P-001. Does the scorer read the candidate's KEY NAMES as finding text?

Run it from anywhere:  python review/probes/P-001-key-name-probe.py
It imports scripts/weird_surface.py from this repository. It is read only:
no network, no target, no container, no file written.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
import weird_surface as w  # noqa: E402

BENIGN = {
    "component": "video player",
    "entry_point": "the settings screen",
    "source_sink": "not applicable",
    "primitive": "layout defect",
    "impact": "the play button sits two pixels too low on small screens",
}

EMPTY_VALUES_ONLY = {
    "component": "",
    "entry_point": "",
    "source_sink": "",
    "primitive": "",
    "impact": "",
}


def report(name, candidate):
    text = json.dumps(candidate, ensure_ascii=False)
    wss, factors = w.weird_surface_score(text)
    print(f"--- {name}")
    print(f"    text scored : {text}")
    print(f"    score       : {wss}   (N held at its 0.5 placeholder here)")
    print(f"    factors     : {factors}")
    print(f"    I factor    : {w.factor(text, w.INTERPRETER_WORDS)}")
    print(f"    matched by I: {[x for x in w.INTERPRETER_WORDS if x in text.lower()]}")
    print()


print(f"repo under test : {REPO}")
print(f"scorer          : {REPO / 'scripts' / 'weird_surface.py'}")
print("=" * 72)
report("A benign layout bug, standard fingerprint keys", BENIGN)
report("Every VALUE is an empty string. Only the key names remain.", EMPTY_VALUES_ONLY)

probe = json.dumps({"source_sink": ""})
print("The whole thing in four lines:")
print(f"  json.dumps({{'source_sink': ''}})  = {probe}")
print(f"  'rce' in that string              = {'rce' in probe.lower()}")
print(f"  so factor(...) -> I               = {w.factor(probe, w.INTERPRETER_WORDS)}")
print(f"  and I is weighted                 = {w.WSS_WEIGHTS['I']}"
      f"  ({w.WSS_WEIGHTS['I'] * 100:.0f} points of 100, awarded to every candidate)")
print()
print("Cause: run() scores json.dumps(candidate), so the KEY NAME 'source_sink'")
print("is scored as finding text, and it contains the letters r, c, e in sequence.")
