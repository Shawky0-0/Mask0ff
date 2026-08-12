#!/usr/bin/env python3
"""P-002. Does a detected "semantic transition" mean a value travelled?

Run it from anywhere:  python review/probes/P-002-transition-probe.py
It imports scripts/weird_surface.py from this repository. It is read only:
no network, no target, no container, no file written.
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))
import weird_surface as w  # noqa: E402

# Two facts about one site that have nothing to do with each other.
# The candidate says so in its own text.
UNRELATED = {
    "component": "a photo gallery plugin",
    "entry_point": "members upload a profile photo, which is stored in the media library",
    "source_sink": "unrelated to the above: the theme ships a template for the footer",
    "primitive": "none, these are two separate observations about one site",
    "impact": "no impact is claimed, this candidate is a deliberate control",
}

text = json.dumps(UNRELATED, ensure_ascii=False)
wss, factors = w.weird_surface_score(text)
transitions = w.detected_transitions(text)

print(f"repo under test : {REPO}")
print(f"scorer          : {REPO / 'scripts' / 'weird_surface.py'}")
print("=" * 72)
print("A candidate that states, in its own words, that its two halves are unrelated")
print("and that no impact is claimed:")
print()
print(json.dumps(UNRELATED, indent=2, ensure_ascii=False))
print()
print(f"score                : {wss}   (N held at its 0.5 placeholder here)")
print(f"factors              : {factors}")
print(f"transitions invented : {len(transitions)}")
for t in transitions:
    print(f"    {t['from']:20s} -> {t['to']:24s} on keywords {t['keywords']}")
print()
print(f"high_value_route     : {bool(transitions and factors['I'])}")
print()
print("Cause: detected_transitions() collects which roles matched ANYWHERE in the")
print("text, then emits every source role paired with every target role. Nothing")
print("checks that the source and the target are the same value, in the same")
print("sentence, or connected at all. See also P-001: factors['I'] is 1.0 on every")
print("candidate carrying the key 'source_sink', so high_value_route reduces to")
print("'at least one transition was detected'.")
