"""
Plain-assert sanity checks (no pytest dependency) -- run with:
    python tests/test_demo.py
from the project root. Verifies each of the six bundled demo scenarios
produces the expected verdict.
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from jobless_router.engine import JoblessRouterEngine
from jobless_router.firehose import replay_file
from jobless_router.models import RPKIState

FORCED_STATES = {
    "valid": RPKIState.VALID,
    "invalid_asn": RPKIState.INVALID_ASN,
    "invalid_length": RPKIState.INVALID_LENGTH,
    "not_found": RPKIState.NOT_FOUND,
}


def main():
    root = os.path.join(os.path.dirname(__file__), "..")
    engine = JoblessRouterEngine(
        relationships_path=os.path.join(root, "data/sample_as_relationships.txt"),
        watchlist=["1.1.1.0/24"],
        db_dir=":memory:",
    )

    incidents = {}
    for event in replay_file(os.path.join(root, "sample_events.jsonl")):
        label = event.raw.get("_label", "")
        forced = FORCED_STATES.get(event.raw.get("_demo_rpki"), RPKIState.UNKNOWN)
        incident = engine.process(event, forced_rpki=forced)
        key = label.split(":")[0].strip()
        incidents[key] = incident

    # A: clean baseline-establishing route -- must NOT raise an incident
    assert incidents["A"] is None, "Scenario A should be silent (clean, first-seen, RPKI valid)."

    # B: fat-finger
    b = incidents["B"]
    assert b is not None, "Scenario B should raise an incident."
    assert b.intent.label == "LIKELY_FAT_FINGER", b.intent.label
    assert b.complicit_upstream == 3356

    # C: targeted MITM
    c = incidents["C"]
    assert c is not None
    assert c.intent.label == "LIKELY_TARGETED_INTERCEPTION", c.intent.label
    assert c.complicit_upstream == 1299

    # D: poisoning + targeted intercept boost
    d = incidents["D"]
    assert d is not None
    assert d.path_anomaly.kind == "POISONING", d.path_anomaly.kind
    assert d.path_anomaly.suspect_asn == 1299
    assert d.intent.label == "LIKELY_TARGETED_INTERCEPTION", d.intent.label

    # E: blackhole community should override to legitimate-mitigation label
    e = incidents["E"]
    assert e is not None
    assert e.intent.label.startswith("LIKELY_LEGITIMATE"), e.intent.label
    assert any("BLACKHOLE" in tag for tag in e.community_tags)

    # F: baseline-only catch despite RPKI NOT_FOUND (no ROA at all)
    f = incidents["F"]
    assert f is not None, "Scenario F should be caught by baseline deviation even with no RPKI signal."
    assert f.rpki.state == RPKIState.NOT_FOUND

    print("All scenario assertions passed.")


if __name__ == "__main__":
    main()
