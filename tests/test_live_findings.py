"""
Regression test for a real false positive found while testing against the
actual live RIPE RIS Live feed: Cloudflare's own legitimate, RPKI-VALID
announcement of 1.1.1.0/24 / 1.0.0.0/24 got labeled LIKELY_TARGETED_INTERCEPTION
because a never-before-seen (but completely normal, anycast) upstream
tripped baseline novelty, and the heuristic scorer never checked RPKI
validity at all before assigning MITM points.

Run with: python tests/test_live_findings.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from jobless_router.engine import JoblessRouterEngine
from jobless_router.models import AnnouncementEvent, RPKIState


def test_rpki_valid_suppresses_anycast_false_positive():
    engine = JoblessRouterEngine(
        relationships_path=os.path.join(os.path.dirname(__file__), "..", "data", "sample_as_relationships.txt"),
        watchlist=["1.1.1.0/24"],
        db_dir=":memory:",
    )

    # First sighting: 1.1.1.0/24, origin 13335 (Cloudflare), via upstream 6939.
    # Establishes baseline. RPKI VALID. Must not be flagged (first sighting
    # is exempt from novelty anyway).
    e1 = AnnouncementEvent(
        timestamp=1, collector="rrc01", peer_asn="6939",
        prefix="1.1.1.0/24", as_path=[6939, 13335], communities=[],
    )
    incident1 = engine.process(e1, forced_rpki=RPKIState.VALID)
    assert incident1 is None, "First sighting of a valid route must stay silent."

    # Second sighting: SAME prefix, SAME legitimate origin, but a brand new
    # upstream (52873) -- completely normal anycast/multi-homing behavior.
    # RPKI still VALID. This is the exact shape that produced the false
    # positive against real Cloudflare traffic.
    e2 = AnnouncementEvent(
        timestamp=2, collector="rrc15", peer_asn="52873",
        prefix="1.1.1.0/24", as_path=[52873, 13335], communities=[],
    )
    incident2 = engine.process(e2, forced_rpki=RPKIState.VALID)
    assert incident2 is None, (
        "A new upstream for an RPKI-VALID route must not be flagged -- "
        "RPKI validity outranks baseline novelty."
    )


def test_rpki_valid_overrides_heuristics_if_reached_directly():
    # Defense in depth: even called directly, classify_intent must never
    # let heuristic scores produce a threat label when RPKI already
    # cryptographically confirmed the route.
    from jobless_router.heuristics import classify_intent
    result = classify_intent(fat_finger=80, mitm=90, blackhole=False, rpki_valid=True)
    assert result.label == "CONSISTENT_WITH_RPKI (origin cryptographically authorized)"
    assert result.confidence == 0


def main():
    tests = [
        test_rpki_valid_suppresses_anycast_false_positive,
        test_rpki_valid_overrides_heuristics_if_reached_directly,
    ]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print("All live-finding regression tests passed.")


if __name__ == "__main__":
    main()
