"""
Regression tests for three real bugs caught in code review (see CHANGELOG):

1. find_complicit_upstream returned the origin's own ASN instead of the
   real upstream when the origin used AS-path prepending.
2. detect_path_anomaly flagged ordinary transit-AS prepending as poisoning.
3. valley_free_check's pairwise walk never bridged across an unmapped
   intermediate ASN (e.g. an IXP route server), so a leak transiting one
   was invisible.

Run with: python tests/test_review_fixes.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from jobless_router.path_analysis import find_complicit_upstream, detect_path_anomaly
from jobless_router.relationships import RelationshipGraph, valley_free_check


def test_prepend_does_not_hide_real_upstream():
    # Origin AS18101 prepends itself 3x. The real complicit upstream is
    # AS15412, not AS18101 itself.
    path = [2914, 15412, 18101, 18101, 18101]
    assert find_complicit_upstream(path) == 15412


def test_transit_prepend_is_not_poisoning():
    # AS2914 (a transit network, not the origin AS18101) prepends itself
    # once, adjacently -- this is routine traffic engineering and must
    # not be flagged.
    path = [2914, 2914, 15412, 18101]
    anomaly = detect_path_anomaly(path)
    assert anomaly.kind == "CLEAN", anomaly.detail


def test_real_poisoning_is_still_caught():
    # AS62041 is planted non-adjacently -- this IS poisoning and must
    # still be flagged after the prepend fix.
    path = [18101, 62041, 15412, 62041]
    anomaly = detect_path_anomaly(path)
    assert anomaly.kind == "POISONING"
    assert anomaly.suspect_asn == 62041


def test_valley_check_bridges_unmapped_ixp_hop():
    # AS500 and AS600 are peers; AS600 is a CUSTOMER of AS800 (so
    # 600 -> 800 is an 'up' hop). An IXP route server (999) sits between
    # the origin (500) and 600, and CAIDA has no data on 999 at all.
    # A leak that goes peer-hop then illegally back up must still be
    # caught even though it transits an unmapped ASN.
    g = RelationshipGraph()
    g._rel[(500, 600)] = 0
    g._rel[(600, 500)] = 0
    g._rel[(600, 800)] = 1   # 600 is customer of 800
    g._rel[(800, 600)] = -1

    as_path = [800, 600, 999, 500]  # origin 500 -> unmapped IXP RS -> 600 -> 800
    result = valley_free_check(as_path, g)
    assert result.is_valley_free is False, result.detail


def test_valley_check_bridging_does_not_false_positive():
    # Same shape, but this time the path after the peer hop legitimately
    # goes DOWN (600 -> 700, 600 is 700's provider), which is valley-free.
    # Bridging across the unmapped IXP hop must not introduce a false
    # violation on a legitimate path.
    g = RelationshipGraph()
    g._rel[(500, 600)] = 0
    g._rel[(600, 500)] = 0
    g._rel[(600, 700)] = -1  # 600 is provider of 700
    g._rel[(700, 600)] = 1

    as_path = [700, 600, 999, 500]  # origin 500 -> unmapped IXP RS -> 600 -> 700
    result = valley_free_check(as_path, g)
    assert result.is_valley_free is True, result.detail


def main():
    tests = [
        test_prepend_does_not_hide_real_upstream,
        test_transit_prepend_is_not_poisoning,
        test_real_poisoning_is_still_caught,
        test_valley_check_bridges_unmapped_ixp_hop,
        test_valley_check_bridging_does_not_false_positive,
    ]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print("All review-fix regression tests passed.")


if __name__ == "__main__":
    main()
