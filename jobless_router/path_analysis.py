"""
AS-path forensics.

RIS-Live-style AS-path arrays are ordered nearest-observer-first / origin
last: path[0] is the peer closest to the collector, path[-1] is the origin
AS. That means path[-2] is the first network that accepted the
announcement directly from the origin and propagated it onward -- the
'complicit' transit provider that failed to filter its customer.
"""
from typing import List, Optional
from .models import PathAnomaly


def find_complicit_upstream(as_path: List[int]) -> Optional[int]:
    if len(as_path) < 2:
        return None
    return as_path[-2]


def detect_path_anomaly(as_path: List[int]) -> PathAnomaly:
    """
    Separates benign prepending (traffic engineering) from AS-path
    poisoning (deliberate loop-prevention evasion).

    Benign prepend: the origin AS repeats *itself*, consecutively, in the
    run of hops closest to itself.

    Poisoning: some *other* AS's number is planted once, non-adjacently,
    elsewhere in the path -- specifically so that AS's own loop-prevention
    logic drops the route and it stays blind to the hijack while everyone
    else still happily routes through the attacker.
    """
    if not as_path:
        return PathAnomaly("CLEAN", None, "Empty path.")

    origin = as_path[-1]
    counts = {}
    for asn in as_path:
        counts[asn] = counts.get(asn, 0) + 1

    repeated = {asn: n for asn, n in counts.items() if n > 1}
    if not repeated:
        return PathAnomaly("CLEAN", None, "No repeated ASNs in path.")

    for asn, n in repeated.items():
        if asn == origin:
            tail_run = 0
            for hop in reversed(as_path):
                if hop == origin:
                    tail_run += 1
                else:
                    break
            if tail_run == n:
                continue  # every occurrence is a consecutive self-prepend at the tail -- benign

        idx_positions = [i for i, hop in enumerate(as_path) if hop == asn]
        adjacent = all(b - a == 1 for a, b in zip(idx_positions, idx_positions[1:]))
        if not adjacent or asn != origin:
            return PathAnomaly(
                "POISONING",
                asn,
                f"AS{asn} appears {n}x at non-adjacent/non-origin positions {idx_positions} "
                f"in path {as_path} -- consistent with deliberate loop-prevention evasion.",
            )

    return PathAnomaly("PREPEND", origin, "All repeats are consecutive self-prepends by the origin; looks like ordinary traffic engineering.")
