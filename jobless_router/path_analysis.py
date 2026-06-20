"""
AS-path forensics.

RIS-Live-style AS-path arrays are ordered nearest-observer-first / origin
last: path[0] is the peer closest to the collector, path[-1] is the origin
AS. That means the AS adjacent to the origin is the first network that
accepted the announcement directly from the origin and propagated it
onward -- the 'complicit' transit provider that failed to filter its
customer.

IMPORTANT: AS-path prepending (an AS repeating its own ASN consecutively,
e.g. [2914, 15412, 18101, 18101, 18101]) is routine, benign traffic
engineering, and it can be done by the origin OR by any transit AS in the
path. Every function here collapses consecutive duplicate hops first, so
prepending never gets mistaken for the actual topology or for poisoning.
"""
from typing import List, Optional
from .models import PathAnomaly


def collapse_consecutive_duplicates(as_path: List[int]) -> List[int]:
    """
    Squash AS-path prepending down to a single hop per distinct,
    consecutive run. This must happen before any topological judgement
    (finding the upstream, walking valley-free relationships) -- otherwise
    a prepended origin or a prepended transit AS gets misread as part of
    the real path structure.
    """
    collapsed: List[int] = []
    for asn in as_path:
        if not collapsed or collapsed[-1] != asn:
            collapsed.append(asn)
    return collapsed


def find_complicit_upstream(as_path: List[int]) -> Optional[int]:
    """
    Returns the AS immediately upstream of the origin, after collapsing
    prepends. For [2914, 15412, 18101, 18101, 18101] (origin 18101
    prepending itself three times), this correctly returns 15412, not
    18101 -- naively taking as_path[-2] on the raw array would return the
    origin's own ASN and miss the real complicit upstream entirely.
    """
    collapsed = collapse_consecutive_duplicates(as_path)
    if len(collapsed) < 2:
        return None
    return collapsed[-2]


def detect_path_anomaly(as_path: List[int]) -> PathAnomaly:
    """
    Separates benign prepending (traffic engineering, by the origin OR by
    any transit AS) from AS-path poisoning (deliberate loop-prevention
    evasion).

    The distinguishing signal is adjacency, not identity: a repeated ASN
    whose every occurrence is consecutive is ordinary prepending. A
    repeated ASN broken up by other networks in between -- e.g.
    [18101, 62041, 15412, 62041] -- is poisoning: that AS's own
    loop-detection will drop the route the moment it sees its own number,
    so it stays blind to the hijack while everyone else still routes
    through the attacker.

    Collapsing consecutive duplicates first and then checking for any
    *remaining* repeat is equivalent to, and simpler than, checking
    adjacency by hand: anything still repeated after collapsing must have
    been non-adjacent in the original path.
    """
    if not as_path:
        return PathAnomaly("CLEAN", None, "Empty path.")

    collapsed = collapse_consecutive_duplicates(as_path)
    counts = {}
    for asn in collapsed:
        counts[asn] = counts.get(asn, 0) + 1
    repeated = {asn: n for asn, n in counts.items() if n > 1}

    if not repeated:
        return PathAnomaly(
            "CLEAN", None,
            "No anomalous repeats (consecutive self-prepending, if any, is ordinary traffic engineering)."
        )

    asn = next(iter(repeated))
    idx_positions = [i for i, hop in enumerate(as_path) if hop == asn]
    return PathAnomaly(
        "POISONING",
        asn,
        f"AS{asn} appears {counts[asn]}x at non-adjacent positions {idx_positions} in path {as_path} "
        f"-- consistent with deliberate loop-prevention evasion, not ordinary prepending.",
    )
