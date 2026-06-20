"""
AS business-relationship graph and the Gao-Rexford valley-free check.

Loads CAIDA 'serial-2' format AS-relationship files:
    as1|as2|relationship
where relationship == -1 means as1 is the PROVIDER of as2 (as2 is the
customer), and relationship == 0 means as1 and as2 are settlement-free
PEERS. This is the same relationship data CAIDA publishes publicly at
https://publicdata.caida.org/datasets/as-relationships/ -- point
RelationshipGraph.load() at a real downloaded copy for production use.
The bundled data/sample_as_relationships.txt is a tiny illustrative subset
for demos and tests only.

The valley-free property (Gao & Rexford, 2001) is the theoretical basis
RFC 7908 uses to define a route leak: a legitimate BGP path can only travel
zero-or-more customer->provider ('up') hops, then optionally a single
peer-to-peer hop, then zero-or-more provider->customer ('down') hops. Once
a path has gone 'down' or used its one peer hop, it can never legitimately
go 'up' again. When it does, that's almost always a route leak.

Two things the naive version of this check gets wrong, both fixed here:

1. AS-path prepending. [..., 18101, 18101, 18101] must not be walked as
   three separate hops -- it's one hop, repeated for traffic engineering.
   Collapsing consecutive duplicates before walking the path is required;
   relying on CAIDA simply not mapping self-edges to "accidentally" skip
   prepends is fragile and not an actual invariant.

2. Unmapped intermediate ASNs (most commonly an IXP route server, which
   operates as a transparent BGP next-hop and is rarely present in CAIDA's
   relationship data at all). A naive pairwise walk that just does
   `continue` on an unknown relationship silently severs the chain: it
   never actually checks whether the AS *before* the unknown hop and the
   AS *after* it have a real relationship, because each side of the gap
   only ever gets compared to the unknown ASN itself. Any leak that
   transits an unmapped hop becomes invisible. The fix is an anchored
   walk: keep the last AS we successfully classified a transition from as
   an anchor, and when the next hop's relationship is unknown, don't
   advance the anchor -- try the anchor against the hop *after* that
   instead, bridging across the gap until a known relationship is found.
"""
from typing import Dict, List, Optional, Tuple
from .models import ValleyCheck
from .path_analysis import collapse_consecutive_duplicates

PROVIDER_TO_CUSTOMER = -1
PEER_TO_PEER = 0


class RelationshipGraph:
    def __init__(self):
        self._rel: Dict[Tuple[int, int], int] = {}

    def load(self, path: str) -> "RelationshipGraph":
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                if len(parts) < 3:
                    continue
                a, b, rel = int(parts[0]), int(parts[1]), int(parts[2])
                self._rel[(a, b)] = rel
                self._rel[(b, a)] = -rel if rel != 0 else 0
        return self

    def relationship(self, a: int, b: int) -> Optional[str]:
        """'p2c' if a is b's provider, 'c2p' if a is b's customer, 'p2p' if peers, else None (unknown)."""
        if (a, b) not in self._rel:
            return None
        code = self._rel[(a, b)]
        if code == PROVIDER_TO_CUSTOMER:
            return "p2c"
        if code == -PROVIDER_TO_CUSTOMER:
            return "c2p"
        if code == PEER_TO_PEER:
            return "p2p"
        return None


def valley_free_check(as_path: List[int], graph: RelationshipGraph) -> ValleyCheck:
    collapsed = collapse_consecutive_duplicates(as_path)
    if len(collapsed) < 2:
        return ValleyCheck(True, None, "Path too short to evaluate.")

    hops = list(reversed(collapsed))  # walk origin -> observer
    phase = "up"
    unknown_hops = 0
    anchor_idx = 0  # index into `hops` of the last AS we actually classified a transition from

    i = 1
    while i < len(hops):
        a, b = hops[anchor_idx], hops[i]
        rel = graph.relationship(a, b)

        if rel is None:
            # Bridge across the unmapped hop (e.g. an IXP route server)
            # instead of severing the chain -- keep the same anchor and
            # try it against the next hop further down the path.
            unknown_hops += 1
            i += 1
            continue

        step = "up" if rel == "c2p" else "down" if rel == "p2c" else "peer"

        if phase == "up":
            if step == "peer":
                phase = "peer"
            elif step == "down":
                phase = "down"
        elif phase == "peer":
            if step == "down":
                phase = "down"
            elif step == "up":
                return ValleyCheck(False, i, f"AS{a}->AS{b} goes 'up' again after a peering hop -- valley after peer.")
            elif step == "peer":
                return ValleyCheck(False, i, f"AS{a}->AS{b} is a second peer-to-peer hop -- not valley-free.")
        elif phase == "down":
            if step != "down":
                return ValleyCheck(False, i, f"AS{a}->AS{b} goes '{step}' after the path already turned downstream -- classic route-leak valley.")

        anchor_idx = i
        i += 1

    note = "Valley-free." if unknown_hops == 0 else f"Valley-free over known hops ({unknown_hops} hop(s) bridged across unmapped ASNs, e.g. IXP route servers)."
    return ValleyCheck(True, None, note)
