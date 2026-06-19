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
go 'up' again. When it does, that's almost always a route leak: a customer
route got handed to a peer (or provider) who re-advertised it as if they
had transit rights to it.
"""
from typing import Dict, List, Optional, Tuple
from .models import ValleyCheck

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
    if len(as_path) < 2:
        return ValleyCheck(True, None, "Path too short to evaluate.")

    hops = list(reversed(as_path))  # walk origin -> observer
    phase = "up"
    unknown_hops = 0

    for i in range(len(hops) - 1):
        a, b = hops[i], hops[i + 1]
        rel = graph.relationship(a, b)
        if rel is None:
            unknown_hops += 1
            continue  # no relationship data for this hop -- can't judge it, don't penalize

        if rel == "c2p":
            step = "up"
        elif rel == "p2c":
            step = "down"
        else:
            step = "peer"

        if phase == "up":
            if step == "peer":
                phase = "peer"
            elif step == "down":
                phase = "down"
            # step == "up": stay in 'up'
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

    note = "Valley-free." if unknown_hops == 0 else f"Valley-free over known hops ({unknown_hops} hop(s) had no relationship data)."
    return ValleyCheck(True, None, note)
