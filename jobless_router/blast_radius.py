"""
Live blast-radius mapping -- the honest version.

Cross-referencing PeeringDB doesn't actually tell you what fraction of the
global routing table accepted a bad route; PeeringDB describes peering
relationships, not live RIB state. What you *can* measure honestly is how
many independent, geographically-distributed RIS route collectors (RIPE
runs ~25 of them, rrc00-rrc26, at different exchange points worldwide) saw
the same (prefix, origin) pair. That's a real, defensible propagation
sample -- not a guess.
"""
from typing import Dict
from .models import BlastRadius
from . import config


class BlastRadiusTracker:
    def __init__(self):
        self._sightings: Dict[str, set] = {}

    def record(self, key: str, collector: str):
        self._sightings.setdefault(key, set()).add(collector)

    def estimate(self, key: str) -> BlastRadius:
        seen = self._sightings.get(key, set())
        total = config.KNOWN_RIS_COLLECTOR_COUNT
        regions = sorted({config.RIS_COLLECTOR_REGIONS.get(c, c) for c in seen})
        pct = round(100 * len(seen) / total, 1) if total else 0.0
        return BlastRadius(len(seen), total, pct, regions)
