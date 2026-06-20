from typing import Optional, List

from . import rpki, communities, path_analysis, heuristics, mitigation, report
from .relationships import RelationshipGraph, valley_free_check
from .blast_radius import BlastRadiusTracker
from .threat_db import ThreatDB
from .baseline import BaselineStore
from .models import AnnouncementEvent, RPKIState, Incident


def _db_path(db_dir: str, name: str) -> str:
    if db_dir == ":memory:":
        return ":memory:"
    return f"{db_dir}/{name}"


class JoblessRouterEngine:
    def __init__(
        self,
        relationships_path: Optional[str] = None,
        watchlist: Optional[List[str]] = None,
        offline: bool = False,
        db_dir: str = ":memory:",
    ):
        self.graph = RelationshipGraph()
        if relationships_path:
            self.graph.load(relationships_path)
        self.blast = BlastRadiusTracker()
        self.threat_db = ThreatDB(_db_path(db_dir, "jobless_router_threat.db"))
        self.baseline = BaselineStore(_db_path(db_dir, "jobless_router_baseline.db"))
        self.watchlist = set(watchlist or [])
        self.offline = offline

    def _on_watchlist(self, prefix: str) -> bool:
        return prefix in self.watchlist

    def process(self, event: AnnouncementEvent, forced_rpki: Optional[RPKIState] = None) -> Optional[Incident]:
        origin = event.origin_asn
        if origin is None:
            return None

        upstream = path_analysis.find_complicit_upstream(event.as_path)

        novel, novel_note = self.baseline.is_novel(event.prefix, origin, upstream or 0)
        self.baseline.observe(event.prefix, origin, upstream or 0)

        if forced_rpki is not None:
            rpki_verdict = rpki.mock_validate_route(event.prefix, origin, forced_rpki, novel_note)
        elif self.offline:
            rpki_verdict = rpki.mock_validate_route(event.prefix, origin, RPKIState.UNKNOWN, novel_note)
        else:
            rpki_verdict = rpki.validate_route(event.prefix, origin)

        blackhole = communities.has_blackhole_tag(event.communities)
        # RPKI VALID is a cryptographic attestation, not a heuristic -- it
        # must take precedence over baseline novelty. A prefix legitimately
        # gets announced through a never-before-seen upstream constantly
        # (anycast, new transit relationships, etc.); that's not a leak if
        # RPKI already confirms this exact origin is authorized for this
        # exact prefix. Without this guard, a brand new (but 100% legitimate)
        # upstream for an already-valid route gets treated as "novel" and
        # then scored by heuristics that never check RPKI at all -- which is
        # exactly how Cloudflare's own valid 1.1.1.0/24 announcement once
        # got flagged as LIKELY_TARGETED_INTERCEPTION in testing.
        interesting = rpki_verdict.state in (RPKIState.INVALID_ASN, RPKIState.INVALID_LENGTH) or (
            novel and rpki_verdict.state != RPKIState.VALID
        )
        if not interesting:
            return None  # clean, baseline-consistent (or RPKI-confirmed) route -- correctly stays silent

        anomaly = path_analysis.detect_path_anomaly(event.as_path)
        valley = valley_free_check(event.as_path, self.graph)
        has_relationship = upstream is not None and self.graph.relationship(upstream, origin) is not None

        ff_score = heuristics.fat_finger_score(event.prefix, rpki_verdict)
        mitm_score = heuristics.targeted_mitm_score(
            event.prefix,
            rpki_verdict,
            valley,
            on_watchlist=self._on_watchlist(event.prefix),
            has_business_relationship=has_relationship,
            path_poisoned=(anomaly.kind == "POISONING"),
        )
        intent = heuristics.classify_intent(ff_score, mitm_score, blackhole=blackhole, rpki_valid=(rpki_verdict.state == RPKIState.VALID))

        key = f"{event.prefix}|{origin}"
        self.blast.record(key, event.collector)
        blast = self.blast.estimate(key)

        if not blackhole:
            self.threat_db.record_incident(origin)

        tags = communities.decode_communities(event.communities)

        return Incident(
            event=event,
            rpki=rpki_verdict,
            complicit_upstream=upstream,
            path_anomaly=anomaly,
            valley=valley,
            intent=intent,
            blast=blast,
            community_tags=tags,
        )

    def render_incident(self, incident: Incident) -> str:
        playbook = ""
        label = incident.intent.label
        if label not in ("AMBIGUOUS",) and not label.startswith(("LIKELY_LEGITIMATE", "CONSISTENT_WITH_RPKI")) and incident.complicit_upstream:
            playbook = mitigation.build_playbook(incident.event.prefix, incident.event.origin_asn)
        return report.render(incident, playbook)
