from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
import time


class RPKIState(Enum):
    VALID = "VALID"
    INVALID_ASN = "INVALID_ASN"
    INVALID_LENGTH = "INVALID_LENGTH"
    NOT_FOUND = "NOT_FOUND"
    UNKNOWN = "UNKNOWN"  # validator unreachable, or offline/demo mode


@dataclass
class RPKIVerdict:
    state: RPKIState
    matched_roas: List[dict] = field(default_factory=list)
    note: str = ""


@dataclass
class AnnouncementEvent:
    timestamp: float
    collector: str          # e.g. "rrc14"
    peer_asn: str
    prefix: str
    as_path: List[int]
    communities: List[str] = field(default_factory=list)  # "asn:value" strings
    raw: dict = field(default_factory=dict)

    @property
    def origin_asn(self) -> Optional[int]:
        return self.as_path[-1] if self.as_path else None


@dataclass
class PathAnomaly:
    kind: str  # "PREPEND" | "POISONING" | "CLEAN"
    suspect_asn: Optional[int]
    detail: str


@dataclass
class ValleyCheck:
    is_valley_free: bool
    broken_at_hop: Optional[int]
    detail: str


@dataclass
class IntentScore:
    fat_finger_score: int
    targeted_mitm_score: int
    label: str  # LIKELY_FAT_FINGER | LIKELY_TARGETED_INTERCEPTION | LIKELY_LEGITIMATE_RTBH... | AMBIGUOUS
    confidence: int


@dataclass
class BlastRadius:
    collectors_seen: int
    collectors_total: int
    pct_estimate: float
    regions: List[str]


@dataclass
class Incident:
    event: AnnouncementEvent
    rpki: RPKIVerdict
    complicit_upstream: Optional[int]
    path_anomaly: PathAnomaly
    valley: ValleyCheck
    intent: IntentScore
    blast: BlastRadius
    community_tags: List[str]
    novel: bool = False
    novel_note: str = ""
    ct_flags: List[str] = field(default_factory=list)
    opened_at: float = field(default_factory=time.time)
