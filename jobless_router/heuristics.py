"""
The "Intent vs. Error" heuristic engine.

Two independent scores, each 0-100:

- fat_finger_score: evidence this is an accidental over-deaggregation /
  misconfiguration (broad prefix, RPKI INVALID_LENGTH).
- targeted_mitm_score: evidence this is a deliberate, surgical
  interception attempt (highly specific prefix, hits a watched critical
  service, no business relationship between the complicit upstream and
  the origin, breaks valley-free routing, or pairs with AS-path
  poisoning aimed at evading a specific network's loop detection).

The two scores are deliberately independent -- a real event can score
nonzero on both, and the gap between them (not just the max) is part of
the signal.
"""
from .models import IntentScore, RPKIVerdict, RPKIState, ValleyCheck
from . import config


def _prefix_len(prefix: str) -> int:
    return int(prefix.split("/")[-1])


def fat_finger_score(prefix: str, rpki: RPKIVerdict) -> int:
    score = 0
    plen = _prefix_len(prefix)
    if plen <= config.FAT_FINGER_MAX_PREFIX_LEN:
        score += 40
    if rpki.state == RPKIState.INVALID_LENGTH:
        score += 40
    if rpki.state == RPKIState.INVALID_ASN and plen <= config.FAT_FINGER_MAX_PREFIX_LEN:
        score += 10
    return min(score, 100)


def targeted_mitm_score(
    prefix: str,
    rpki: RPKIVerdict,
    valley: ValleyCheck,
    on_watchlist: bool,
    has_business_relationship: bool,
    path_poisoned: bool = False,
) -> int:
    score = 0
    plen = _prefix_len(prefix)
    if plen >= config.MITM_MIN_PREFIX_LEN:
        score += 30
    if on_watchlist:
        score += 30
    if not has_business_relationship:
        # Weak signal, deliberately: CAIDA's relationship data is known to
        # be thin for regional/domestic peering (e.g. a local ISP privately
        # peering with a national carrier at a regional IXP). "No known
        # relationship" is genuinely ambiguous between "no relationship
        # exists" and "CAIDA just doesn't have it" -- so it contributes a
        # little, but a real valley-free violation (which IS explicit,
        # structural evidence) is weighted twice as heavily below.
        score += 10
    if not valley.is_valley_free:
        score += 20
    if rpki.state == RPKIState.INVALID_ASN:
        score += 10
    if path_poisoned:
        score += 20
    return min(score, 100)


def classify_intent(fat_finger: int, mitm: int, blackhole: bool = False, rpki_valid: bool = False) -> IntentScore:
    if rpki_valid:
        # Cryptographic proof of legitimacy outranks every heuristic below.
        # No combination of prefix-specificity/watchlist/relationship-graph
        # signals should ever be allowed to override an actual valid ROA.
        return IntentScore(fat_finger, mitm, "CONSISTENT_WITH_RPKI (origin cryptographically authorized)", 0)

    if blackhole:
        # A blackhole community is an operator deliberately asking the
        # network to drop this traffic -- almost always legitimate DDoS
        # mitigation, not a hijack. Don't let prefix-specificity heuristics
        # override an explicit, machine-readable statement of intent.
        return IntentScore(fat_finger, mitm, "LIKELY_LEGITIMATE_RTBH (blackhole community present)", 80)

    if mitm >= config.THREAT_SCORE_HIGH and mitm >= fat_finger:
        return IntentScore(fat_finger, mitm, "LIKELY_TARGETED_INTERCEPTION", mitm)
    if fat_finger >= config.THREAT_SCORE_HIGH and fat_finger >= mitm:
        return IntentScore(fat_finger, mitm, "LIKELY_FAT_FINGER", fat_finger)
    if max(fat_finger, mitm) >= config.THREAT_SCORE_MEDIUM:
        label = "LIKELY_TARGETED_INTERCEPTION" if mitm > fat_finger else "LIKELY_FAT_FINGER"
        return IntentScore(fat_finger, mitm, label, max(fat_finger, mitm))
    return IntentScore(fat_finger, mitm, "AMBIGUOUS", max(fat_finger, mitm))
