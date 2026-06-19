"""Central configuration and constants for Jobless-Router."""

RIS_LIVE_WS_URL = "wss://ris-live.ripe.net/v1/ws/?client=jobless-router"
RIPESTAT_RPKI_URL = "https://stat.ripe.net/data/rpki-validation/data.json"
CRTSH_URL = "https://crt.sh/?q={domain}&output=json"

# Approximate, illustrative RIS collector -> region map, used only to turn
# "which collectors saw this" into a human-readable regional spread for the
# blast-radius section of the report. RIPE adds/retires collectors over
# time -- refresh this from https://ris.ripe.net/docs/route-collectors/
# before relying on it for anything operational.
RIS_COLLECTOR_REGIONS = {
    "rrc00": "Amsterdam, NL",
    "rrc01": "London, UK",
    "rrc03": "Amsterdam, NL",
    "rrc04": "Geneva, CH",
    "rrc05": "Vienna, AT",
    "rrc06": "Otemachi, JP",
    "rrc07": "Stockholm, SE",
    "rrc10": "Milan, IT",
    "rrc11": "New York, US",
    "rrc12": "Frankfurt, DE",
    "rrc13": "Moscow, RU",
    "rrc14": "Palo Alto, US",
    "rrc15": "Sao Paulo, BR",
    "rrc16": "Miami, US",
    "rrc18": "Barcelona, ES",
    "rrc19": "Johannesburg, ZA",
    "rrc20": "Zurich, CH",
    "rrc21": "Paris, FR",
    "rrc23": "Singapore, SG",
    "rrc24": "Montevideo, UY",
    "rrc25": "Amsterdam, NL",
    "rrc26": "Dubai, AE",
}
KNOWN_RIS_COLLECTOR_COUNT = len(RIS_COLLECTOR_REGIONS)

# RFC 1997 / RFC 7999 well-known communities, expressed the way RIS Live
# already formats them ("asn:value" strings).
WELL_KNOWN_COMMUNITIES = {
    "65535:65281": "NO_EXPORT",
    "65535:65282": "NO_ADVERTISE",
    "65535:65283": "NO_EXPORT_SUBCONFED",
    "65535:65284": "NOPEER",
    "65535:666": "BLACKHOLE (RFC 7999 RTBH trigger)",
}
BLACKHOLE_COMMUNITY = "65535:666"

# Heuristic thresholds -- tune freely for your own network's risk appetite.
FAT_FINGER_MAX_PREFIX_LEN = 16   # /16 or broader looks like over-deaggregation
MITM_MIN_PREFIX_LEN = 24         # /24 or more specific looks surgical
THREAT_SCORE_HIGH = 70
THREAT_SCORE_MEDIUM = 40
