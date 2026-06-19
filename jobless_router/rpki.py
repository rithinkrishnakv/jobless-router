"""
Live RPKI validation.

Uses RIPEstat's free, no-auth rpki-validation data call, which itself
cross-references the global RPKI repository's cryptographic ROAs. Falls
back to UNKNOWN (rather than crashing the pipeline) if the validator is
unreachable -- e.g. in a sandboxed environment with restricted egress, or
during a genuine network blip.
"""
import requests

from .models import RPKIVerdict, RPKIState
from . import config


def validate_route(prefix: str, origin_asn: int, timeout: float = 4.0) -> RPKIVerdict:
    try:
        resp = requests.get(
            config.RIPESTAT_RPKI_URL,
            params={"resource": origin_asn, "prefix": prefix},
            timeout=timeout,
        )
        resp.raise_for_status()
        data = resp.json()["data"]
        status = data.get("status", "").lower()
        roas = data.get("validating_roas", [])

        if status == "valid":
            return RPKIVerdict(RPKIState.VALID, roas, "Origin/prefix covered by a matching ROA.")
        if status == "invalid_asn":
            return RPKIVerdict(RPKIState.INVALID_ASN, roas, "A covering ROA exists, but for a different origin ASN.")
        if status == "invalid_length":
            return RPKIVerdict(RPKIState.INVALID_LENGTH, roas, "Announced prefix is more specific than the ROA's max length allows.")
        if status == "not_found":
            return RPKIVerdict(RPKIState.NOT_FOUND, roas, "No covering ROA exists; RPKI has no opinion on this route.")
        return RPKIVerdict(RPKIState.UNKNOWN, roas, f"Unrecognized validator status: {status!r}")

    except requests.RequestException as exc:
        return RPKIVerdict(
            RPKIState.UNKNOWN, [],
            f"RPKI validator unreachable ({exc.__class__.__name__}) -- running with no RPKI signal.",
        )


def mock_validate_route(prefix: str, origin_asn: int, forced_state: RPKIState, note: str = "") -> RPKIVerdict:
    """Used by --replay/demo mode to deterministically drive scenarios without needing network access."""
    return RPKIVerdict(forced_state, [], note or "mocked verdict (demo/test mode)")
