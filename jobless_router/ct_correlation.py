"""
Certificate Transparency cross-correlation.

Targeted hijacks against high-value targets are sometimes paired with a
rushed, suspicious TLS certificate issuance for the victim's domain, to
actually intercept HTTPS traffic rather than just blackhole it. Polling CT
logs (via crt.sh's free JSON endpoint) for certs issued close to a BGP
incident's timestamp is a cross-layer signal almost nothing else checks --
the difference between "a route leaked" and "someone is actively trying
to MITM HTTPS."

This is intentionally a thin, fail-soft module: a production deployment
should parse crt.sh's timestamps properly (e.g. with dateutil) and compare
issuance time to the incident window with a real tolerance; here we surface
candidates and leave the final timing judgement to a human reviewer.
"""
import requests
from typing import List
from . import config


def recent_certs_for_domain(domain: str, timeout: float = 5.0) -> List[dict]:
    try:
        resp = requests.get(config.CRTSH_URL.format(domain=domain), timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except (requests.RequestException, ValueError):
        return []  # offline, rate-limited, or no results -- fail soft, never crash the pipeline


def flag_suspicious_issuance(domain: str, incident_ts: float, window_seconds: int = 3600) -> List[str]:
    flags = []
    for cert in recent_certs_for_domain(domain):
        not_before = cert.get("not_before") or cert.get("entry_timestamp")
        if not_before:
            flags.append(
                f"Cert for {domain} (issuer: {cert.get('issuer_name', 'unknown')}) "
                f"logged around {not_before} -- verify manually against the incident window."
            )
    return flags
