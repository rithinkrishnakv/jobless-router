"""
Decodes BGP community attributes attached to an announcement.

Communities are how operators tag internal routing policy ("don't export
this past Europe", "this is a customer route", "this is a deliberate
blackhole"). A rogue or leaking AS frequently forgets to strip these on the
way out, which means they leak the *intent* behind the route along with the
route itself.
"""
from typing import List
from . import config


def decode_communities(communities: List[str]) -> List[str]:
    """Turn raw 'asn:value' community strings into human-readable tags."""
    tags = []
    for c in communities:
        if c in config.WELL_KNOWN_COMMUNITIES:
            tags.append(f"{c} -> {config.WELL_KNOWN_COMMUNITIES[c]}")
        else:
            tags.append(f"{c} -> operator-defined (check the origin AS's published BGP community policy)")
    return tags


def has_blackhole_tag(communities: List[str]) -> bool:
    """RFC 7999 blackhole community -- a strong 'this is intentional RTBH mitigation' signal."""
    return config.BLACKHOLE_COMMUNITY in communities
