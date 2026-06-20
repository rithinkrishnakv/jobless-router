"""
Two ways to feed the engine:

1. live_stream() -- connects to RIPE RIS Live's public websocket firehose
   (wss://ris-live.ripe.net), no API key required. Needs normal outbound
   internet access; will not work from a network-restricted sandbox.

2. replay_file() -- reads canned, RIS-Live-shaped JSONL messages from disk.
   Zero network dependency, fully deterministic -- this is what the bundled
   sample_events.jsonl demo uses.
"""
import asyncio
import json
import socket
import time
from typing import AsyncIterator, Iterator, Optional, List

from .models import AnnouncementEvent
from . import config

try:
    import websockets
except ImportError:
    websockets = None


def _event_from_data(data: dict, raw: dict) -> Iterator[AnnouncementEvent]:
    announcements = data.get("announcements", [])
    if not announcements and data.get("prefix"):
        announcements = [{"prefixes": [data["prefix"]]}]
    for ann in announcements:
        for prefix in ann.get("prefixes", []):
            yield AnnouncementEvent(
                timestamp=data.get("timestamp", time.time()),
                collector=data.get("host", "unknown"),
                peer_asn=str(data.get("peer_asn", "")),
                prefix=prefix,
                as_path=[int(a) for a in data.get("path", []) if str(a).lstrip("-").isdigit()],
                communities=[":".join(c) if isinstance(c, list) else c for c in data.get("community", [])],
                raw=raw,
            )


async def live_stream(prefix_filter: Optional[str] = None) -> AsyncIterator[AnnouncementEvent]:
    if websockets is None:
        raise RuntimeError("Install the 'websockets' package to use --live mode (pip install websockets).")

    subscribe_msg = {"type": "ris_subscribe", "data": {"type": "UPDATE"}}
    if prefix_filter:
        subscribe_msg["data"]["prefix"] = prefix_filter

    # family=AF_INET: many VM/NAT setups (VirtualBox/VMware NAT in particular)
    # hand out a working IPv4 path but cannot actually route IPv6, even
    # though DNS still returns an IPv6 address. Without this, the connect
    # attempt can hang on the unreachable IPv6 address before ever trying
    # IPv4 -- curl avoids this by racing both (Happy Eyeballs), but plain
    # asyncio connects do not unless told to skip IPv6 outright.
    async with websockets.connect(config.RIS_LIVE_WS_URL, open_timeout=30, family=socket.AF_INET) as ws:
        await ws.send(json.dumps(subscribe_msg))
        async for raw_msg in ws:
            msg = json.loads(raw_msg)
            data = msg.get("data", {})
            for event in _event_from_data(data, msg):
                yield event


def replay_file(path: str) -> Iterator[AnnouncementEvent]:
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            msg = json.loads(line)
            data = msg.get("data", msg)
            for event in _event_from_data(data, msg):
                yield event
