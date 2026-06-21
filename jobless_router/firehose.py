"""
Two ways to feed the engine:

1. run_producer() -- connects to RIPE RIS Live's public websocket firehose
   (wss://ris-live.ripe.net), no API key required, and pushes raw messages
   onto a queue (consumed separately in run.py). Needs normal outbound
   internet access; will not work from a network-restricted sandbox.
   Auto-reconnects with backoff on dropped connections, and optionally
   routes through a SOCKS5 proxy.

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


def _format_community(c) -> str:
    """
    Normalize one BGP community entry into 'asn:value' string form.
    The bundled sample_events.jsonl uses strings (["65535", "666"]), but
    RIPE's real RIS Live feed sends actual JSON integers ([65535, 666]) --
    str()-ing every element here handles either shape instead of assuming
    one.
    """
    if isinstance(c, (list, tuple)):
        return ":".join(str(x) for x in c)
    return str(c)


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
                communities=[_format_community(c) for c in data.get("community", [])],
                raw=raw,
            )


try:
    from python_socks.async_.asyncio import Proxy
except ImportError:
    Proxy = None


async def run_producer(
    queue: asyncio.Queue,
    prefix_filter: Optional[str] = None,
    host: Optional[str] = None,
    more_specific: bool = False,
    proxy_url: Optional[str] = None,
    ping_interval: float = 10.0,
    ping_timeout: float = 5.0,
):
    if websockets is None:
        raise RuntimeError("Install the 'websockets' package to use --live mode (pip install websockets).")

    subscribe_msg = {"type": "ris_subscribe", "data": {"type": "UPDATE"}}
    if prefix_filter:
        subscribe_msg["data"]["prefix"] = prefix_filter
        if more_specific:
            subscribe_msg["data"]["moreSpecific"] = True
    if host:
        subscribe_msg["data"]["host"] = host

    retry_delay = 2.0
    max_retry_delay = 30.0

    from urllib.parse import urlparse
    parsed_url = urlparse(config.RIS_LIVE_WS_URL)
    dest_host = parsed_url.hostname
    dest_port = parsed_url.port or (443 if parsed_url.scheme == 'wss' else 80)

    while True:
        sock = None
        try:
            if proxy_url:
                if Proxy is None:
                    print("[warning] python-socks not installed, ignoring proxy.")
                else:
                    proxy = Proxy.from_url(proxy_url)
                    sock = await proxy.connect(dest_host, dest_port)

            async with websockets.connect(
                config.RIS_LIVE_WS_URL,
                sock=sock,
                server_hostname=dest_host if sock else None,
                open_timeout=30,
                ping_interval=ping_interval,
                ping_timeout=ping_timeout,
                family=socket.AF_INET if not sock else 0
            ) as ws:
                await ws.send(json.dumps(subscribe_msg))
                retry_delay = 2.0  # reset on successful connect

                async for raw_msg in ws:
                    await queue.put(raw_msg)
                    
        except (
            websockets.exceptions.ConnectionClosed,
            asyncio.TimeoutError,
            ConnectionRefusedError,
            socket.error
        ) as exc:
            if sock:
                sock.close()
            print(f"[producer] Connection dropped ({exc.__class__.__name__}). Reconnecting in {retry_delay}s...")
            await asyncio.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, max_retry_delay)
        except asyncio.CancelledError:
            if sock:
                sock.close()
            raise


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
