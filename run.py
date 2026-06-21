import argparse
import asyncio
import json
import sys

import websockets.exceptions

from jobless_router.engine import JoblessRouterEngine
from jobless_router.firehose import replay_file, run_producer, _event_from_data
from jobless_router.models import RPKIState
from jobless_router.banner import render_banner

FORCED_STATES = {
    "valid": RPKIState.VALID,
    "invalid_asn": RPKIState.INVALID_ASN,
    "invalid_length": RPKIState.INVALID_LENGTH,
    "not_found": RPKIState.NOT_FOUND,
}


def _load_watchlist(path: str):
    try:
        with open(path) as fh:
            return json.load(fh)
    except FileNotFoundError:
        return []


def run_replay(path: str, relationships: str, watchlist, db_dir: str):
    engine = JoblessRouterEngine(relationships_path=relationships, watchlist=watchlist, db_dir=db_dir)
    flagged = 0
    total = 0
    for event in replay_file(path):
        total += 1
        forced = event.raw.get("_demo_rpki")
        label = event.raw.get("_label", "")
        forced_state = FORCED_STATES.get(forced, RPKIState.UNKNOWN)
        incident = engine.process(event, forced_rpki=forced_state)
        if label:
            print(f"[scenario] {label}")
        if incident:
            flagged += 1
            print(engine.render_incident(incident))
        else:
            print(f"-> no incident raised for {event.prefix} (clean / baseline-consistent).")
        print("\n" + "=" * 80 + "\n")
    print(f"[jobless-router] replay complete: {flagged}/{total} event(s) flagged as incidents.")


def run_live(relationships: str, watchlist, db_dir: str, prefix_filter=None, host=None, debug=False, more_specific=False, proxy=None, ping_interval=10.0, ping_timeout=5.0):
    engine = JoblessRouterEngine(relationships_path=relationships, watchlist=watchlist, db_dir=db_dir)
    state = {"count": 0, "incidents": 0}

    def debug_print(event, upstream, rpki_verdict, novel, novel_note, ff_score, mitm_score, intent, interesting):
        upstream_str = f"AS{upstream}" if upstream is not None else "(no upstream, direct peering)"
        print(
            f"[debug] AS{event.origin_asn} {event.prefix} via {upstream_str} | "
            f"RPKI={rpki_verdict.state.value} novel={novel} | "
            f"FF={ff_score}/100 MITM={mitm_score}/100 -> {intent.label} | "
            f"interesting={interesting}"
        )
        if rpki_verdict.state.value == "UNKNOWN":
            print(f"         RPKI note: {rpki_verdict.note}")
        if novel:
            print(f"         baseline note: {novel_note}")

    async def _consumer(queue: asyncio.Queue, heartbeat_every: int):
        while True:
            raw_msg = await queue.get()
            if raw_msg is None:
                queue.task_done()
                break
            try:
                msg = json.loads(raw_msg)
                data = msg.get("data", {})
                for event in _event_from_data(data, msg):
                    if prefix_filter and not more_specific and event.prefix != prefix_filter:
                        continue
                    state["count"] += 1
                    incident = await asyncio.to_thread(
                        engine.process, event, None, debug_print if debug else None
                    )
                    if incident:
                        state["incidents"] += 1
                        print(engine.render_incident(incident))
                        print("\n" + "=" * 80 + "\n")
                    if state["count"] % heartbeat_every == 0:
                        print(f"[jobless-router] ...alive -- processed {state['count']} updates, {state['incidents']} flagged so far.")
            except Exception as e:
                print(f"[consumer] Parse or process error: {e}")
                # Crash if there is a parsing logic issue, do not swallow it silently
                raise
            finally:
                queue.task_done()

    async def _go():
        print("[jobless-router] connecting to RIPE RIS Live firehose...")
        if prefix_filter:
            print(
                f"[jobless-router] filtering to prefix: {prefix_filter}"
                + (" (+ all more-specific sub-prefixes)" if more_specific else "")
                + (f", collector: {host}" if host else "")
            )
            print(
                "[jobless-router] waiting for the first real BGP update for this prefix -- BGP only "
                "sends an update when something actually changes, not on a fixed schedule, so this can "
                "take anywhere from a few seconds to several minutes even for a busy prefix. Quiet is normal."
            )
            heartbeat_every = 1
        elif host:
            print(f"[jobless-router] filtering to collector: {host} (all prefixes seen by this one route collector)")
            print(
                "[jobless-router] this is a real, continuous stream of path changes from dozens of "
                "networks -- expect frequent heartbeats, and a real shot at an actual flagged incident "
                "within a minute or two, since RPKI-invalid routes genuinely occur on the live internet "
                "at a low but steady rate."
            )
            heartbeat_every = 10
        else:
            print(
                "[jobless-router] no --prefix/--host given -- subscribing to the FULL unfiltered global "
                "firehose. This is genuinely high volume, and the tool deliberately stays silent on "
                "ordinary, legitimate traffic, so it can look 'stuck' even while working correctly. "
                "Watch for the heartbeat line below, or stop (Ctrl+C) and rerun with e.g. "
                "--host rrc00 to see something concrete sooner."
            )
            heartbeat_every = 25

        queue = asyncio.Queue(maxsize=10000)
        consumer_task = asyncio.create_task(_consumer(queue, heartbeat_every))
        producer_task = asyncio.create_task(run_producer(
            queue, prefix_filter, host, more_specific, proxy, ping_interval, ping_timeout
        ))

        try:
            # Wait on whichever finishes first. Under normal operation
            # neither task ever finishes on its own (the producer retries
            # forever, the consumer loops until it gets the shutdown
            # sentinel) -- this exists purely so an unhandled exception in
            # EITHER task surfaces immediately and loudly. Without this,
            # a crash in the consumer (a genuine parsing bug, say) would
            # leave it silently dead while the producer kept running with
            # nothing left consuming the queue -- the program would look
            # alive (still connected) while having actually stopped
            # processing anything, with the real error invisible until
            # something else (like Ctrl+C) finally touched consumer_task.
            done, _ = await asyncio.wait(
                [producer_task, consumer_task], return_when=asyncio.FIRST_EXCEPTION
            )
            for t in done:
                if t.exception() is not None:
                    raise t.exception()
        except asyncio.CancelledError:
            print(f"\n[jobless-router] graceful shutdown initiated. Waiting for remaining {queue.qsize()} items in queue...")
        finally:
            producer_task.cancel()

            async def cleanup():
                # Let the consumer drain whatever's already queued rather
                # than cutting it off mid-item -- but if it already died
                # (e.g. via the exception path above), there's nothing
                # alive to drain into, and putting/awaiting on it would
                # just hang forever.
                if not consumer_task.done():
                    await queue.put(None)
                    try:
                        await consumer_task
                    except asyncio.CancelledError:
                        pass

            try:
                await asyncio.shield(cleanup())
            except asyncio.CancelledError:
                pass

    try:
        asyncio.run(_go())
    except KeyboardInterrupt:
        pass
    print(f"\n[jobless-router] stopped. Processed {state['count']} update(s), flagged {state['incidents']} incident(s).")


def main():
    parser = argparse.ArgumentParser(
        prog="jobless-router",
        description="BGP zero-trust route-leak / hijack fingerprinter.",
    )
    parser.add_argument("--replay", help="Path to a JSONL file of canned RIS-Live-style messages (no network needed).")
    parser.add_argument("--live", action="store_true", help="Connect to the real RIPE RIS Live firehose.")
    parser.add_argument("--proxy", default=None, help="SOCKS5 proxy URL (e.g. socks5://127.0.0.1:1080) for the live connection.")
    parser.add_argument("--ping-interval", type=float, default=10.0, help="WebSocket keepalive ping interval in seconds.")
    parser.add_argument("--ping-timeout", type=float, default=5.0, help="WebSocket keepalive ping timeout in seconds.")
    parser.add_argument("--prefix", default=None, help="With --live, subscribe to only this prefix (e.g. 1.1.1.0/24) instead of the full global firehose.")
    parser.add_argument("--host", default=None, help="With --live, subscribe to only this RIS collector (e.g. rrc00) -- all prefixes it sees, real continuous traffic.")
    parser.add_argument("--debug", action="store_true", help="With --live, print RPKI/score/verdict for every event, including ones that don't get flagged -- use this to verify the engine is actually evaluating traffic, not just to trust the silence.")
    parser.add_argument("--more-specific", action="store_true", help="With --live --prefix, also match every more-specific sub-prefix within that block (e.g. catches a /24 hijacked out of a watched /16) instead of only the exact prefix.")
    parser.add_argument("--relationships", default="data/sample_as_relationships.txt", help="CAIDA-format AS relationship file.")
    parser.add_argument("--watchlist", default="data/watchlist.json", help="JSON list of critical prefixes to watch.")
    parser.add_argument("--db-dir", default=":memory:", help="Directory for sqlite threat/baseline DBs, or ':memory:' for an ephemeral run.")
    args = parser.parse_args()

    print(render_banner())
    watchlist = _load_watchlist(args.watchlist)

    if args.replay:
        run_replay(args.replay, args.relationships, watchlist, args.db_dir)
    elif args.live:
        run_live(args.relationships, watchlist, args.db_dir, args.prefix, args.host, args.debug, args.more_specific, args.proxy, args.ping_interval, args.ping_timeout)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
