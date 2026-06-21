import argparse
import asyncio
import json
import sys

import websockets.exceptions

from jobless_router.engine import JoblessRouterEngine
from jobless_router.firehose import replay_file, live_stream
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


def run_live(relationships: str, watchlist, db_dir: str, prefix_filter=None, host=None, debug=False, more_specific=False):
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
        max_retries = 5
        retry_delay = 2
        attempt = 0

        while True:
            try:
                async for event in live_stream(prefix_filter, host, more_specific):
                    if prefix_filter and not more_specific and event.prefix != prefix_filter:
                        # RIS Live's prefix filter matches at the UPDATE-message
                        # level; a single message can legitimately carry several
                        # prefixes (e.g. Cloudflare's 1.0.0.0/24 and 1.1.1.0/24
                        # often ride the same path). Only count exact matches so
                        # --prefix actually means what it says.
                        continue
                    state["count"] += 1
                    # Run off the event loop: engine.process() makes a blocking
                    # network call (the RPKI check), and running that directly
                    # inside this coroutine corrupts asyncio's cleanup if the
                    # user hits Ctrl+C mid-request.
                    incident = await asyncio.to_thread(
                        engine.process, event, None, debug_print if debug else None
                    )
                    if incident:
                        state["incidents"] += 1
                        print(engine.render_incident(incident))
                        print("\n" + "=" * 80 + "\n")
                    if state["count"] % heartbeat_every == 0:
                        print(f"[jobless-router] ...alive -- processed {state['count']} updates, {state['incidents']} flagged so far.")
                    attempt = 0  # a successful message resets the retry budget
                return  # live_stream ending cleanly (shouldn't normally happen) -- stop
            except websockets.exceptions.ConnectionClosed as exc:
                attempt += 1
                if attempt > max_retries:
                    print(
                        f"[jobless-router] connection kept dropping ({exc.__class__.__name__}) after "
                        f"{max_retries} reconnect attempts -- giving up. Processed {state['count']} update(s), "
                        f"flagged {state['incidents']} total before this. This is usually transient network "
                        f"flakiness (NAT idle-connection timeouts are a common cause on VM networks) rather "
                        f"than anything wrong with the tool. Try again, or use --replay for the offline demo."
                    )
                    return
                print(
                    f"[jobless-router] connection dropped ({exc.__class__.__name__}) -- reconnecting in "
                    f"{retry_delay}s (attempt {attempt}/{max_retries}). {state['count']} update(s) processed, "
                    f"{state['incidents']} flagged so far."
                )
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 30)
            except Exception as exc:
                print(
                    f"[jobless-router] could not reach the RIS Live firehose ({exc.__class__.__name__}: {exc}).\n"
                    f"This usually means outbound access to ris-live.ripe.net is blocked by your network/proxy.\n"
                    f"Try `python run.py --replay sample_events.jsonl` for an offline demo instead."
                )
                return

    try:
        asyncio.run(_go())
    except KeyboardInterrupt:
        print(f"\n[jobless-router] stopped. Processed {state['count']} update(s), flagged {state['incidents']} incident(s).")


def main():
    parser = argparse.ArgumentParser(
        prog="jobless-router",
        description="BGP zero-trust route-leak / hijack fingerprinter.",
    )
    parser.add_argument("--replay", help="Path to a JSONL file of canned RIS-Live-style messages (no network needed).")
    parser.add_argument("--live", action="store_true", help="Connect to the real RIPE RIS Live firehose.")
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
        run_live(args.relationships, watchlist, args.db_dir, args.prefix, args.host, args.debug, args.more_specific)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
