import argparse
import asyncio
import json
import sys

from jobless_router.engine import JoblessRouterEngine
from jobless_router.firehose import replay_file, live_stream
from jobless_router.models import RPKIState

BANNER = r"""
   JOBLESS-ROUTER
   Reincarnated in a Tier-1 Scrubbing Center to Master BGP Flowspec
"""

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


def run_live(relationships: str, watchlist, db_dir: str):
    engine = JoblessRouterEngine(relationships_path=relationships, watchlist=watchlist, db_dir=db_dir)

    async def _go():
        print("[jobless-router] connecting to RIPE RIS Live firehose...")
        try:
            async for event in live_stream():
                incident = engine.process(event)
                if incident:
                    print(engine.render_incident(incident))
                    print("\n" + "=" * 80 + "\n")
        except Exception as exc:
            print(
                f"[jobless-router] could not reach the RIS Live firehose ({exc.__class__.__name__}: {exc}).\n"
                f"This usually means outbound access to ris-live.ripe.net is blocked by your network/proxy.\n"
                f"Try `python run.py --replay sample_events.jsonl` for an offline demo instead."
            )

    asyncio.run(_go())


def main():
    parser = argparse.ArgumentParser(
        prog="jobless-router",
        description="BGP zero-trust route-leak / hijack fingerprinter.",
    )
    parser.add_argument("--replay", help="Path to a JSONL file of canned RIS-Live-style messages (no network needed).")
    parser.add_argument("--live", action="store_true", help="Connect to the real RIPE RIS Live firehose.")
    parser.add_argument("--relationships", default="data/sample_as_relationships.txt", help="CAIDA-format AS relationship file.")
    parser.add_argument("--watchlist", default="data/watchlist.json", help="JSON list of critical prefixes to watch.")
    parser.add_argument("--db-dir", default=":memory:", help="Directory for sqlite threat/baseline DBs, or ':memory:' for an ephemeral run.")
    args = parser.parse_args()

    print(BANNER)
    watchlist = _load_watchlist(args.watchlist)

    if args.replay:
        run_replay(args.replay, args.relationships, watchlist, args.db_dir)
    elif args.live:
        run_live(args.relationships, watchlist, args.db_dir)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
