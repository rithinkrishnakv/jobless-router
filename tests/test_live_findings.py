"""
Regression test for a real false positive found while testing against the
actual live RIPE RIS Live feed: Cloudflare's own legitimate, RPKI-VALID
announcement of 1.1.1.0/24 / 1.0.0.0/24 got labeled LIKELY_TARGETED_INTERCEPTION
because a never-before-seen (but completely normal, anycast) upstream
tripped baseline novelty, and the heuristic scorer never checked RPKI
validity at all before assigning MITM points.

Run with: python tests/test_live_findings.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from jobless_router.engine import JoblessRouterEngine
from jobless_router.models import AnnouncementEvent, RPKIState


def test_rpki_valid_suppresses_anycast_false_positive():
    engine = JoblessRouterEngine(
        relationships_path=os.path.join(os.path.dirname(__file__), "..", "data", "sample_as_relationships.txt"),
        watchlist=["1.1.1.0/24"],
        db_dir=":memory:",
    )

    # First sighting: 1.1.1.0/24, origin 13335 (Cloudflare), via upstream 6939.
    # Establishes baseline. RPKI VALID. Must not be flagged (first sighting
    # is exempt from novelty anyway).
    e1 = AnnouncementEvent(
        timestamp=1, collector="rrc01", peer_asn="6939",
        prefix="1.1.1.0/24", as_path=[6939, 13335], communities=[],
    )
    incident1 = engine.process(e1, forced_rpki=RPKIState.VALID)
    assert incident1 is None, "First sighting of a valid route must stay silent."

    # Second sighting: SAME prefix, SAME legitimate origin, but a brand new
    # upstream (52873) -- completely normal anycast/multi-homing behavior.
    # RPKI still VALID. This is the exact shape that produced the false
    # positive against real Cloudflare traffic.
    e2 = AnnouncementEvent(
        timestamp=2, collector="rrc15", peer_asn="52873",
        prefix="1.1.1.0/24", as_path=[52873, 13335], communities=[],
    )
    incident2 = engine.process(e2, forced_rpki=RPKIState.VALID)
    assert incident2 is None, (
        "A new upstream for an RPKI-VALID route must not be flagged -- "
        "RPKI validity outranks baseline novelty."
    )


def test_rpki_valid_overrides_heuristics_if_reached_directly():
    # Defense in depth: even called directly, classify_intent must never
    # let heuristic scores produce a threat label when RPKI already
    # cryptographically confirmed the route.
    from jobless_router.heuristics import classify_intent
    result = classify_intent(fat_finger=80, mitm=90, blackhole=False, rpki_valid=True)
    assert result.label == "CONSISTENT_WITH_RPKI (origin cryptographically authorized)"
    assert result.confidence == 0


def test_live_reconnect_survives_repeated_drops():
    # --live wraps the firehose consumption loop in retry-with-backoff so
    # a transient disconnect (NAT idle timeouts, brief network hiccups --
    # both observed for real against rrc00) doesn't kill the whole run.
    # This exercises the same retry shape run.py uses, against a fake
    # stream that fails twice with ConnectionClosed then succeeds.
    import asyncio
    import websockets.exceptions

    async def fake_live_stream(state={"calls": 0}):
        state["calls"] += 1
        if state["calls"] <= 2:
            yield "msg"
            raise websockets.exceptions.ConnectionClosedError(None, None)
        else:
            yield "final-msg"
            return

    async def run_with_retry():
        processed = []
        attempt = 0
        max_retries = 5
        delay = 0.001  # fast for the test
        while True:
            try:
                async for item in fake_live_stream():
                    processed.append(item)
                    attempt = 0
                return processed
            except websockets.exceptions.ConnectionClosed:
                attempt += 1
                if attempt > max_retries:
                    return processed
                await asyncio.sleep(delay)

    result = asyncio.run(run_with_retry())
    assert result == ["msg", "msg", "final-msg"], result


def test_producer_consumer_crash_surfaces_instead_of_hanging():
    # run.py's --live mode runs a producer (receives off the websocket)
    # and a consumer (does the actual scoring) as separate asyncio tasks
    # joined by a queue, so slow processing can't delay draining the
    # socket (a likely contributor to the ping-timeout disconnects seen
    # against real rrc00 traffic). The risk: the producer retries forever
    # and never finishes on its own, so if only the producer is awaited,
    # a crash in the consumer would die silently -- the program would look
    # alive (still connected) while having actually stopped processing
    # anything. This proves asyncio.wait(..., FIRST_EXCEPTION) surfaces a
    # consumer crash immediately instead of hanging.
    import asyncio

    async def fake_producer_runs_forever():
        while True:
            await asyncio.sleep(0.01)

    async def fake_consumer_crashes():
        await asyncio.sleep(0.02)
        raise ValueError("simulated parse error")

    async def main():
        producer_task = asyncio.create_task(fake_producer_runs_forever())
        consumer_task = asyncio.create_task(fake_consumer_crashes())
        try:
            done, _ = await asyncio.wait(
                [producer_task, consumer_task], return_when=asyncio.FIRST_EXCEPTION
            )
            for t in done:
                if t.exception() is not None:
                    raise t.exception()
        finally:
            producer_task.cancel()

    raised = False
    try:
        asyncio.run(main())
    except ValueError as e:
        raised = True
        assert "simulated parse error" in str(e)
    assert raised, "consumer crash should have surfaced, not hung silently"


def main():
    tests = [
        test_rpki_valid_suppresses_anycast_false_positive,
        test_rpki_valid_overrides_heuristics_if_reached_directly,
        test_live_reconnect_survives_repeated_drops,
        test_producer_consumer_crash_surfaces_instead_of_hanging,
    ]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print("All live-finding regression tests passed.")


if __name__ == "__main__":
    main()
