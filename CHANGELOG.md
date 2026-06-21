# Changelog

## v0.3.0 -- producer/consumer architecture

- **Decoupled receiving from processing.** The previous `--live` loop
  awaited the full scoring pipeline (including the RPKI HTTP call) before
  ever asking the websocket for the next message -- meaning slow
  processing directly delayed draining the socket, which is a plausible
  contributor to the ping-timeout disconnects seen repeatedly in earlier
  live testing. Now a dedicated producer task only receives and queues
  raw messages; a separate consumer task does the actual scoring. Bounded
  queue (10,000 items) for backpressure.
- **Added SOCKS5 proxy support** (`--proxy socks5://host:port`) via
  `python-socks`, for networks where a direct connection to
  ris-live.ripe.net isn't viable.
- **Made `--ping-interval`/`--ping-timeout` configurable** instead of
  hardcoded, in case a given network needs more or less tolerance than
  the defaults.
- **Fixed a real visibility gap**: the producer retries forever and never
  finishes on its own, so if only the producer were awaited (as an
  earlier draft of this change did), a crash in the consumer would die
  completely silently -- the program would look alive (still connected,
  still printing nothing wrong) while having actually stopped processing
  anything. Now both tasks are waited on together
  (`asyncio.wait(..., return_when=FIRST_EXCEPTION)`), so either crashing
  surfaces immediately, while a normal shutdown still lets the consumer
  drain whatever's already queued rather than cutting it off mid-item.
- Added an LRU-ish bound (50,000 entries) to `BlastRadiusTracker` so a
  long-running session can't grow its sightings dict unboundedly.

## v0.2.0 -- validated against real live traffic

Everything in this release was found by actually running `--live` against
the real RIPE RIS Live firehose, not just synthetic data. In rough
chronological order:

**Connectivity:**
- Fixed `--live` hanging indefinitely on networks where IPv6 routes but
  doesn't actually work (common on VirtualBox/VMware NAT) -- now forces
  IPv4-only resolution (`family=socket.AF_INET`).
- Raised the websocket handshake/keepalive timeouts for slower/NAT'd paths.
- Auto-reconnects with exponential backoff (up to 5 attempts) on dropped
  connections instead of dying -- transient drops are normal for any
  long-lived streaming connection. Resubscribes fresh each attempt and
  preserves heartbeat/incident counters across reconnects.
- Moved `engine.process()`'s blocking RPKI HTTP call off the event loop
  via `asyncio.to_thread()` -- running it directly inside the coroutine
  corrupted asyncio's cleanup on Ctrl+C.

**Correctness (the important one):**
- **Fixed a severe false positive**: Cloudflare's own legitimate,
  RPKI-VALID announcement of `1.1.1.0/24` was getting labeled
  `LIKELY_TARGETED_INTERCEPTION`. Root cause: baseline novelty (a
  never-before-seen upstream -- completely normal anycast/multi-homing
  behavior) tripped the interest gate even though RPKI had already
  cryptographically confirmed the route, and the heuristic scorer never
  checked RPKI validity at all. RPKI VALID now unconditionally overrides
  both the interest gate and the intent classifier.
- Fixed real BGP communities crashing parsing (`TypeError`) -- RIPE's live
  feed sends community values as JSON integers, not the strings the
  bundled demo data used.
- Fixed RIPEstat's RPKI status string `"unknown"` (the real, documented
  value for "no covering ROA exists") being misread as an error -- the
  code checked for `"not_found"` instead, which the live API never
  actually sends.
- The report now shows a dedicated "Baseline check" line explaining
  baseline-driven flags -- previously, a route with no RPKI opinion that
  got flagged purely on baseline novelty gave no visible explanation of
  *why*, even though the engine had computed it internally.

**Usability:**
- Added `--prefix` (with exact-match client-side filtering, since RIS
  Live's filter operates at the message level and a single update can
  legitimately bundle several prefixes sharing one path), `--host`
  (subscribe to one collector's full traffic instead of one prefix),
  `--more-specific` (catch sub-prefix hijacks within a watched block),
  and `--debug` (print every event's score, flagged or not, so silence
  is verifiable rather than just trusted).
- Caches RPKI lookups per (prefix, origin) for 5 minutes -- live path
  churn re-announces the same routes constantly, and querying RIPEstat
  fresh every time both wasted time and risked rate limits.
- Colorized ASCII-art startup banner (pyfiglet, falls back to plain text
  if unavailable).

## v0.1.1 -- code review fixes

Three real bugs caught in review, all fixed and covered by
`tests/test_review_fixes.py`:

1. **`find_complicit_upstream` mistook a prepended origin for the
   upstream.** `as_path[-2]` on a raw path breaks the moment the origin
   uses AS-path prepending (extremely common for traffic engineering) --
   e.g. `[2914, 15412, 18101, 18101, 18101]` would name AS18101 (the
   origin itself) as its own complicit upstream, completely missing
   AS15412. Fixed by collapsing consecutive duplicate hops before taking
   the second-to-last entry.

2. **`detect_path_anomaly` flagged ordinary transit-AS prepending as
   poisoning.** The original condition (`not adjacent or asn != origin`)
   flagged *any* repeated ASN that wasn't the origin, regardless of
   whether its repeats were adjacent -- so a transit network prepending
   itself (e.g. `[2914, 2914, 15412, 18101]`) was misclassified as a
   poisoning attack. Fixed by collapsing prepends first: anything still
   repeated after collapsing is, by construction, non-adjacent in the
   original path, which is the actual poisoning signal.

3. **`valley_free_check` couldn't see across an unmapped intermediate
   ASN** (most commonly an IXP route server, which is rarely present in
   CAIDA's relationship data). The original pairwise walk only ever
   compared immediate neighbors in the path, so a leak transiting an
   unmapped hop was invisible -- the one pair of ASNs that actually had
   relationship data on either side of the gap was never compared
   directly. Fixed with an anchored walk: when a relationship lookup is
   unknown, the last successfully-classified ASN is kept as an anchor and
   tried against progressively further hops until a known relationship
   bridges the gap.

Also reduced the weight of the "no known business relationship" signal in
`heuristics.targeted_mitm_score` from +20 to +10. CAIDA's AS-relationship
data is known to be thin for regional/domestic peering, so "no known
relationship" is genuinely ambiguous between "no relationship exists" and
"the dataset just doesn't have it" -- it's kept as a weak corroborating
signal rather than removed outright, since combined with other concrete
evidence (watchlist match, RPKI invalid, an actual valley-free violation)
it's still informative; it's just no longer weighted as if it were
itself a strong signal.
