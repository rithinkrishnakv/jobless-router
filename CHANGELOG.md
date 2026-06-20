# Changelog

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
