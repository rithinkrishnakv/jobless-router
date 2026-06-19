# Jobless-Router
### *Reincarnated in a Tier-1 Scrubbing Center to Master BGP Flowspec*

[![tests](https://github.com/rithinkrishnakv/jobless-router/actions/workflows/tests.yml/badge.svg)](https://github.com/rithinkrishnakv/jobless-router/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A real-time BGP zero-trust threat-intelligence engine. It listens to the global
routing firehose, cryptographically validates announcements against live RPKI,
and scores *intent* — accidental misconfiguration vs. deliberate route leak vs.
targeted interception attempt — instead of just flagging "RPKI invalid" and
stopping there.

## What it actually does

1. **AS-path traversal** — names the exact "complicit" upstream transit
   provider that accepted a bad route from its origin and propagated it
   onward unfiltered.
2. **Intent heuristics** — two independent 0-100 scores:
   - *Fat-finger*: broad over-deaggregated prefix, RPKI `INVALID_LENGTH`.
   - *Targeted MITM*: highly specific prefix, hits a watched critical service,
     zero business relationship with the legitimate holder, breaks
     [valley-free routing](https://en.wikipedia.org/wiki/Valley-free_routing)
     (the Gao-Rexford property RFC 7908 leans on to define route leaks), or
     pairs with AS-path poisoning.
3. **BGP community decoding** — flags RFC 1997/7999 well-known communities,
   including the blackhole (RTBH) community, so a deliberate, operator-issued
   mitigation route doesn't get misclassified as a hijack.
4. **AS-path poisoning detection** — separates benign self-prepending
   (traffic engineering) from a non-origin ASN planted mid-path to dodge a
   specific network's own loop-prevention.
5. **Baseline deviation detection** — learns which origin ASNs and upstreams
   have legitimately announced each prefix before, so it can catch a leak
   even when there's no RPKI ROA to be cryptographically invalid against.
   (RPKI ROA coverage is still well under half the routed table — silence
   isn't innocence.)
6. **Blast-radius estimation** — counts how many distinct, geographically
   spread RIPE RIS route collectors saw the same bad route, as an honest,
   measurable propagation sample (PeeringDB describes peering relationships,
   not live RIB state, so it can't actually answer "what % of the internet
   accepted this" — this can).
7. **Repeat-offender tracking** — a small sqlite ledger of cumulative
   bad-routing time per ASN, not just incident counts.
8. **Certificate Transparency cross-check** — optionally polls `crt.sh` for
   suspicious certs issued near an incident window, the cross-layer signal
   that distinguishes "a route leaked" from "someone's trying to MITM TLS."
9. **Advisory mitigation playbook** — generates RTBH text, a BGP Flowspec
   (RFC 8955) rule, and Cisco/Juniper/Arista ACL config for a human to
   review. It deliberately never opens a live BGP session or pushes config
   automatically — false positives in *automated* mitigation can black-hole
   legitimate traffic faster than the hijack would have.

## Quick start

```bash
git clone https://github.com/rithinkrishnakv/jobless-router.git
cd jobless-router
pip install -r requirements.txt

# Offline demo -- six scripted scenarios, zero network dependency:
python run.py --replay sample_events.jsonl

# Sanity-check the detection logic itself:
python tests/test_demo.py

# The real thing -- connects to RIPE RIS Live's public websocket firehose,
# no API key needed. Requires normal outbound internet access.
python run.py --live
```

## The bundled demo (`sample_events.jsonl`)

Six canned, RIS-Live-shaped events that exercise every subsystem end to end
without touching the network:

| # | Scenario | What it proves |
|---|---|---|
| A | Clean route, baseline-establishing | Tool stays silent on legitimate traffic |
| B | Broad `/16`, `INVALID_LENGTH` | Fat-finger heuristic fires correctly |
| C | Watchlisted `/24`, rogue origin, no relationship | Targeted-MITM heuristic fires correctly |
| D | Repeated non-origin ASN mid-path | AS-path poisoning detector catches it, boosts MITM score |
| E | `/32` with the `65535:666` blackhole community | Community decoding suppresses a false alarm |
| F | Same prefix as A, new origin, no ROA at all | Baseline deviation catches a leak RPKI can't see |

Every prefix used is from an IANA-reserved documentation range (RFC 5737:
`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) except the one watchlist
example, Cloudflare's public `1.1.1.0/24` resolver — used purely to show the
watchlist mechanism working, not as a claim about any real event. All "rogue"
and "customer" ASNs are in the IANA private-use range (64512–65534).

## Swapping in real data for production use

- **AS relationships**: `data/sample_as_relationships.txt` is a tiny,
  hand-built illustrative subset. For real valley-free checking, download
  the actual dataset from
  [CAIDA's AS-relationships project](https://publicdata.caida.org/datasets/as-relationships/serial-2/)
  (same `as1|as2|relationship` format) and point `--relationships` at it.
- **Watchlist**: edit `data/watchlist.json` with the prefixes that actually
  matter to you.
- **RPKI**: `jobless_router/rpki.py` calls RIPEstat's free
  `rpki-validation` API — no key needed, just normal internet access.
- **Persistence**: pass `--db-dir /some/real/path` instead of the default
  `:memory:` so the baseline and repeat-offender databases survive restarts.

## Architecture

```
firehose.py  --> engine.py --(orchestrates)--> rpki.py
                              |--> path_analysis.py (traversal + poisoning)
                              |--> relationships.py (valley-free / Gao-Rexford)
                              |--> communities.py   (RFC1997/7999 decoding)
                              |--> baseline.py       (sqlite, learns "normal")
                              |--> blast_radius.py   (multi-collector sampling)
                              |--> heuristics.py     (intent scoring)
                              |--> threat_db.py      (sqlite, repeat offenders)
                              |--> ct_correlation.py (crt.sh cross-check)
                              |--> mitigation.py     (advisory playbook text)
                              `--> report.py          (markdown rendering)
```

## A note on scope and honesty

This is a genuinely functional detection and reporting pipeline, tested
end-to-end against synthetic data — but it's a single-operator tool, not a
substitute for MANRS-style coordinated filtering, and its sample
relationship graph and collector-region map are small/illustrative rather
than authoritative. Treat its output as a strong lead for a human analyst,
not an automated verdict, and keep mitigation actions behind a human
approval gate.
