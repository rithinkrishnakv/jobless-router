"""
Learns 'normal' for every prefix it observes: which origin ASNs and which
immediate upstreams have legitimately announced it before.

This matters because RPKI ROA coverage is still well under half the
routed table -- RPKI silence is not innocence. A prefix that suddenly
gets a never-before-seen origin or upstream is a real anomaly signal even
when there's no ROA to be cryptographically invalid against.
"""
import sqlite3
import time
import json
from typing import Tuple

SCHEMA = """
CREATE TABLE IF NOT EXISTS baseline (
    prefix TEXT PRIMARY KEY,
    origins TEXT NOT NULL DEFAULT '[]',
    upstreams TEXT NOT NULL DEFAULT '[]',
    first_seen REAL,
    last_seen REAL
);
"""


class BaselineStore:
    def __init__(self, path: str = "jobless_router_baseline.db"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.execute(SCHEMA)
        self.conn.commit()

    def observe(self, prefix: str, origin: int, upstream: int):
        now = time.time()
        cur = self.conn.execute("SELECT origins, upstreams FROM baseline WHERE prefix=?", (prefix,))
        row = cur.fetchone()
        if row is None:
            self.conn.execute(
                "INSERT INTO baseline (prefix, origins, upstreams, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
                (prefix, json.dumps([origin]), json.dumps([upstream] if upstream else []), now, now),
            )
        else:
            origins = set(json.loads(row[0])) | {origin}
            upstreams = set(json.loads(row[1])) | ({upstream} if upstream else set())
            self.conn.execute(
                "UPDATE baseline SET origins=?, upstreams=?, last_seen=? WHERE prefix=?",
                (json.dumps(list(origins)), json.dumps(list(upstreams)), now, prefix),
            )
        self.conn.commit()

    def is_novel(self, prefix: str, origin: int, upstream: int) -> Tuple[bool, str]:
        cur = self.conn.execute("SELECT origins, upstreams FROM baseline WHERE prefix=?", (prefix,))
        row = cur.fetchone()
        if row is None:
            return False, "First time seeing this prefix at all -- no baseline yet, can't call it anomalous."
        origins = set(json.loads(row[0]))
        upstreams = set(json.loads(row[1]))
        if origin not in origins:
            return True, f"AS{origin} has never originated {prefix} before (known origins: {sorted(origins)})."
        if upstream and upstream not in upstreams:
            return True, f"AS{upstream} has never been seen as upstream for {prefix} before."
        return False, "Consistent with established baseline."
