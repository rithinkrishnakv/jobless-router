"""
Tracks repeat offenders by total cumulative bad-routing time, not just
incident count -- one network with a single six-hour leak is a different
threat profile than one with five ninety-second leaks.
"""
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS offenders (
    asn INTEGER PRIMARY KEY,
    incident_count INTEGER NOT NULL DEFAULT 0,
    total_bad_seconds REAL NOT NULL DEFAULT 0,
    first_seen REAL,
    last_seen REAL
);
"""


class ThreatDB:
    def __init__(self, path: str = "jobless_router_threat.db"):
        self.conn = sqlite3.connect(path)
        self.conn.execute(SCHEMA)
        self.conn.commit()

    def record_incident(self, asn: int, duration_seconds: float = 0.0):
        now = time.time()
        cur = self.conn.execute("SELECT incident_count FROM offenders WHERE asn=?", (asn,))
        row = cur.fetchone()
        if row is None:
            self.conn.execute(
                "INSERT INTO offenders (asn, incident_count, total_bad_seconds, first_seen, last_seen) "
                "VALUES (?, 1, ?, ?, ?)",
                (asn, duration_seconds, now, now),
            )
        else:
            self.conn.execute(
                "UPDATE offenders SET incident_count = incident_count + 1, "
                "total_bad_seconds = total_bad_seconds + ?, last_seen = ? WHERE asn=?",
                (duration_seconds, now, asn),
            )
        self.conn.commit()

    def is_repeat_offender(self, asn: int, threshold: int = 2) -> bool:
        cur = self.conn.execute("SELECT incident_count FROM offenders WHERE asn=?", (asn,))
        row = cur.fetchone()
        return bool(row and row[0] >= threshold)

    def leaderboard(self, limit: int = 10):
        cur = self.conn.execute(
            "SELECT asn, incident_count, total_bad_seconds FROM offenders "
            "ORDER BY total_bad_seconds DESC LIMIT ?",
            (limit,),
        )
        return cur.fetchall()
