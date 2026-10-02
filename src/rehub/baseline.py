import hashlib
import json
import sqlite3
from dataclasses import dataclass, field

from rehub.db import now

Item = tuple[str, str, str, str]


class BaselineError(RuntimeError):
    pass


@dataclass
class BaselineDiff:
    new_pairs: list[tuple[str, str]] = field(default_factory=list)
    new_actions: list[Item] = field(default_factory=list)
    missing_pairs: list[tuple[str, str]] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not (self.new_pairs or self.new_actions or self.missing_pairs)


def run_items(conn: sqlite3.Connection, run_id: int) -> set[Item]:
    rows = conn.execute(
        "SELECT src, dst, protocol, action FROM observations WHERE run_id = ?", (run_id,)
    ).fetchall()
    if not rows:
        raise BaselineError(f"run {run_id} has no observations (use the zeek run id from analyze)")
    return {(r[0], r[1], r[2], r[3]) for r in rows}


def _digest(items: set[Item]) -> str:
    return hashlib.sha256(json.dumps(sorted(items)).encode()).hexdigest()


def save(conn: sqlite3.Connection, name: str, run_id: int) -> str:
    items = run_items(conn, run_id)
    if conn.execute("SELECT 1 FROM baselines WHERE name = ?", (name,)).fetchone():
        raise BaselineError(f"baseline {name!r} exists; baselines are immutable, pick a new name")
    digest = _digest(items)
    with conn:
        cur = conn.execute(
            "INSERT INTO baselines (name, created_at, sha256, locked) VALUES (?, ?, ?, 0)",
            (name, now(), digest),
        )
        conn.executemany(
            "INSERT INTO baseline_items (baseline_id, src, dst, protocol, action)"
            " VALUES (?, ?, ?, ?, ?)",
            [(cur.lastrowid, *item) for item in sorted(items)],
        )
        conn.execute("UPDATE baselines SET locked = 1 WHERE id = ?", (cur.lastrowid,))
    return digest


def list_baselines(conn: sqlite3.Connection) -> list[tuple[str, str, str, int]]:
    rows = conn.execute(
        "SELECT b.name, b.created_at, b.sha256, COUNT(i.src) FROM baselines b"
        " LEFT JOIN baseline_items i ON i.baseline_id = b.id GROUP BY b.id ORDER BY b.id"
    ).fetchall()
    return [(r[0], r[1], r[2], r[3]) for r in rows]


def baseline_items(conn: sqlite3.Connection, name: str) -> set[Item]:
    row = conn.execute("SELECT id FROM baselines WHERE name = ?", (name,)).fetchone()
    if row is None:
        raise BaselineError(f"no baseline named {name!r}")
    rows = conn.execute(
        "SELECT src, dst, protocol, action FROM baseline_items WHERE baseline_id = ?", (row[0],)
    ).fetchall()
    return {(r[0], r[1], r[2], r[3]) for r in rows}


def diff(conn: sqlite3.Connection, name: str, run_id: int) -> BaselineDiff:
    """Read-only comparison of a run against a baseline. Never writes."""
    base = baseline_items(conn, name)
    seen = run_items(conn, run_id)
    base_pairs = {(s, d) for s, d, _, _ in base}
    seen_pairs = {(s, d) for s, d, _, _ in seen}
    return BaselineDiff(
        new_pairs=sorted(seen_pairs - base_pairs),
        new_actions=sorted(i for i in seen - base if (i[0], i[1]) in base_pairs),
        missing_pairs=sorted(base_pairs - seen_pairs),
    )
