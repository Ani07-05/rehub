import json
import os
import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS tool_versions (
    id INTEGER PRIMARY KEY,
    tool TEXT NOT NULL,
    version TEXT NOT NULL,
    seen_at TEXT NOT NULL,
    UNIQUE (tool, version)
);
CREATE TABLE IF NOT EXISTS doctor_runs (
    id INTEGER PRIMARY KEY,
    tool TEXT NOT NULL,
    version TEXT NOT NULL,
    image TEXT NOT NULL,
    fixture TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('PASS', 'FAIL')),
    diff_json TEXT NOT NULL,
    at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    input_sha256 TEXT NOT NULL,
    tool TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    started_at TEXT NOT NULL,
    exit_code INTEGER,
    raw_path TEXT
);
CREATE TABLE IF NOT EXISTS observations (
    run_id INTEGER NOT NULL REFERENCES runs(id),
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    protocol TEXT NOT NULL,
    action TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS baselines (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    locked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS baseline_items (
    baseline_id INTEGER NOT NULL REFERENCES baselines(id),
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    protocol TEXT NOT NULL,
    action TEXT NOT NULL,
    UNIQUE (baseline_id, src, dst, protocol, action)
);
CREATE TRIGGER IF NOT EXISTS baselines_no_update BEFORE UPDATE ON baselines
WHEN OLD.locked = 1 BEGIN SELECT RAISE(ABORT, 'baseline is immutable'); END;
CREATE TRIGGER IF NOT EXISTS baselines_no_delete BEFORE DELETE ON baselines
BEGIN SELECT RAISE(ABORT, 'baseline is immutable'); END;
CREATE TRIGGER IF NOT EXISTS baseline_items_no_insert BEFORE INSERT ON baseline_items
WHEN (SELECT locked FROM baselines WHERE id = NEW.baseline_id) = 1
BEGIN SELECT RAISE(ABORT, 'baseline is immutable'); END;
CREATE TRIGGER IF NOT EXISTS baseline_items_no_update BEFORE UPDATE ON baseline_items
BEGIN SELECT RAISE(ABORT, 'baseline is immutable'); END;
CREATE TRIGGER IF NOT EXISTS baseline_items_no_delete BEFORE DELETE ON baseline_items
BEGIN SELECT RAISE(ABORT, 'baseline is immutable'); END;
"""


def home() -> Path:
    return Path(os.environ.get("REHUB_HOME", Path.home() / ".rehub"))


def connect(path: Path | None = None) -> sqlite3.Connection:
    path = path or home() / "rehub.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    return conn


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def record_tool_version(conn: sqlite3.Connection, tool: str, version: str) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO tool_versions (tool, version, seen_at) VALUES (?, ?, ?)",
        (tool, version, now()),
    )
    conn.commit()


def record_doctor_run(
    conn: sqlite3.Connection,
    tool: str,
    version: str,
    image: str,
    fixture: str,
    status: str,
    diff: dict[str, Any],
) -> None:
    conn.execute(
        "INSERT INTO doctor_runs (tool, version, image, fixture, status, diff_json, at)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        (tool, version, image, fixture, status, json.dumps(diff, sort_keys=True), now()),
    )
    conn.commit()


def start_run(
    conn: sqlite3.Connection, kind: str, input_sha256: str, tool: str, tool_version: str
) -> int:
    cur = conn.execute(
        "INSERT INTO runs (kind, input_sha256, tool, tool_version, started_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (kind, input_sha256, tool, tool_version, now()),
    )
    conn.commit()
    assert cur.lastrowid is not None
    return cur.lastrowid


def finish_run(
    conn: sqlite3.Connection, run_id: int, exit_code: int, raw_path: Path | None
) -> None:
    conn.execute(
        "UPDATE runs SET exit_code = ?, raw_path = ? WHERE id = ?",
        (exit_code, str(raw_path) if raw_path else None, run_id),
    )
    conn.commit()


def record_observations(
    conn: sqlite3.Connection, run_id: int, items: Iterable[tuple[str, str, str, str]]
) -> None:
    conn.executemany(
        "INSERT INTO observations (run_id, src, dst, protocol, action) VALUES (?, ?, ?, ?, ?)",
        [(run_id, *item) for item in items],
    )
    conn.commit()
