import json
import os
import sqlite3
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
"""


def home() -> Path:
    return Path(os.environ.get("REHUB_HOME", Path.home() / ".rehub"))


def connect(path: Path | None = None) -> sqlite3.Connection:
    path = path or home() / "rehub.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    return conn


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def record_tool_version(conn: sqlite3.Connection, tool: str, version: str) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO tool_versions (tool, version, seen_at) VALUES (?, ?, ?)",
        (tool, version, _now()),
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
        (tool, version, image, fixture, status, json.dumps(diff, sort_keys=True), _now()),
    )
    conn.commit()
