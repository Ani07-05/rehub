import hashlib
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
CREATE TABLE IF NOT EXISTS yara_rules (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    text TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('validated', 'unvalidated')),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS plc_programs (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    filename TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    text TEXT NOT NULL,
    approved_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS device_labels (
    ip TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS plc_programs_no_update BEFORE UPDATE ON plc_programs
BEGIN SELECT RAISE(ABORT, 'approved programs are immutable'); END;
CREATE TRIGGER IF NOT EXISTS plc_programs_no_delete BEFORE DELETE ON plc_programs
BEGIN SELECT RAISE(ABORT, 'approved programs are immutable'); END;
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


def record_yara_rule(conn: sqlite3.Connection, name: str, text: str, status: str) -> int:
    cur = conn.execute(
        "INSERT INTO yara_rules (name, text, status, created_at) VALUES (?, ?, ?, ?)",
        (name, text, status, now()),
    )
    conn.commit()
    assert cur.lastrowid is not None
    return cur.lastrowid


def approve_plc_program(conn: sqlite3.Connection, name: str, filename: str, text: str) -> int:

    digest = hashlib.sha256(text.encode()).hexdigest()
    cur = conn.execute(
        "INSERT INTO plc_programs (name, filename, sha256, text, approved_at)"
        " VALUES (?, ?, ?, ?, ?)",
        (name, filename, digest, text, now()),
    )
    conn.commit()
    assert cur.lastrowid is not None
    return cur.lastrowid


def latest_plc_program(conn: sqlite3.Connection, name: str) -> tuple[int, str, str] | None:
    row = conn.execute(
        "SELECT id, sha256, text FROM plc_programs WHERE name = ? ORDER BY id DESC LIMIT 1", (name,)
    ).fetchone()
    return (row[0], row[1], row[2]) if row else None


def list_plc_programs(conn: sqlite3.Connection) -> list[dict[str, object]]:
    keys = ("id", "name", "filename", "sha256", "approved_at")
    rows = conn.execute(
        "SELECT id, name, filename, sha256, approved_at FROM plc_programs ORDER BY id DESC"
    ).fetchall()
    return [dict(zip(keys, r, strict=True)) for r in rows]


def set_device_label(conn: sqlite3.Connection, ip: str, label: str, replace: bool = True) -> None:
    label = label.strip()
    if not label:
        conn.execute("DELETE FROM device_labels WHERE ip = ?", (ip,))
    elif replace:
        conn.execute(
            "INSERT INTO device_labels (ip, label, updated_at) VALUES (?, ?, ?)"
            " ON CONFLICT(ip) DO UPDATE SET label = excluded.label,"
            " updated_at = excluded.updated_at",
            (ip, label, now()),
        )
    else:
        conn.execute(
            "INSERT OR IGNORE INTO device_labels (ip, label, updated_at) VALUES (?, ?, ?)",
            (ip, label, now()),
        )
    conn.commit()


def device_labels(conn: sqlite3.Connection) -> dict[str, str]:
    return {r[0]: r[1] for r in conn.execute("SELECT ip, label FROM device_labels ORDER BY ip")}
