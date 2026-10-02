import sqlite3
from pathlib import Path

import pytest

from rehub import baseline, db

NORMAL = [
    ("10.0.0.10", "10.0.0.20", "s7comm", "conn"),
    ("10.0.0.11", "10.0.0.21", "modbus", "conn"),
]


@pytest.fixture
def conn(tmp_path: Path) -> sqlite3.Connection:
    return db.connect(tmp_path / "t.db")


def make_run(conn: sqlite3.Connection, items: list[tuple[str, str, str, str]]) -> int:
    run_id = db.start_run(conn, "analyze", "sha", "zeek", "8.0.10")
    db.record_observations(conn, run_id, items)
    return run_id


def snapshot(conn: sqlite3.Connection) -> list[tuple[object, ...]]:
    return conn.execute(
        "SELECT b.name, b.sha256, b.locked, i.src, i.dst, i.protocol, i.action"
        " FROM baselines b JOIN baseline_items i ON i.baseline_id = b.id ORDER BY 1,4,5,6,7"
    ).fetchall()


def test_identical_run_is_clean(conn: sqlite3.Connection) -> None:
    baseline.save(conn, "n", make_run(conn, NORMAL))
    assert baseline.diff(conn, "n", make_run(conn, NORMAL)).clean


def test_new_pair(conn: sqlite3.Connection) -> None:
    baseline.save(conn, "n", make_run(conn, NORMAL))
    seen = [*NORMAL, ("10.0.0.99", "10.0.0.20", "s7comm", "conn")]
    result = baseline.diff(conn, "n", make_run(conn, seen))
    assert result.new_pairs == [("10.0.0.99", "10.0.0.20")]
    assert result.new_actions == []
    assert result.missing_pairs == []


def test_new_action_on_known_pair(conn: sqlite3.Connection) -> None:
    baseline.save(conn, "n", make_run(conn, NORMAL))
    seen = [*NORMAL, ("10.0.0.10", "10.0.0.20", "s7comm", "stop")]
    result = baseline.diff(conn, "n", make_run(conn, seen))
    assert result.new_actions == [("10.0.0.10", "10.0.0.20", "s7comm", "stop")]
    assert result.new_pairs == []


def test_new_protocol_on_known_pair(conn: sqlite3.Connection) -> None:
    baseline.save(conn, "n", make_run(conn, NORMAL))
    seen = [*NORMAL, ("10.0.0.10", "10.0.0.20", "modbus", "conn")]
    result = baseline.diff(conn, "n", make_run(conn, seen))
    assert result.new_actions == [("10.0.0.10", "10.0.0.20", "modbus", "conn")]


def test_missing_pair(conn: sqlite3.Connection) -> None:
    baseline.save(conn, "n", make_run(conn, NORMAL))
    result = baseline.diff(conn, "n", make_run(conn, NORMAL[:1]))
    assert result.missing_pairs == [("10.0.0.11", "10.0.0.21")]
    assert not result.clean


def test_diff_leaves_baseline_unchanged(conn: sqlite3.Connection) -> None:
    baseline.save(conn, "n", make_run(conn, NORMAL))
    before = snapshot(conn)
    drifted = [*NORMAL[:1], ("10.0.0.99", "10.0.0.20", "s7comm", "stop")]
    baseline.diff(conn, "n", make_run(conn, drifted))
    assert snapshot(conn) == before


def test_resave_same_name_refused(conn: sqlite3.Connection) -> None:
    baseline.save(conn, "n", make_run(conn, NORMAL))
    before = snapshot(conn)
    with pytest.raises(baseline.BaselineError, match="immutable"):
        baseline.save(conn, "n", make_run(conn, NORMAL[:1]))
    assert snapshot(conn) == before


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE baseline_items SET dst = 'x'",
        "DELETE FROM baseline_items",
        "INSERT INTO baseline_items VALUES (1, 'a', 'b', 'c', 'd')",
        "UPDATE baselines SET name = 'x'",
        "DELETE FROM baselines",
    ],
)
def test_database_rejects_mutation(conn: sqlite3.Connection, sql: str) -> None:
    baseline.save(conn, "n", make_run(conn, NORMAL))
    before = snapshot(conn)
    with pytest.raises(sqlite3.DatabaseError, match="immutable"):
        conn.execute(sql)
    assert snapshot(conn) == before


def test_run_without_observations_rejected(conn: sqlite3.Connection) -> None:
    empty = db.start_run(conn, "analyze", "sha", "suricata", "8.0.7")
    with pytest.raises(baseline.BaselineError, match="no observations"):
        baseline.save(conn, "n", empty)


def test_digest_is_order_independent(conn: sqlite3.Connection) -> None:
    a = baseline.save(conn, "a", make_run(conn, NORMAL))
    b = baseline.save(conn, "b", make_run(conn, list(reversed(NORMAL))))
    assert a == b
