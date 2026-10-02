import json
import re
import sqlite3
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rehub import baseline, cli, db, report

NORMAL = [
    ("10.0.0.10", "10.0.0.20", "s7comm", "conn"),
    ("10.0.0.11", "10.0.0.21", "modbus", "conn"),
]
CHANGED = [
    ("10.0.0.10", "10.0.0.20", "s7comm", "conn"),
    ("10.0.0.10", "10.0.0.20", "s7comm", "stop"),
    ("10.0.0.99", "10.0.0.20", "s7comm", "conn"),
]


@pytest.fixture
def conn(tmp_path: Path) -> sqlite3.Connection:
    return db.connect(tmp_path / "t.db")


def make_run(conn: sqlite3.Connection, items: list[tuple[str, str, str, str]]) -> int:
    run_id = db.start_run(conn, "analyze", "ab" * 32, "zeek", "8.0.10")
    db.record_observations(conn, run_id, items)
    return run_id


def extract(html: str) -> dict[str, object]:
    match = re.search(r"const DATA = (.*?);\s*const VIEWS", html, re.DOTALL)
    assert match
    data: dict[str, object] = json.loads(match.group(1))
    return data


def test_snapshot_contains_precomputed_diffs(conn: sqlite3.Connection) -> None:
    first = make_run(conn, NORMAL)
    baseline.save(conn, "plant-normal", first)
    second = make_run(conn, CHANGED)
    data = report.snapshot(conn)
    diff = data["diffs"][f"plant-normal|{second}"]
    assert diff["new_pairs"] == [["10.0.0.99", "10.0.0.20"]]
    assert diff["new_actions"] == [["10.0.0.10", "10.0.0.20", "s7comm", "stop"]]
    assert diff["missing_pairs"] == [["10.0.0.11", "10.0.0.21"]]
    assert data["diffs"][f"plant-normal|{first}"]["clean"] is True
    assert str(second) in data["observations"]


def test_snapshot_reports_latest_doctor_result_per_fixture(conn: sqlite3.Connection) -> None:
    db.record_doctor_run(
        conn, "suricata", "8.0.7", "img", "fx", "FAIL", {"logs_removed": ["alert"]}
    )
    db.record_doctor_run(conn, "suricata", "8.0.7", "img", "fx", "PASS", {})
    rows = report.snapshot(conn)["doctor"]
    assert len(rows) == 1
    assert rows[0]["status"] == "PASS"


def test_snapshot_is_read_only(conn: sqlite3.Connection) -> None:
    baseline.save(conn, "n", make_run(conn, NORMAL))
    before = conn.execute("SELECT COUNT(*) FROM runs").fetchone()
    report.snapshot(conn)
    assert conn.execute("SELECT COUNT(*) FROM runs").fetchone() == before


def test_render_cannot_break_out_of_the_script(conn: sqlite3.Connection) -> None:
    baseline.save(conn, "</script><script>alert(1)</script>", make_run(conn, NORMAL))
    html = report.render(report.snapshot(conn))
    assert html.count("</script>") == 1
    data = extract(html)
    assert data["baselines"][0]["name"] == "</script><script>alert(1)</script>"  # type: ignore[index]


def test_render_without_data_keeps_template_placeholder_check() -> None:
    assert report.PLACEHOLDER in report.TEMPLATE.read_text()


def test_template_has_no_em_dash_and_no_external_resources() -> None:
    text = report.TEMPLATE.read_text()
    assert "—" not in text
    assert not re.search(r"(src|href)=[\"']https?://", text)


def test_cli_report_writes_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REHUB_HOME", str(tmp_path))
    out = tmp_path / "out" / "r.html"
    result = CliRunner().invoke(cli.app, ["report", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert "const DATA = {" in out.read_text()
