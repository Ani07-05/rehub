import json
import shutil
from pathlib import Path

import pytest
from conftest import FakeRunner

from rehub.doctor import check_tool, golden_path
from rehub.tools import zeek

LOGS = {"s7comm.log": '{"ts":1,"uid":"C1","function_name":"PLC Stop"}\n'}


@pytest.fixture
def fixtures(tmp_path: Path) -> Path:
    (tmp_path / "pcaps").mkdir()
    (tmp_path / "pcaps" / "demo.pcap").write_bytes(b"")
    return tmp_path


def test_accept_then_pass(fixtures: Path) -> None:
    runner = FakeRunner(LOGS)
    assert check_tool(zeek, runner, fixtures, accept=True).passed
    report = check_tool(zeek, runner, fixtures)
    assert report.passed
    assert report.version == "8.0.10"
    assert report.installed["ICSNPP::S7COMM"] == "1.3.0"


def test_missing_golden_fails(fixtures: Path) -> None:
    report = check_tool(zeek, FakeRunner(LOGS), fixtures)
    assert not report.passed
    assert "golden_missing" in report.results[0].diff


def test_changed_field_value_is_named(fixtures: Path) -> None:
    check_tool(zeek, FakeRunner(LOGS), fixtures, accept=True)
    changed = {"s7comm.log": '{"ts":1,"uid":"C1","function_name":"Stop CPU"}\n'}
    report = check_tool(zeek, FakeRunner(changed, version="9.0.0"), fixtures)
    assert not report.passed
    change = report.results[0].diff["logs"]["s7comm"]["rows_changed"][0]
    assert change["fields"] == ["function_name"]
    assert report.version == "9.0.0"


def test_removed_log_fails(fixtures: Path) -> None:
    check_tool(zeek, FakeRunner(LOGS), fixtures, accept=True)
    report = check_tool(zeek, FakeRunner({}), fixtures)
    assert report.results[0].diff["logs_removed"] == ["s7comm"]


def test_accept_writes_normalized_golden(fixtures: Path) -> None:
    check_tool(zeek, FakeRunner(LOGS), fixtures, accept=True)
    doc = json.loads(golden_path(fixtures, "zeek", "demo").read_text())
    assert doc == {"logs": {"s7comm": [{"function_name": "PLC Stop"}]}}


def test_repo_golden_exists_for_every_fixture() -> None:
    repo = Path(__file__).resolve().parents[1] / "fixtures"
    for pcap in (repo / "pcaps").glob("*.pcap"):
        assert golden_path(repo, "zeek", pcap.stem).exists()
    shutil.which("true")
