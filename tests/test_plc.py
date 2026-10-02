import sqlite3
from pathlib import Path

import pytest

from rehub import db, plc

APPROVED = """\
(* boiler control *)
PROGRAM Boiler
VAR
    Setpoint : INT := 80;
    InterlockOk : BOOL;
END_VAR
IF Temp > Setpoint THEN
    Valve := FALSE;
END_IF;
END_PROGRAM
"""


def ids(findings: list[plc.Finding]) -> set[str]:
    return {f.rule for f in findings}


def test_clean_program_has_no_findings() -> None:
    assert plc.analyze(APPROVED) == []


@pytest.mark.parametrize(
    ("line", "rule"),
    [
        ('AdminPassword := "hunter2";', "hardcoded-secret"),
        ("AdminPassword : STRING := 'hunter2';", "hardcoded-secret"),
        ("ApiKey : STRING[20] := 'abc123';", "hardcoded-secret"),
        ("STP();", "cpu-stop"),
        ("ForceOutput := TRUE;", "force-override"),
        ("SafetyInterlock := FALSE;", "interlock-off"),
        ("TCON(REQ := TRUE);", "network-call"),
        ('Target := "10.1.2.3";', "fixed-address"),
        ("WHILE TRUE DO", "endless-loop"),
        ("DebugMode := TRUE;", "test-mode-on"),
    ],
)
def test_each_rule_fires(line: str, rule: str) -> None:
    assert rule in ids(plc.analyze(f"PROGRAM P\n{line}\nEND_PROGRAM\n"))


def test_empty_secret_variables_are_not_flagged() -> None:
    assert plc.analyze("Password : STRING;\nPasswordOk := TRUE;\n") == []


def test_comments_are_ignored() -> None:
    text = '// AdminPassword := "x";\n(* STP(); *)\nx := 1;\n'
    assert plc.analyze(text) == []


def test_line_numbers_survive_block_comments() -> None:
    text = "(* a\nb\nc *)\nSTP();\n"
    assert [f.line for f in plc.analyze(text)] == [4]


def test_findings_are_sorted_high_first() -> None:
    found = plc.analyze("WHILE TRUE DO\nSTP();\n")
    assert [f.severity for f in found] == ["high", "medium"]


def test_every_finding_explains_itself() -> None:
    for finding in plc.analyze('STP();\nPassword := "x";\n'):
        assert finding.why
        assert finding.check


def test_l5x_logic_is_extracted() -> None:
    xml = "<RSLogix5000Content><Line><![CDATA[STP();]]></Line></RSLogix5000Content>"
    assert ids(plc.analyze(xml)) == {"cpu-stop"}


def test_compare_identical_is_unchanged() -> None:
    assert plc.compare(APPROVED, APPROVED).unchanged


def test_compare_reports_changed_setpoint_as_a_value_change() -> None:
    changed = APPROVED.replace(":= 80;", ":= 120;")
    result = plc.compare(APPROVED, changed)
    assert [(v.before, v.after) for v in result.value_changes] == [
        ("Setpoint : INT := 80;", "Setpoint : INT := 120;")
    ]
    assert result.added == [] and result.removed == []


def test_compare_flags_only_new_risks() -> None:
    risky = APPROVED.replace("END_PROGRAM", "TCON(REQ := TRUE);\nEND_PROGRAM")
    result = plc.compare(APPROVED, risky)
    assert ids(result.new_findings) == {"network-call"}
    assert result.added == ["TCON(REQ := TRUE);"]
    again = plc.compare(risky, risky)
    assert again.new_findings == []


def test_compare_ignores_line_shifts_and_whitespace() -> None:
    shifted = "\n\n" + APPROVED.replace("    Valve", "        Valve")
    assert plc.compare(APPROVED, shifted).unchanged


def test_resolved_findings_listed() -> None:
    before = APPROVED.replace("END_PROGRAM", "STP();\nEND_PROGRAM")
    assert ids(plc.compare(before, APPROVED).resolved_findings) == {"cpu-stop"}


@pytest.fixture
def conn(tmp_path: Path) -> sqlite3.Connection:
    return db.connect(tmp_path / "t.db")


def test_approved_programs_are_versioned_and_immutable(conn: sqlite3.Connection) -> None:
    first = db.approve_plc_program(conn, "boiler", "boiler.st", APPROVED)
    second = db.approve_plc_program(conn, "boiler", "boiler.st", APPROVED + "x := 1;\n")
    latest = db.latest_plc_program(conn, "boiler")
    assert latest is not None
    assert latest[0] == second > first
    for sql in ("UPDATE plc_programs SET text = 'x'", "DELETE FROM plc_programs"):
        with pytest.raises(sqlite3.DatabaseError, match="immutable"):
            conn.execute(sql)
    assert db.latest_plc_program(conn, "missing") is None
    assert len(db.list_plc_programs(conn)) == 2


def test_bundled_sample_programs_show_the_demo_story() -> None:
    root = Path(__file__).resolve().parents[1] / "fixtures" / "plc"
    approved = (root / "boiler_approved.st").read_text()
    updated = (root / "boiler_updated.st").read_text()
    assert plc.analyze(approved) == []
    result = plc.compare(approved, updated)
    assert [(v.before, v.after) for v in result.value_changes] == [
        ("Setpoint : INT := 80;", "Setpoint : INT := 120;")
    ]
    assert ids(result.new_findings) == {"hardcoded-secret", "network-call", "interlock-off"}


def test_call_with_address_is_one_finding() -> None:
    found = plc.analyze("TCON(REQ := TRUE, ADDR := '10.9.8.7');")
    assert ids(found) == {"network-call"}
