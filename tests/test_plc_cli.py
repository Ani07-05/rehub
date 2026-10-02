from pathlib import Path

import pytest
from typer.testing import CliRunner

from rehub import cli

GOOD = "PROGRAM P\nVAR\n    Setpoint : INT := 80;\nEND_VAR\nEND_PROGRAM\n"


@pytest.fixture(autouse=True)
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("REHUB_HOME", str(tmp_path / "home"))
    return tmp_path


def run(*args: str) -> tuple[int, str]:
    result = CliRunner().invoke(cli.app, ["plc", *args])
    return result.exit_code, result.output


def test_check_flags_high_severity(home: Path) -> None:
    file = home / "p.st"
    file.write_text('Password := "x";\n')
    code, out = run("check", str(file))
    assert code == 1
    assert "HIGH" in out
    assert "no approved version" in out


def test_approve_then_changed_value_and_new_risk(home: Path) -> None:
    file = home / "p.st"
    file.write_text(GOOD)
    assert run("approve", str(file), "--name", "p")[0] == 0
    assert run("check", str(file))[0] == 0
    file.write_text(GOOD.replace(":= 80;", ":= 120;"))
    code, out = run("check", str(file))
    assert code == 0
    assert "value changed" in out
    file.write_text(GOOD.replace("END_PROGRAM", "STP();\nEND_PROGRAM"))
    code, out = run("check", str(file))
    assert code == 1
    assert "NEW HIGH" in out


def test_list_programs(home: Path) -> None:
    assert "no approved programs" in run("list")[1]
    file = home / "p.st"
    file.write_text(GOOD)
    run("approve", str(file), "--name", "boiler")
    assert "boiler" in run("list")[1]
