import shutil
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rehub.cli import app
from rehub.runner import DEFAULT_IMAGE

pytestmark = pytest.mark.docker


def image_available() -> bool:
    if not shutil.which("docker"):
        return False
    proc = subprocess.run(
        ["docker", "image", "inspect", DEFAULT_IMAGE], capture_output=True, check=False
    )
    return proc.returncode == 0


@pytest.mark.skipif(not image_available(), reason=f"{DEFAULT_IMAGE} not built")
def test_doctor_passes_on_pinned_image(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("REHUB_HOME", str(tmp_path))
    result = CliRunner().invoke(app, ["doctor"])
    assert result.exit_code == 0, result.output
    assert "zeek 8.0.10: PASS" in result.output


@pytest.mark.skipif(not image_available(), reason=f"{DEFAULT_IMAGE} not built")
def test_analyze_and_baseline_diff_end_to_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("REHUB_HOME", str(tmp_path))
    scenarios = Path(__file__).resolve().parents[1] / "fixtures" / "scenarios"
    cli = CliRunner()
    first = cli.invoke(app, ["analyze", str(scenarios / "plant_normal.pcap")])
    assert first.exit_code == 0, first.output
    assert cli.invoke(app, ["baseline", "save", "plant-normal", "--run", "1"]).exit_code == 0
    second = cli.invoke(app, ["analyze", str(scenarios / "plant_changed.pcap")])
    assert second.exit_code == 0, second.output
    diff = cli.invoke(app, ["baseline", "diff", "plant-normal", "--run", "4"])
    assert diff.exit_code == 1
    assert "NEW PAIR      10.0.0.99 -> 10.0.0.20" in diff.output
    assert "NEW ACTION    10.0.0.10 -> 10.0.0.20  s7comm  stop" in diff.output
    assert "MISSING PAIR  10.0.0.11 -> 10.0.0.21" in diff.output


@pytest.mark.skipif(not image_available(), reason=f"{DEFAULT_IMAGE} not built")
def test_yara_draft_against_real_yr(tmp_path: Path) -> None:
    from rehub import yara_ai
    from rehub.runner import DockerRunner

    root = Path(__file__).resolve().parents[1] / "fixtures" / "yara" / "samples"
    benign = tmp_path / "benign"
    benign.mkdir()
    (benign / "notes.txt").write_bytes((root / "benign.txt").read_bytes())
    engine = yara_ai.RunnerEngine(DockerRunner(DEFAULT_IMAGE))
    good = 'rule T { strings: $a = "P_PROGRAM" condition: $a }'

    class Canned:
        hosted = False
        name = "canned"

        def __init__(self, reply: str) -> None:
            self.reply = reply

        def complete(self, system: str, user: str) -> str:
            return self.reply

    stop = root / "s7_stop_payload.bin"
    ok = yara_ai.draft(Canned(f"```yara\n{good}\n```"), engine, "x", [stop], benign)
    assert ok.status == "validated", ok

    broken = yara_ai.draft(Canned("rule Bad { condition: $nope }"), engine, "x", [stop], benign)
    assert broken.status == "unvalidated"
    assert broken.compile_error
    assert "unknown pattern" in broken.compile_error

    misses = yara_ai.draft(Canned(good.replace("P_PROGRAM", "ZZZ")), engine, "x", [stop], benign)
    assert misses.status == "unvalidated"
    assert misses.positives == {"s7_stop_payload.bin": False}
