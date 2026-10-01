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
