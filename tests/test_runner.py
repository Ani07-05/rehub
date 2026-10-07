import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from rehub import runner


def _fake(stderr: str, code: int = 125) -> Callable[..., subprocess.CompletedProcess[str]]:
    def run(cmd: list[str], **_kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(cmd, code, stdout="", stderr=stderr)

    return run


def test_missing_image_says_how_to_build(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess, "run", _fake("Unable to find image 'rehub:pinned' locally\ndocker: denied")
    )
    with pytest.raises(runner.RunnerError, match="Run: rehub setup"):
        runner.DockerRunner("rehub:pinned").run(["zeek", "--version"], workdir=tmp_path)


def test_stopped_docker_says_start_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        subprocess,
        "run",
        _fake("Cannot connect to the Docker daemon at unix:///var/run/docker.sock"),
    )
    with pytest.raises(runner.RunnerError, match="Docker is not running"):
        runner.DockerRunner("rehub:pinned").run(["zeek", "--version"], workdir=tmp_path)
