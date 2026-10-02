import os
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Protocol

INPUT = "{input}"
DEFAULT_IMAGE = "rehub:pinned"


class RunnerError(RuntimeError):
    pass


class Runner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        workdir: Path,
        input_file: Path | None = None,
        extra: Mapping[str, Path] | None = None,
    ) -> subprocess.CompletedProcess[str]: ...


def _inputs(input_file: Path | None, extra: Mapping[str, Path] | None) -> dict[str, Path]:
    found = dict(extra or {})
    if input_file is not None:
        found[INPUT] = input_file
    return found


class LocalRunner:
    def run(
        self,
        argv: Sequence[str],
        *,
        workdir: Path,
        input_file: Path | None = None,
        extra: Mapping[str, Path] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        paths = _inputs(input_file, extra)
        cmd = [str(paths[a]) if a in paths else a for a in argv]
        return subprocess.run(cmd, cwd=workdir, capture_output=True, text=True, check=False)


class DockerRunner:
    def __init__(self, image: str) -> None:
        self.image = image

    def run(
        self,
        argv: Sequence[str],
        *,
        workdir: Path,
        input_file: Path | None = None,
        extra: Mapping[str, Path] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        cmd = [
            "docker", "run", "--rm", "--network", "none",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "-v", f"{workdir.resolve()}:/out", "-w", "/out",
        ]  # fmt: skip
        targets: dict[str, str] = {}
        for token, path in _inputs(input_file, extra).items():
            target = f"/in/{token.strip('{}')}/{path.name}"
            cmd += ["-v", f"{path.resolve()}:{target}:ro"]
            targets[token] = target
        cmd += [self.image, *[targets.get(a, a) for a in argv]]
        try:
            return subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError as exc:
            raise RunnerError("docker not found on PATH") from exc


def default_runner(image: str | None = None) -> Runner:
    if image is None and os.environ.get("REHUB_IN_IMAGE"):
        return LocalRunner()
    return DockerRunner(image or DEFAULT_IMAGE)
