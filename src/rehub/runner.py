import os
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Protocol

INPUT = "{input}"
DEFAULT_IMAGE = "rehub:pinned"


class RunnerError(RuntimeError):
    pass


class Runner(Protocol):
    def run(
        self, argv: Sequence[str], *, workdir: Path, input_file: Path | None = None
    ) -> subprocess.CompletedProcess[str]: ...


class LocalRunner:
    def run(
        self, argv: Sequence[str], *, workdir: Path, input_file: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        cmd = [str(input_file) if a == INPUT and input_file else a for a in argv]
        return subprocess.run(cmd, cwd=workdir, capture_output=True, text=True, check=False)


class DockerRunner:
    def __init__(self, image: str) -> None:
        self.image = image

    def run(
        self, argv: Sequence[str], *, workdir: Path, input_file: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        cmd = [
            "docker", "run", "--rm", "--network", "none",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "-v", f"{workdir.resolve()}:/out", "-w", "/out",
        ]  # fmt: skip
        mapped = list(argv)
        if input_file is not None:
            target = f"/in/{input_file.name}"
            cmd += ["-v", f"{input_file.resolve()}:{target}:ro"]
            mapped = [target if a == INPUT else a for a in argv]
        cmd += [self.image, *mapped]
        try:
            return subprocess.run(cmd, capture_output=True, text=True, check=False)
        except FileNotFoundError as exc:
            raise RunnerError("docker not found on PATH") from exc


def default_runner(image: str | None = None) -> Runner:
    if image is None and os.environ.get("REHUB_IN_IMAGE"):
        return LocalRunner()
    return DockerRunner(image or DEFAULT_IMAGE)
