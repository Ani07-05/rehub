import subprocess
from collections.abc import Sequence
from pathlib import Path


class FakeRunner:
    """Pretends to be a tool image: writes canned log files into the workdir."""

    def __init__(
        self, logs: dict[str, str], version: str = "8.0.10", plugins: str | None = None
    ) -> None:
        self.logs = logs
        self.version = version
        self.plugins = (
            plugins if plugins is not None else "ICSNPP::S7COMM - S7comm (dynamic, version 1.3.0)\n"
        )

    def run(
        self, argv: Sequence[str], *, workdir: Path, input_file: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        out = ""
        err = ""
        if "--version" in argv:
            out = f"zeek version {self.version}\n"
        elif "-N" in argv:
            err = self.plugins
        else:
            for name, text in self.logs.items():
                (workdir / name).write_text(text)
        return subprocess.CompletedProcess(list(argv), 0, out, err)
