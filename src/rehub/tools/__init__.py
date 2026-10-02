from pathlib import Path
from typing import Any, Protocol

from rehub.runner import Runner

Normalized = dict[str, Any]


class Tool(Protocol):
    NAME: str
    PINNED: dict[str, str]
    FIXTURES: tuple[str, str]

    def installed(self, runner: Runner, workdir: Path) -> dict[str, str]: ...

    def run(self, runner: Runner, pcap: Path, workdir: Path) -> Normalized: ...

    def normalize(self, raw: Normalized) -> Normalized: ...
