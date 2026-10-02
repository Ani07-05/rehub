import json
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rehub.diff import Diff, diff_normalized
from rehub.runner import Runner
from rehub.tools import Tool

FIXTURES_DIR = Path(__file__).resolve().parents[2] / "fixtures"


@dataclass
class FixtureResult:
    fixture: str
    status: str
    diff: Diff = field(default_factory=dict)


@dataclass
class ToolReport:
    tool: str
    installed: dict[str, str]
    pinned: dict[str, str]
    results: list[FixtureResult]

    @property
    def passed(self) -> bool:
        return all(r.status == "PASS" for r in self.results)

    @property
    def version(self) -> str:
        return self.installed.get(self.tool) or next(iter(self.installed.values()), "unknown")


def golden_path(fixtures: Path, tool: str, fixture: str) -> Path:
    return fixtures / "golden" / tool / f"{fixture}.json"


def _dump(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def check_tool(
    tool: Tool, runner: Runner, fixtures: Path = FIXTURES_DIR, accept: bool = False
) -> ToolReport:
    subdir, pattern = tool.FIXTURES
    pcaps = sorted(p for p in (fixtures / subdir).glob(pattern) if p.is_file())
    with tempfile.TemporaryDirectory(prefix="rehub-doctor-") as tmp:
        installed = tool.installed(runner, Path(tmp))
    results = []
    for pcap in pcaps:
        with tempfile.TemporaryDirectory(prefix="rehub-doctor-") as tmp:
            actual = tool.normalize(tool.run(runner, pcap, Path(tmp)))
        path = golden_path(fixtures, tool.NAME, pcap.stem)
        if accept:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(_dump(actual))
            results.append(FixtureResult(pcap.stem, "PASS"))
        elif not path.exists():
            results.append(FixtureResult(pcap.stem, "FAIL", {"golden_missing": str(path)}))
        else:
            diff = diff_normalized(json.loads(path.read_text()), actual)
            results.append(FixtureResult(pcap.stem, "FAIL" if diff else "PASS", diff))
    return ToolReport(tool.NAME, installed, dict(tool.PINNED), results)


def run_doctor(
    tools: Sequence[Tool], runner: Runner, fixtures: Path = FIXTURES_DIR, accept: bool = False
) -> list[ToolReport]:
    return [check_tool(t, runner, fixtures, accept) for t in tools]
