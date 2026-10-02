import hashlib
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rehub import db
from rehub.observations import Observation, extract
from rehub.runner import Runner, RunnerError
from rehub.tools import Tool, zeek


@dataclass
class ToolRun:
    tool: str
    run_id: int
    version: str
    summary: dict[str, int]
    error: str | None = None


@dataclass
class Analysis:
    runs: list[ToolRun]
    observations: set[Observation]
    zeek_run_id: int | None


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _summary(normalized: dict[str, Any]) -> dict[str, int]:
    return {name: len(rows) for name, rows in normalized["logs"].items()}


def analyze(
    pcap: Path, tools: list[Tool], runner: Runner, conn: sqlite3.Connection, home: Path
) -> Analysis:
    digest = sha256_file(pcap)
    runs: list[ToolRun] = []
    observations: set[Observation] = set()
    zeek_run_id: int | None = None
    for tool in tools:
        version = "unknown"
        run_id = db.start_run(conn, "analyze", digest, tool.NAME, version)
        raw_dir = home / "runs" / str(run_id)
        raw_dir.mkdir(parents=True, exist_ok=True)
        try:
            version = tool.installed(runner, raw_dir).get(tool.NAME, "unknown")
            conn.execute("UPDATE runs SET tool_version = ? WHERE id = ?", (version, run_id))
            normalized = tool.normalize(tool.run(runner, pcap, raw_dir))
        except RunnerError as exc:
            db.finish_run(conn, run_id, 1, raw_dir)
            runs.append(ToolRun(tool.NAME, run_id, version, {}, str(exc)))
            continue
        db.finish_run(conn, run_id, 0, raw_dir)
        db.record_tool_version(conn, tool.NAME, version)
        runs.append(ToolRun(tool.NAME, run_id, version, _summary(normalized)))
        if tool is zeek:
            zeek_run_id = run_id
            observations = extract(normalized)
            db.record_observations(conn, run_id, observations)
    return Analysis(runs, observations, zeek_run_id)
