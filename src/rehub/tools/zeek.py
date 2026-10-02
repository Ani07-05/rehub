import json
import re
from pathlib import Path
from typing import Any

from rehub.runner import INPUT, Runner, RunnerError
from rehub.tools import Normalized

NAME = "zeek"
PINNED = {"zeek": "8.0.10", "ICSNPP::S7COMM": "1.3.0", "ICSNPP::ENIP": "1.3.0"}
FIXTURES = ("pcaps", "*.pcap")
SCRIPT = "/opt/rehub/zeek/rehub.zeek"

VOLATILE_FIELDS = frozenset(
    {"ts", "uid", "uids", "fuid", "fuids", "duration", "packet_correlation_id"}
)
IGNORED_LOGS = frozenset({"packet_filter", "loaded_scripts", "stats", "capture_loss"})

_VERSION_RE = re.compile(r"zeek version (\S+)")
_PLUGIN_RE = re.compile(r"^(ICSNPP::\S+) - .*\(.*version ([\d.]+)\)", re.MULTILINE)


def installed(runner: Runner, workdir: Path) -> dict[str, str]:
    ver = runner.run(["zeek", "--version"], workdir=workdir)
    match = _VERSION_RE.search(ver.stdout)
    if ver.returncode != 0 or not match:
        raise RunnerError(f"zeek --version failed: {ver.stderr.strip() or ver.stdout.strip()}")
    found = {"zeek": match.group(1)}
    plugins = runner.run(["zeek", "-N"], workdir=workdir)
    found.update({m[0]: m[1] for m in _PLUGIN_RE.findall(plugins.stderr + plugins.stdout)})
    return found


def run(runner: Runner, pcap: Path, workdir: Path) -> Normalized:
    proc = runner.run(["zeek", "-C", "-r", INPUT, SCRIPT], workdir=workdir, input_file=pcap)
    if proc.returncode != 0:
        raise RunnerError(f"zeek exited {proc.returncode}: {proc.stderr.strip()}")
    logs: dict[str, list[dict[str, Any]]] = {}
    for path in sorted(workdir.glob("*.log")):
        logs[path.stem] = [
            json.loads(line) for line in path.read_text().splitlines() if line.startswith("{")
        ]
    return {"logs": logs}


def normalize(raw: Normalized) -> Normalized:
    logs: dict[str, list[dict[str, Any]]] = {}
    for name, rows in raw["logs"].items():
        if name in IGNORED_LOGS:
            continue
        clean = [{k: v for k, v in row.items() if k not in VOLATILE_FIELDS} for row in rows]
        logs[name] = sorted(clean, key=lambda r: json.dumps(r, sort_keys=True))
    return {"logs": logs}
