import json
import re
from pathlib import Path
from typing import Any

from rehub.runner import INPUT, Runner, RunnerError
from rehub.tools import Normalized

NAME = "suricata"
PINNED = {"suricata": "8.0.7"}
CONFIG = "/opt/suricata/etc/suricata/suricata.yaml"
RULES = "/opt/rehub/suricata/rehub.rules"
SETTINGS = {
    "app-layer.protocols.modbus.enabled": "yes",
    "app-layer.protocols.enip.enabled": "yes",
}

KEPT_EVENTS = frozenset({"alert", "anomaly", "flow"})
VOLATILE_TOP = frozenset({"timestamp", "flow_id", "pcap_cnt"})
VOLATILE_FLOW = frozenset({"start", "end", "age"})

_VERSION_RE = re.compile(r"Suricata version (\S+)")
_ERROR_RE = re.compile(r"^E: (.*)$", re.MULTILINE)


def installed(runner: Runner, workdir: Path) -> dict[str, str]:
    proc = runner.run(["suricata", "-V"], workdir=workdir)
    match = _VERSION_RE.search(proc.stdout + proc.stderr)
    if not match:
        raise RunnerError(f"suricata -V failed: {(proc.stderr or proc.stdout).strip()}")
    return {"suricata": match.group(1)}


def run(runner: Runner, pcap: Path, workdir: Path) -> Normalized:
    argv = [
        "suricata", "-r", INPUT, "-S", RULES, "-c", CONFIG, "-l", ".",
        "-k", "none", "--runmode", "single",
    ]  # fmt: skip
    for key, value in SETTINGS.items():
        argv += ["--set", f"{key}={value}"]
    proc = runner.run(argv, workdir=workdir, input_file=pcap)
    if proc.returncode != 0:
        raise RunnerError(f"suricata exited {proc.returncode}: {proc.stderr.strip()}")
    eve = workdir / "eve.json"
    events = [json.loads(line) for line in eve.read_text().splitlines()] if eve.exists() else []
    return {"events": events, "errors": _ERROR_RE.findall(proc.stderr)}


def _strip(event: dict[str, Any]) -> dict[str, Any]:
    out = {k: v for k, v in event.items() if k not in VOLATILE_TOP}
    if isinstance(out.get("flow"), dict):
        out["flow"] = {k: v for k, v in out["flow"].items() if k not in VOLATILE_FLOW}
    return out


def normalize(raw: Normalized) -> Normalized:
    logs: dict[str, list[dict[str, Any]]] = {}
    for event in raw["events"]:
        kind = event.get("event_type")
        if kind in KEPT_EVENTS:
            logs.setdefault(kind, []).append(_strip(event))
    if raw["errors"]:
        logs["engine_errors"] = [{"message": m} for m in raw["errors"]]
    return {
        "logs": {k: sorted(v, key=lambda r: json.dumps(r, sort_keys=True)) for k, v in logs.items()}
    }
