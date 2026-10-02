import json
import re
from pathlib import Path
from typing import Any

from rehub.runner import INPUT, Runner, RunnerError
from rehub.tools import Normalized

NAME = "yara"
PINNED = {"yara-x": "1.21.0"}
FIXTURES = ("yara/samples", "*")
SHIPPED_RULES = "/opt/rehub/yara/rules"

RULES = "{rules}"
TARGET = "{target}"
_VERSION_RE = re.compile(r"yara-x-cli (\S+)")


def installed(runner: Runner, workdir: Path) -> dict[str, str]:
    proc = runner.run(["yr", "--version"], workdir=workdir)
    match = _VERSION_RE.search(proc.stdout)
    if proc.returncode != 0 or not match:
        raise RunnerError(f"yr --version failed: {(proc.stderr or proc.stdout).strip()}")
    return {"yara-x": match.group(1)}


def compile_rules(runner: Runner, rules: Path, workdir: Path) -> str | None:
    """Return the compiler error text, or None when the rules compile."""
    proc = runner.run(
        ["yr", "compile", RULES, "-o", "rules.yarc"], workdir=workdir, extra={RULES: rules}
    )
    if proc.returncode == 0:
        return None
    return (proc.stderr or proc.stdout).strip() or f"yr compile exited {proc.returncode}"


def _relative(file: str, target: Path) -> str:
    if target.is_dir():
        for prefix in (f"/in/{TARGET.strip('{}')}/{target.name}/", f"{target}/"):
            if file.startswith(prefix):
                return file[len(prefix) :]
    return Path(file).name


def scan(runner: Runner, rules: Path, target: Path, workdir: Path) -> list[dict[str, str]]:
    argv = ["yr", "scan", "-o", "json", *(["-r"] if target.is_dir() else []), RULES, TARGET]
    proc = runner.run(argv, workdir=workdir, extra={RULES: rules, TARGET: target})
    if proc.returncode != 0:
        raise RunnerError(f"yr scan exited {proc.returncode}: {proc.stderr.strip()}")
    doc = json.loads(proc.stdout)
    return [
        {"rule": m["rule"], "file": _relative(m["file"], target)} for m in doc.get("matches", [])
    ]


def run(runner: Runner, sample: Path, workdir: Path) -> Normalized:
    argv = ["yr", "scan", "-o", "json", SHIPPED_RULES, INPUT]
    proc = runner.run(argv, workdir=workdir, input_file=sample)
    if proc.returncode != 0:
        raise RunnerError(f"yr scan exited {proc.returncode}: {proc.stderr.strip()}")
    return {"matches": [{"rule": m["rule"]} for m in json.loads(proc.stdout).get("matches", [])]}


def normalize(raw: Normalized) -> Normalized:
    rows: list[dict[str, Any]] = sorted(raw["matches"], key=lambda r: str(r["rule"]))
    return {"logs": {"matches": rows}}
