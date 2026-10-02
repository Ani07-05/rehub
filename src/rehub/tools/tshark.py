from pathlib import Path

from rehub.runner import INPUT, Runner, RunnerError
from rehub.tools import Normalized

NAME = "tshark"
PINNED = {"tshark": "4.4.19"}

FIELDS = (
    "frame.number",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "_ws.col.protocol",
    "_ws.col.info",
)


def installed(runner: Runner, workdir: Path) -> dict[str, str]:
    proc = runner.run(["tshark", "--version"], workdir=workdir)
    first = proc.stdout.splitlines()[0] if proc.stdout else ""
    if proc.returncode != 0 or not first.startswith("TShark"):
        raise RunnerError(f"tshark --version failed: {(proc.stderr or proc.stdout).strip()}")
    return {"tshark": first.rsplit(" ", 1)[-1].rstrip(".")}


def run(runner: Runner, pcap: Path, workdir: Path) -> Normalized:
    argv = ["tshark", "-r", INPUT, "-T", "fields", "-E", "separator=/t"]
    for field in FIELDS:
        argv += ["-e", field]
    proc = runner.run(argv, workdir=workdir, input_file=pcap)
    if proc.returncode != 0:
        raise RunnerError(f"tshark exited {proc.returncode}: {proc.stderr.strip()}")
    rows = []
    for line in proc.stdout.splitlines():
        cells = line.split("\t")
        cells += [""] * (len(FIELDS) - len(cells))
        rows.append(dict(zip(FIELDS, cells, strict=True)))
    return {"packets": rows}


def normalize(raw: Normalized) -> Normalized:
    return {"logs": {"packets": raw["packets"]}}
