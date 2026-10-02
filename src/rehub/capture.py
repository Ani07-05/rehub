import re
import shutil
import signal
import subprocess
from pathlib import Path

MAX_SECONDS = 86_400
_IFACE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,31}$")
LISTEN_ONLY = "Listening only: rehub never sends packets. Capture is written to {out}."


class CaptureError(RuntimeError):
    pass


def validate(iface: str, seconds: int, out: Path) -> None:
    if not _IFACE.match(iface) or iface.lower() == "any":
        raise CaptureError("pass one explicit interface name (not 'any')")
    if not 1 <= seconds <= MAX_SECONDS:
        raise CaptureError(f"--seconds must be between 1 and {MAX_SECONDS}")
    if out.exists():
        raise CaptureError(f"{out} exists; refusing to overwrite a capture")


def command(iface: str, out: Path) -> list[str]:
    return ["tcpdump", "-i", iface, "-nn", "-s", "0", "-w", str(out)]


def capture(iface: str, seconds: int, out: Path) -> None:
    """Passive tcpdump capture for a fixed time. No packet is ever transmitted."""
    validate(iface, seconds, out)
    if shutil.which("tcpdump") is None:
        raise CaptureError("tcpdump not found on PATH (it is included in the rehub image)")
    proc = subprocess.Popen(
        command(iface, out), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True
    )
    try:
        proc.wait(timeout=seconds)
    except subprocess.TimeoutExpired:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    stderr = proc.stderr.read() if proc.stderr else ""
    if proc.returncode not in (0, -signal.SIGINT) or not out.exists():
        raise CaptureError(f"tcpdump failed (exit {proc.returncode}): {stderr.strip()}")
