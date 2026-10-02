import os
import stat
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rehub import capture, cli


@pytest.mark.parametrize("iface", ["any", "ANY", "", "eth0; rm -rf /", "a b", "-i"])
def test_invalid_or_unspecific_interface_refused(iface: str, tmp_path: Path) -> None:
    with pytest.raises(capture.CaptureError):
        capture.validate(iface, 5, tmp_path / "x.pcap")


@pytest.mark.parametrize("seconds", [0, -1, capture.MAX_SECONDS + 1])
def test_bad_duration_refused(seconds: int, tmp_path: Path) -> None:
    with pytest.raises(capture.CaptureError):
        capture.validate("eth0", seconds, tmp_path / "x.pcap")


def test_existing_output_refused(tmp_path: Path) -> None:
    out = tmp_path / "x.pcap"
    out.write_bytes(b"keep")
    with pytest.raises(capture.CaptureError, match="overwrite"):
        capture.validate("eth0", 5, out)
    assert out.read_bytes() == b"keep"


def test_command_is_read_only_tcpdump(tmp_path: Path) -> None:
    cmd = capture.command("eth0", tmp_path / "x.pcap")
    assert cmd[0] == "tcpdump"
    assert cmd[cmd.index("-i") + 1] == "eth0"
    assert "-nn" in cmd
    assert "-w" in cmd


def fake_tcpdump(bin_dir: Path, body: str) -> None:
    script = bin_dir / "tcpdump"
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)


def test_capture_stops_after_timeout_and_keeps_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_tcpdump(bin_dir, 'out=""; while [ $# -gt 0 ]; do [ "$1" = -w ] && out=$2; shift; done;'
                 ' trap "exit 0" INT; : > "$out"; while true; do sleep 0.1; done')  # fmt: skip
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    out = tmp_path / "x.pcap"
    capture.capture("eth0", 1, out)
    assert out.exists()


def test_missing_tcpdump_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(capture.CaptureError, match="tcpdump not found"):
        capture.capture("eth0", 1, tmp_path / "x.pcap")


def test_cli_requires_explicit_interface(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli.app, ["capture", "--seconds", "1", "--out", str(tmp_path / "x")]
    )
    assert result.exit_code != 0
    assert not (tmp_path / "x").exists()


def test_cli_states_it_only_listens(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(capture, "capture", lambda iface, seconds, out: None)
    result = CliRunner().invoke(
        cli.app,
        ["capture", "--iface", "eth0", "--seconds", "1", "--out", str(tmp_path / "x.pcap")],
    )
    assert result.exit_code == 0
    assert "never sends packets" in result.output
