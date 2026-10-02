import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

from rehub.tools import suricata, tshark


class Canned:
    def __init__(self, stdout: str = "", stderr: str = "", files: dict[str, str] | None = None):
        self.stdout, self.stderr, self.files = stdout, stderr, files or {}
        self.calls: list[list[str]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        workdir: Path,
        input_file: Path | None = None,
        extra: Mapping[str, Path] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append(list(argv))
        for name, text in self.files.items():
            (workdir / name).write_text(text)
        return subprocess.CompletedProcess(list(argv), 0, self.stdout, self.stderr)


def test_suricata_installed_parses_version(tmp_path: Path) -> None:
    runner = Canned(stdout="This is Suricata version 8.0.7 RELEASE\n")
    assert suricata.installed(runner, tmp_path) == {"suricata": "8.0.7"}


def test_suricata_normalize_filters_and_strips() -> None:
    raw = {
        "events": [
            {"event_type": "stats", "timestamp": "t"},
            {
                "event_type": "alert",
                "timestamp": "t1",
                "flow_id": 9,
                "pcap_cnt": 4,
                "src_ip": "1.1.1.1",
            },
            {
                "event_type": "flow",
                "timestamp": "t2",
                "flow": {"start": "a", "end": "b", "age": 1, "pkts_toserver": 3},
            },
        ],
        "errors": [],
    }
    assert suricata.normalize(raw) == {
        "logs": {
            "alert": [{"event_type": "alert", "src_ip": "1.1.1.1"}],
            "flow": [{"event_type": "flow", "flow": {"pkts_toserver": 3}}],
        }
    }


def test_suricata_engine_errors_become_a_log() -> None:
    raw = {"events": [], "errors": ["detect-parse: bad rule"]}
    assert suricata.normalize(raw) == {
        "logs": {"engine_errors": [{"message": "detect-parse: bad rule"}]}
    }


def test_suricata_run_collects_eve_and_errors(tmp_path: Path) -> None:
    runner = Canned(
        stderr="E: detect: boom\ni: fine\n",
        files={"eve.json": '{"event_type":"alert"}\n{"event_type":"stats"}\n'},
    )
    raw = suricata.run(runner, tmp_path / "x.pcap", tmp_path)
    assert [e["event_type"] for e in raw["events"]] == ["alert", "stats"]
    assert raw["errors"] == ["detect: boom"]
    assert "-k" in runner.calls[0]
    assert "none" in runner.calls[0]


def test_tshark_installed_and_rows(tmp_path: Path) -> None:
    assert tshark.installed(Canned(stdout="TShark (Wireshark) 4.4.18.\n"), tmp_path) == {
        "tshark": "4.4.18"
    }
    runner = Canned(stdout="1\t10.0.0.1\t10.0.0.2\t1\t102\tCOTP\tCR TPDU\n2\t\t\t\t\tARP\n")
    rows = tshark.run(runner, tmp_path / "x.pcap", tmp_path)["packets"]
    assert rows[0]["ip.src"] == "10.0.0.1"
    assert rows[1]["ip.src"] == ""
    assert rows[1]["_ws.col.protocol"] == "ARP"
