from pathlib import Path

from rehub.tools import zeek


def test_normalize_strips_volatile_and_sorts() -> None:
    raw = {
        "logs": {
            "conn": [
                {"ts": 2.0, "uid": "B", "duration": 0.5, "proto": "tcp", "port": 2},
                {"ts": 1.0, "uid": "A", "duration": 0.1, "proto": "tcp", "port": 1},
            ],
            "packet_filter": [{"ts": 1.0, "filter": "ip or not ip"}],
        }
    }
    assert zeek.normalize(raw) == {
        "logs": {"conn": [{"proto": "tcp", "port": 1}, {"proto": "tcp", "port": 2}]}
    }


def test_normalize_is_stable_across_uid_changes() -> None:
    a = {"logs": {"conn": [{"uid": "X", "ts": 1.0, "p": 1}]}}
    b = {"logs": {"conn": [{"uid": "Y", "ts": 9.0, "p": 1}]}}
    assert zeek.normalize(a) == zeek.normalize(b)


def test_run_parses_json_logs(tmp_path: Path) -> None:
    from conftest import FakeRunner

    runner = FakeRunner({"conn.log": '{"ts":1,"p":1}\n#close\n'})
    raw = zeek.run(runner, tmp_path / "x.pcap", tmp_path)
    assert raw == {"logs": {"conn": [{"ts": 1, "p": 1}]}}
