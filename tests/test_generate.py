from pathlib import Path

import generate

PCAPS = Path(__file__).resolve().parents[1] / "fixtures" / "pcaps"


def test_committed_pcaps_match_generator() -> None:
    for name, build in generate.FIXTURES.items():
        assert (PCAPS / f"{name}.pcap").read_bytes() == build().to_bytes()


def test_generator_is_deterministic() -> None:
    first = generate.build_s7_download_stop().to_bytes()
    assert first == generate.build_s7_download_stop().to_bytes()
