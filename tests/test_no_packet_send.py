import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_guard_passes_on_repo() -> None:
    proc = subprocess.run(
        [str(ROOT / "scripts" / "check_no_send.sh")], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_guard_catches_a_raw_socket(tmp_path: Path) -> None:
    fake = tmp_path / "repo"
    (fake / "scripts").mkdir(parents=True)
    (fake / "src").mkdir()
    (fake / "fixtures").mkdir()
    (fake / "docker").mkdir()
    (fake / "fixtures" / "generate.py").write_text("")
    (fake / "docker" / "Dockerfile").write_text("")
    (fake / "src" / "bad.py").write_text(
        "import socket\ns = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)\n"
    )
    script = fake / "scripts" / "check_no_send.sh"
    script.write_text((ROOT / "scripts" / "check_no_send.sh").read_text())
    script.chmod(0o755)
    proc = subprocess.run([str(script)], capture_output=True, text=True)
    assert proc.returncode == 1
    assert "bad.py" in proc.stdout
