import subprocess
from pathlib import Path

import pytest

from rehub import yara_fetch


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false",
         "-C", str(repo), *args],
        capture_output=True, text=True, check=True,
    )  # fmt: skip
    return proc.stdout.strip()


@pytest.fixture
def upstream(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "up"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "a.yar").write_text("rule A { condition: true }")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "one")
    pinned = git(repo, "rev-parse", "HEAD")
    (repo / "b.yar").write_text("rule B { condition: true }")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "two")
    return repo, pinned


def test_fetch_checks_out_pinned_commit(tmp_path: Path, upstream: tuple[Path, str]) -> None:
    repo, pinned = upstream
    dest = tmp_path / "rules"
    yara_fetch.fetch(dest, str(repo), pinned)
    assert (dest / "a.yar").exists()
    assert not (dest / "b.yar").exists()


def test_fetch_refuses_non_empty_dest(tmp_path: Path, upstream: tuple[Path, str]) -> None:
    repo, pinned = upstream
    dest = tmp_path / "rules"
    dest.mkdir()
    (dest / "keep.txt").write_text("x")
    with pytest.raises(yara_fetch.FetchError, match="not empty"):
        yara_fetch.fetch(dest, str(repo), pinned)
    assert (dest / "keep.txt").exists()
