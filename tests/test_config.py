from pathlib import Path

import pytest
from typer.testing import CliRunner

from rehub import cli, config


@pytest.fixture(autouse=True)
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("REHUB_HOME", str(tmp_path))
    return tmp_path


def test_defaults_without_file() -> None:
    assert config.load() == config.Config()


def test_write_default_is_idempotent_and_loadable(home: Path) -> None:
    assert config.write_default() is True
    (home / "config.toml").write_text('image = "rehub:candidate"\nmodel = "m"\n')
    assert config.write_default() is False
    loaded = config.load()
    assert loaded.image == "rehub:candidate"
    assert loaded.model == "m"
    assert loaded.provider == "ollama"


def test_bad_toml_reported(home: Path) -> None:
    (home / "config.toml").write_text("image = ")
    with pytest.raises(config.ConfigError):
        config.load()


def test_init_creates_files_and_reports_mismatch(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "_check_tools", lambda image: False)
    result = CliRunner().invoke(cli.app, ["init"])
    assert result.exit_code == 1
    assert (home / "config.toml").exists()
    assert (home / "rehub.db").exists()
    assert "rehub setup" in result.output
