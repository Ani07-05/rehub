import tomllib
from dataclasses import dataclass
from pathlib import Path

from rehub import db

DEFAULT_IMAGE = "rehub:pinned"

DEFAULT_TEXT = f"""# rehub configuration. Environment variables and flags override these values.
image = "{DEFAULT_IMAGE}"
provider = "ollama"
# model = "your-ollama-model"
# registry_image = "ghcr.io/OWNER/rehub:0.1.0"
"""


class ConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class Config:
    image: str = DEFAULT_IMAGE
    provider: str = "ollama"
    model: str | None = None
    registry_image: str | None = None


def path() -> Path:
    return db.home() / "config.toml"


def load() -> Config:
    file = path()
    if not file.exists():
        return Config()
    try:
        data = tomllib.loads(file.read_text())
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{file}: {exc}") from exc
    defaults = Config()
    return Config(
        image=str(data.get("image", defaults.image)),
        provider=str(data.get("provider", defaults.provider)),
        model=str(data["model"]) if "model" in data else None,
        registry_image=str(data["registry_image"]) if "registry_image" in data else None,
    )


def write_default() -> bool:
    """Create the config file if missing. Returns True when a file was written."""
    file = path()
    if file.exists():
        return False
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(DEFAULT_TEXT)
    return True
