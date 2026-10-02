import subprocess
from pathlib import Path

from rehub.runner import RunnerError

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPO_ROOT / "docker" / "Dockerfile"


def _docker(*args: str, quiet: bool = False) -> int:
    try:
        proc = subprocess.run(
            ["docker", *args],
            check=False,
            stdout=subprocess.DEVNULL if quiet else None,
            stderr=subprocess.DEVNULL if quiet else None,
        )
    except FileNotFoundError as exc:
        raise RunnerError(
            "docker not found on PATH. Install Docker, then run setup again."
        ) from exc
    return proc.returncode


def present(image: str) -> bool:
    return _docker("image", "inspect", image, quiet=True) == 0


def pull(source: str, image: str) -> bool:
    if _docker("pull", source) != 0:
        return False
    return _docker("tag", source, image) == 0


def build(image: str) -> None:
    if not DOCKERFILE.exists():
        raise RunnerError(
            "no docker/Dockerfile next to this install and no registry image configured. "
            "Pass --source REGISTRY/IMAGE, or run setup from a checkout of the repository."
        )
    if _docker("build", "-f", str(DOCKERFILE), "-t", image, str(REPO_ROOT)) != 0:
        raise RunnerError("docker build failed, see the output above")


def ensure(image: str, source: str | None) -> str:
    """Make `image` available locally. Returns how: present, pulled or built."""
    if present(image):
        return "present"
    if source and pull(source, image):
        return "pulled"
    build(image)
    return "built"
