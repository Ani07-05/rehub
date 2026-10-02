import pytest

from rehub import image
from rehub.runner import RunnerError


class FakeDocker:
    def __init__(self, fail: set[str] | None = None) -> None:
        self.calls: list[tuple[str, ...]] = []
        self.fail = fail or set()

    def __call__(self, *args: str, quiet: bool = False) -> int:
        self.calls.append(args)
        return 1 if args[0] in self.fail else 0


def use(monkeypatch: pytest.MonkeyPatch, fake: FakeDocker) -> FakeDocker:
    monkeypatch.setattr(image, "_docker", fake)
    return fake


def test_present_image_is_left_alone(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = use(monkeypatch, FakeDocker())
    assert image.ensure("rehub:pinned", "ghcr.io/o/rehub:1") == "present"
    assert [c[0] for c in fake.calls] == ["image"]


def test_missing_image_is_pulled_and_tagged(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = use(monkeypatch, FakeDocker({"image"}))
    assert image.ensure("rehub:pinned", "ghcr.io/o/rehub:1") == "pulled"
    assert fake.calls[-1] == ("tag", "ghcr.io/o/rehub:1", "rehub:pinned")


def test_failed_pull_falls_back_to_build(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = use(monkeypatch, FakeDocker({"image", "pull"}))
    assert image.ensure("rehub:pinned", "ghcr.io/o/rehub:1") == "built"
    assert fake.calls[-1][0] == "build"


def test_no_source_builds(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = use(monkeypatch, FakeDocker({"image"}))
    assert image.ensure("rehub:pinned", None) == "built"
    assert [c[0] for c in fake.calls] == ["image", "build"]


def test_build_failure_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    use(monkeypatch, FakeDocker({"image", "build"}))
    with pytest.raises(RunnerError, match="docker build failed"):
        image.ensure("rehub:pinned", None)


def test_build_without_dockerfile_explains(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pytest.TempPathFactory
) -> None:
    use(monkeypatch, FakeDocker({"image"}))
    monkeypatch.setattr(image, "DOCKERFILE", tmp_path / "nope")  # type: ignore[operator]
    with pytest.raises(RunnerError, match="--source"):
        image.ensure("rehub:pinned", None)
