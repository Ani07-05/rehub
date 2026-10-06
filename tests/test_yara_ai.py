from pathlib import Path

import pytest
from typer.testing import CliRunner

from rehub import cli, yara_ai

GOOD = 'rule Good { strings: $a = "P_PROGRAM" condition: $a }'


class FakeProvider:
    def __init__(self, replies: list[str], hosted: bool = False) -> None:
        self.replies = list(replies)
        self.hosted = hosted
        self.name = "fake"
        self.sent: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.sent.append((system, user))
        return self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]


class FakeEngine:
    """Compiles anything containing 'condition:'; matches files by substring in their name."""

    def __init__(self, compile_ok: bool = True, matching: set[str] | None = None) -> None:
        self.compile_ok = compile_ok
        self.matching = matching or set()

    def compile(self, rule: str) -> str | None:
        ok = self.compile_ok and "condition:" in rule
        return None if ok else "error[E001]: syntax error"

    def matches(self, rule: str, target: Path) -> list[str]:
        if target.is_dir():
            return sorted(p.name for p in target.iterdir() if p.name in self.matching)
        return [target.name] if target.name in self.matching else []


@pytest.fixture
def samples(tmp_path: Path) -> tuple[Path, Path]:
    pos = tmp_path / "stop.bin"
    pos.write_bytes(b"SECRET-SAMPLE-CONTENT")
    benign = tmp_path / "benign"
    benign.mkdir()
    (benign / "ok.txt").write_text("fine")
    return pos, benign


def test_clean_rule_strips_fences_and_prose() -> None:
    raw = f"Here is your rule:\n```yara\n{GOOD}\n```\nHope it helps."
    assert yara_ai.clean_rule(raw) == GOOD
    assert yara_ai.clean_rule(f"Sure!\n{GOOD}") == GOOD
    assert yara_ai.clean_rule(GOOD) == GOOD


def test_validated_only_when_all_tests_pass(samples: tuple[Path, Path]) -> None:
    pos, benign = samples
    result = yara_ai.draft(
        FakeProvider([GOOD]), FakeEngine(matching={"stop.bin"}), "x", [pos], benign
    )
    assert result.status == "validated"
    assert result.positives == {"stop.bin": True}
    assert result.benign_hits == []


def test_broken_output_is_never_validated(samples: tuple[Path, Path]) -> None:
    pos, benign = samples
    provider = FakeProvider(["this is not yara"])
    result = yara_ai.draft(provider, FakeEngine(matching={"stop.bin"}), "x", [pos], benign)
    assert result.status == "unvalidated"
    assert result.reason == "does not compile"
    assert result.compile_error
    assert result.attempts == yara_ai.MAX_RETRIES + 1
    assert len(provider.sent) == yara_ai.MAX_RETRIES + 1
    assert result.positives == {}


def test_compile_error_is_fed_back_then_fixed(samples: tuple[Path, Path]) -> None:
    pos, benign = samples
    provider = FakeProvider(["rule Bad {", GOOD])
    result = yara_ai.draft(provider, FakeEngine(matching={"stop.bin"}), "x", [pos], benign)
    assert result.status == "validated"
    assert result.attempts == 2
    assert "syntax error" in provider.sent[1][1]
    assert "rule Bad {" in provider.sent[1][1]


def test_missing_positive_is_unvalidated(samples: tuple[Path, Path]) -> None:
    pos, benign = samples
    result = yara_ai.draft(FakeProvider([GOOD]), FakeEngine(matching=set()), "x", [pos], benign)
    assert result.status == "unvalidated"
    assert result.positives == {"stop.bin": False}


def test_benign_match_is_unvalidated(samples: tuple[Path, Path]) -> None:
    pos, benign = samples
    engine = FakeEngine(matching={"stop.bin", "ok.txt"})
    result = yara_ai.draft(FakeProvider([GOOD]), engine, "x", [pos], benign)
    assert result.status == "unvalidated"
    assert result.benign_hits == ["ok.txt"]


def test_no_positives_cannot_validate(samples: tuple[Path, Path]) -> None:
    _, benign = samples
    result = yara_ai.draft(FakeProvider([GOOD]), FakeEngine(), "x", [], benign)
    assert result.status == "unvalidated"
    assert result.reason == "no positive samples supplied"


def test_sample_contents_never_sent(samples: tuple[Path, Path]) -> None:
    pos, benign = samples
    provider = FakeProvider(["rule Bad {", GOOD])
    yara_ai.draft(provider, FakeEngine(matching={"stop.bin"}), "detect stop", [pos], benign)
    assert all("SECRET-SAMPLE-CONTENT" not in user for _, user in provider.sent)


def test_make_provider_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("REHUB_MODEL", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    with pytest.raises(yara_ai.ProviderError, match="model"):
        yara_ai.make_provider("ollama", None)
    with pytest.raises(yara_ai.ProviderError, match="ANTHROPIC_API_KEY"):
        yara_ai.make_provider("anthropic", None)
    with pytest.raises(yara_ai.ProviderError, match="unknown"):
        yara_ai.make_provider("nope", None)
    assert not yara_ai.make_provider("ollama", "m").hosted
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    assert yara_ai.make_provider("anthropic", None).hosted


def test_ollama_and_anthropic_payloads(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[str, dict[str, object], dict[str, str]]] = []

    def fake_post(
        url: str, payload: dict[str, object], headers: dict[str, str]
    ) -> dict[str, object]:
        seen.append((url, payload, headers))
        if "11434" in url:
            return {"message": {"content": "local"}}
        return {"content": [{"type": "text", "text": "hosted"}]}

    monkeypatch.setattr(yara_ai, "_post_json", fake_post)
    assert yara_ai.OllamaProvider("m").complete("sys", "usr") == "local"
    assert yara_ai.AnthropicProvider("claude-x", "key").complete("sys", "usr") == "hosted"
    assert seen[0][0] == "http://localhost:11434/api/chat"
    assert seen[1][0] == "https://api.anthropic.com/v1/messages"
    assert seen[1][2]["x-api-key"] == "key"
    assert seen[1][1]["system"] == "sys"


def test_hosted_draft_requires_yes_and_sends_nothing_without_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("REHUB_HOME", str(tmp_path))
    provider = FakeProvider([GOOD], hosted=True)
    monkeypatch.setattr(yara_ai, "make_provider", lambda name, model: provider)
    result = CliRunner().invoke(
        cli.app, ["yara", "draft", "detect plc stop", "--provider", "anthropic"]
    )
    assert result.exit_code == 2
    assert provider.sent == []
    assert "detect plc stop" in result.output
    assert "--yes" in result.output


def test_hosted_explain_requires_yes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    provider = FakeProvider(["explained"], hosted=True)
    monkeypatch.setattr(yara_ai, "make_provider", lambda name, model: provider)
    rule = tmp_path / "r.yar"
    rule.write_text(GOOD)
    cli_runner = CliRunner()
    blocked = cli_runner.invoke(cli.app, ["yara", "explain", str(rule), "--provider", "anthropic"])
    assert blocked.exit_code == 2
    assert provider.sent == []
    allowed = cli_runner.invoke(
        cli.app, ["yara", "explain", str(rule), "--provider", "anthropic", "--yes"]
    )
    assert allowed.exit_code == 0
    assert provider.sent == [(yara_ai.EXPLAIN_SYSTEM, GOOD)]


def test_groq_needs_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(yara_ai.ProviderError, match="GROQ_API_KEY"):
        yara_ai.make_provider("groq", None)


def test_groq_is_hosted_with_default_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GROQ_API_KEY", "k")
    monkeypatch.delenv("REHUB_MODEL", raising=False)
    provider = yara_ai.make_provider("groq", None)
    assert provider.hosted
    assert provider.name == "groq"
    assert isinstance(provider, yara_ai.GroqProvider)
    assert provider.model == yara_ai.DEFAULT_GROQ_MODEL


def test_groq_sends_chat_request(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake_post(
        url: str, payload: dict[str, object], headers: dict[str, str]
    ) -> dict[str, object]:
        seen.update(url=url, payload=payload, headers=headers)
        return {"choices": [{"message": {"content": GOOD}}]}

    monkeypatch.setattr(yara_ai, "_post_json", fake_post)
    reply = yara_ai.GroqProvider("m", "k").complete("sys", "usr")
    assert reply == GOOD
    assert seen["url"] == yara_ai.GROQ_URL
    assert seen["headers"] == {"authorization": "Bearer k", "user-agent": "rehub"}
    assert seen["payload"] == {
        "model": "m",
        "temperature": 0.2,
        "max_tokens": 1024,
        "messages": [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "usr"},
        ],
    }


def test_groq_rejects_odd_response(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(yara_ai, "_post_json", lambda url, payload, headers: {"choices": []})
    with pytest.raises(yara_ai.ProviderError, match="groq"):
        yara_ai.GroqProvider("m", "k").complete("s", "u")


def test_draft_prompt_asks_for_minimal_rules() -> None:
    assert "smallest rule" in yara_ai.DRAFT_SYSTEM
