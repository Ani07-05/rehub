import json
import os
import re
import tempfile
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from rehub.runner import Runner
from rehub.tools import yara

DRAFT_SYSTEM = (
    "You write YARA rules for the YARA-X engine. Reply with only the rule text, "
    "no explanation and no markdown. Use only features of YARA-X. "
    "Write the smallest rule that works: one or two distinctive strings or byte patterns "
    "taken from the description, a short condition, no metadata, no comments, and no imports "
    "unless the condition needs one. Prefer an exact short string over a wildcard or a regex. "
    "Never match generic content that benign files also contain."
)
EXPLAIN_SYSTEM = (
    "You explain YARA rules in plain English to an industrial control system defender. "
    "Say what the rule matches, how it could misfire, and what it cannot detect."
)
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-5-5"
DEFAULT_GROQ_MODEL = "openai/gpt-oss-120b"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
MAX_RETRIES = 3

_FENCE = re.compile(r"```(?:yara|yar)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_RULE_START = re.compile(r"^(import|include|rule|private|global)\b", re.MULTILINE)
_RULE_NAME = re.compile(r"\brule\s+([A-Za-z_]\w*)")


class ProviderError(RuntimeError):
    pass


class Provider(Protocol):
    name: str
    hosted: bool

    def complete(self, system: str, user: str) -> str: ...


def _post_json(url: str, payload: dict[str, object], headers: dict[str, str]) -> dict[str, object]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=300) as response:
            body: dict[str, object] = json.loads(response.read())
            return body
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise ProviderError(f"request to {url} failed: {exc}") from exc


@dataclass
class OllamaProvider:
    model: str
    url: str = "http://localhost:11434"
    name: str = "ollama"
    hosted: bool = False

    def complete(self, system: str, user: str) -> str:
        payload: dict[str, object] = {
            "model": self.model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        body = _post_json(f"{self.url}/api/chat", payload, {})
        message = body.get("message")
        if not isinstance(message, dict) or not isinstance(message.get("content"), str):
            raise ProviderError("unexpected response from ollama")
        return str(message["content"])


@dataclass
class AnthropicProvider:
    model: str
    api_key: str
    name: str = "anthropic"
    hosted: bool = True

    def complete(self, system: str, user: str) -> str:
        payload: dict[str, object] = {
            "model": self.model,
            "max_tokens": 2048,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"}
        body = _post_json("https://api.anthropic.com/v1/messages", payload, headers)
        blocks = body.get("content")
        if not isinstance(blocks, list):
            raise ProviderError("unexpected response from anthropic")
        return "".join(b["text"] for b in blocks if isinstance(b, dict) and "text" in b)


@dataclass
class GroqProvider:
    model: str
    api_key: str
    name: str = "groq"
    hosted: bool = True

    def complete(self, system: str, user: str) -> str:
        payload: dict[str, object] = {
            "model": self.model,
            "temperature": 0.2,
            "max_tokens": 1024,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        headers = {"authorization": f"Bearer {self.api_key}", "user-agent": "rehub"}
        body = _post_json(GROQ_URL, payload, headers)
        choices = body.get("choices")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise ProviderError("unexpected response from groq")
        message = choices[0].get("message")
        if not isinstance(message, dict) or not isinstance(message.get("content"), str):
            raise ProviderError("unexpected response from groq")
        return str(message["content"])


def make_provider(name: str, model: str | None, api_key: str | None = None) -> Provider:
    model = model or os.environ.get("REHUB_MODEL")
    if name == "ollama":
        if not model:
            raise ProviderError("ollama needs a model: pass --model or set REHUB_MODEL")
        return OllamaProvider(model, os.environ.get("REHUB_OLLAMA_URL", "http://localhost:11434"))
    if name == "anthropic":
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise ProviderError("anthropic needs an API key: paste one or set ANTHROPIC_API_KEY")
        return AnthropicProvider(model or DEFAULT_ANTHROPIC_MODEL, key)
    if name == "groq":
        key = api_key or os.environ.get("GROQ_API_KEY")
        if not key:
            raise ProviderError("groq needs an API key: paste one or set GROQ_API_KEY")
        return GroqProvider(model or DEFAULT_GROQ_MODEL, key)
    raise ProviderError(f"unknown provider {name!r} (use ollama, anthropic or groq)")


def draft_prompt(description: str) -> str:
    return f"Write a YARA rule for this: {description}"


def retry_prompt(rule: str, error: str) -> str:
    return (
        "This YARA rule failed to compile.\n\nRule:\n"
        f"{rule}\n\nCompiler error:\n{error}\n\nReturn a corrected rule only."
    )


def clean_rule(text: str) -> str:
    fenced = _FENCE.search(text)
    body = fenced.group(1) if fenced else text
    start = _RULE_START.search(body)
    return (body[start.start() :] if start else body).strip()


def rule_name(rule: str) -> str:
    match = _RULE_NAME.search(rule)
    return match.group(1) if match else "draft"


class Engine(Protocol):
    def compile(self, rule: str) -> str | None: ...

    def matches(self, rule: str, target: Path) -> list[str]: ...


class RunnerEngine:
    def __init__(self, runner: Runner) -> None:
        self.runner = runner

    def compile(self, rule: str) -> str | None:
        with tempfile.TemporaryDirectory(prefix="rehub-yara-") as tmp:
            path = Path(tmp) / "rules" / "draft.yar"
            path.parent.mkdir()
            path.write_text(rule)
            return yara.compile_rules(self.runner, path, Path(tmp))

    def matches(self, rule: str, target: Path) -> list[str]:
        with tempfile.TemporaryDirectory(prefix="rehub-yara-") as tmp:
            path = Path(tmp) / "rules" / "draft.yar"
            path.parent.mkdir()
            path.write_text(rule)
            found = yara.scan(self.runner, path, target, Path(tmp))
        return sorted({m["file"] for m in found})


@dataclass
class DraftResult:
    rule: str
    status: str
    attempts: int
    reason: str = ""
    compile_error: str | None = None
    positives: dict[str, bool] = field(default_factory=dict)
    benign_hits: list[str] = field(default_factory=list)


def draft(
    provider: Provider,
    engine: Engine,
    description: str,
    positives: list[Path],
    benign: Path | None,
    on_send: Callable[[str, str], None] | None = None,
) -> DraftResult:
    """Generate, compile with bounded retries, then test. Only a rule that compiles and passes
    every positive and benign check is marked validated."""
    user = draft_prompt(description)
    rule = ""
    error: str | None = None
    attempts = 0
    for attempt in range(1, MAX_RETRIES + 2):
        attempts = attempt
        if on_send:
            on_send(DRAFT_SYSTEM, user)
        rule = clean_rule(provider.complete(DRAFT_SYSTEM, user))
        error = engine.compile(rule)
        if error is None:
            break
        user = retry_prompt(rule, error)
    if error is not None:
        return DraftResult(rule, "unvalidated", attempts, "does not compile", compile_error=error)

    hits = {p.name: p.name in engine.matches(rule, p) for p in positives}
    benign_hits = engine.matches(rule, benign) if benign else []
    result = DraftResult(rule, "validated", attempts, positives=hits, benign_hits=benign_hits)
    if not positives:
        result.status, result.reason = "unvalidated", "no positive samples supplied"
    elif not all(hits.values()):
        result.status, result.reason = "unvalidated", "rule misses a positive sample"
    elif benign_hits:
        result.status, result.reason = "unvalidated", "rule matches a benign file"
    return result


def explain(provider: Provider, rule_text: str, on_send: Callable[[str, str], None] | None) -> str:
    if on_send:
        on_send(EXPLAIN_SYSTEM, rule_text)
    return provider.complete(EXPLAIN_SYSTEM, rule_text)
