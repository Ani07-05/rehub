import json
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from rehub import baseline, db, web, yara_ai


@pytest.fixture
def server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ThreadingHTTPServer]:
    monkeypatch.setenv("REHUB_HOME", str(tmp_path))
    srv = web.make_server("127.0.0.1", 0)
    web.serve_in_thread(srv)
    yield srv
    srv.shutdown()
    srv.server_close()


def call(
    srv: ThreadingHTTPServer,
    path: str,
    method: str = "GET",
    body: Any = None,
    headers: dict[str, str] | None = None,
    host: str | None = None,
) -> tuple[int, dict[str, Any] | str]:
    port = srv.server_address[1]
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method)
    req.add_header("Host", host or f"127.0.0.1:{port}")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=10) as res:
            raw = res.read().decode()
            status = res.status
            ctype = res.headers.get("Content-Type", "")
    except urllib.error.HTTPError as exc:
        raw, status, ctype = exc.read().decode(), exc.code, exc.headers.get("Content-Type", "")
    return status, json.loads(raw) if "json" in ctype else raw


POST = {"X-Rehub": "1", "Content-Type": "application/json"}


def seed(items: list[tuple[str, str, str, str]]) -> int:
    conn = db.connect()
    run_id = db.start_run(conn, "analyze", "ab" * 32, "zeek", "8.0.10")
    db.record_observations(conn, run_id, items)
    conn.close()
    return run_id


def test_serves_the_page_in_live_mode(server: ThreadingHTTPServer) -> None:
    status, page = call(server, "/")
    assert status == 200
    assert isinstance(page, str)
    assert "const EMBEDDED = /*__REHUB_DATA__*/null;" in page


def test_refuses_to_bind_off_loopback() -> None:
    with pytest.raises(ValueError, match="loopback"):
        web.make_server("0.0.0.0", 0)


@pytest.mark.parametrize(
    "host", ["evil.example", "evil.example:8765", "127.0.0.1.evil.example", ""]
)
def test_rejects_foreign_host_headers(server: ThreadingHTTPServer, host: str) -> None:
    status, body = call(server, "/api/state", host=host or "x")
    if host == "":
        assert status in (200, 403)
        return
    assert status == 403
    assert isinstance(body, dict)


def test_host_allowed_parses_ports_and_ipv6() -> None:
    assert web.host_allowed("localhost:8765")
    assert web.host_allowed("127.0.0.1")
    assert web.host_allowed("[::1]:8765")
    assert not web.host_allowed(None)
    assert not web.host_allowed("localhost.evil.com")


def test_post_needs_the_custom_header(server: ThreadingHTTPServer) -> None:
    status, _ = call(
        server,
        "/api/baselines",
        "POST",
        {"name": "n", "run": 1},
        {"Content-Type": "application/json"},
    )
    assert status == 403


def test_state_save_baseline_and_diff(server: ThreadingHTTPServer) -> None:
    normal = seed(
        [("10.0.0.10", "10.0.0.20", "s7comm", "conn"), ("10.0.0.11", "10.0.0.21", "modbus", "conn")]
    )
    status, saved = call(
        server, "/api/baselines", "POST", {"name": "plant-normal", "run": normal}, POST
    )
    assert status == 200
    assert isinstance(saved, dict)
    changed = seed(
        [
            ("10.0.0.10", "10.0.0.20", "s7comm", "conn"),
            ("10.0.0.10", "10.0.0.20", "s7comm", "stop"),
            ("10.0.0.99", "10.0.0.20", "s7comm", "conn"),
        ]
    )
    status, state = call(server, "/api/state")
    assert status == 200
    assert isinstance(state, dict)
    diff = state["diffs"][f"plant-normal|{changed}"]
    assert diff["new_pairs"] == [["10.0.0.99", "10.0.0.20"]]
    assert diff["missing_pairs"] == [["10.0.0.11", "10.0.0.21"]]
    assert state["baselines"][0]["name"] == "plant-normal"


def test_baseline_cannot_be_overwritten(server: ThreadingHTTPServer) -> None:
    run = seed([("a", "b", "s7comm", "conn")])
    call(server, "/api/baselines", "POST", {"name": "n", "run": run}, POST)
    conn = db.connect()
    before = baseline.baseline_items(conn, "n")
    conn.close()
    status, body = call(server, "/api/baselines", "POST", {"name": "n", "run": run}, POST)
    assert status == 409
    assert isinstance(body, dict)
    assert "immutable" in body["error"]
    conn = db.connect()
    assert baseline.baseline_items(conn, "n") == before
    conn.close()


@pytest.mark.parametrize("payload", [{}, {"name": "", "run": 1}, {"name": "n", "run": "1"}])
def test_save_baseline_validates_input(
    server: ThreadingHTTPServer, payload: dict[str, Any]
) -> None:
    status, body = call(server, "/api/baselines", "POST", payload, POST)
    assert status == 400
    assert isinstance(body, dict)
    assert "required" in body["error"]


def test_unknown_run_is_a_clear_error(server: ThreadingHTTPServer) -> None:
    status, body = call(server, "/api/baselines", "POST", {"name": "n", "run": 99}, POST)
    assert status == 409
    assert isinstance(body, dict)
    assert "no observations" in body["error"]


def test_yara_scan_validates_input(server: ThreadingHTTPServer) -> None:
    status, _ = call(server, "/api/yara/scan", "POST", {"rules": "", "data": ""}, POST)
    assert status == 400
    status, body = call(
        server,
        "/api/yara/scan",
        "POST",
        {"rules": "rule a { condition: true }", "data": "***"},
        POST,
    )
    assert status == 400
    assert isinstance(body, dict)
    assert "base64" in body["error"]


def test_empty_upload_rejected(server: ThreadingHTTPServer) -> None:
    status, body = call(
        server, "/api/analyze", "POST", None, {"X-Rehub": "1", "Content-Length": "0"}
    )
    assert status == 400
    assert isinstance(body, dict)
    assert "empty" in body["error"]


def test_not_found(server: ThreadingHTTPServer) -> None:
    assert call(server, "/nope")[0] == 404
    assert call(server, "/nope", "POST", {}, POST)[0] == 404


def test_responses_carry_security_headers(server: ThreadingHTTPServer) -> None:
    port = server.server_address[1]
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=10) as res:
        assert "default-src 'none'" in res.headers["Content-Security-Policy"]
        assert res.headers["X-Frame-Options"] == "DENY"
        assert res.headers["Cache-Control"] == "no-store"


GOOD_RULE = 'rule Good { strings: $a = "P_PROGRAM" condition: $a }'


class FakeProvider:
    def __init__(self, hosted: bool, replies: list[str]) -> None:
        self.hosted = hosted
        self.name = "anthropic" if hosted else "ollama"
        self.replies = replies
        self.sent: list[str] = []

    def complete(self, system: str, user: str) -> str:
        self.sent.append(user)
        return self.replies.pop(0) if len(self.replies) > 1 else self.replies[0]


class FakeEngine:
    def __init__(self, runner: object) -> None:
        pass

    def compile(self, rule: str) -> str | None:
        return None if "condition:" in rule else "error: syntax"

    def matches(self, rule: str, target: Path) -> list[str]:
        if target.is_dir():
            return []
        return [target.name]


def b64(text: bytes) -> str:
    import base64

    return base64.b64encode(text).decode()


@pytest.fixture
def draft_env(monkeypatch: pytest.MonkeyPatch) -> dict[str, FakeProvider]:
    holder: dict[str, FakeProvider] = {}

    def make(name: str, model: str | None) -> FakeProvider:
        return holder["provider"]

    monkeypatch.setattr(yara_ai, "make_provider", make)
    monkeypatch.setattr(yara_ai, "RunnerEngine", FakeEngine)
    return holder


def draft_body(**extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "description": "S7 PLC stop",
        "positives": [{"filename": "stop.bin", "data": b64(b"SECRET-BYTES")}],
        "benign": [{"filename": "ok.txt", "data": b64(b"fine")}],
    }
    body.update(extra)
    return body


def test_hosted_draft_asks_for_confirmation_and_sends_nothing(
    server: ThreadingHTTPServer, draft_env: dict[str, FakeProvider]
) -> None:
    provider = FakeProvider(hosted=True, replies=[GOOD_RULE])
    draft_env["provider"] = provider
    status, body = call(server, "/api/yara/draft", "POST", draft_body(provider="anthropic"), POST)
    assert status == 200
    assert isinstance(body, dict)
    assert body["needs_confirmation"] is True
    assert body["provider"] == "anthropic"
    assert "S7 PLC stop" in body["user"]
    assert provider.sent == []


def test_hosted_draft_runs_after_confirmation_without_leaking_samples(
    server: ThreadingHTTPServer, draft_env: dict[str, FakeProvider]
) -> None:
    provider = FakeProvider(hosted=True, replies=["rule Bad {", GOOD_RULE])
    draft_env["provider"] = provider
    status, body = call(
        server, "/api/yara/draft", "POST", draft_body(provider="anthropic", yes=True), POST
    )
    assert status == 200
    assert isinstance(body, dict)
    assert body["status"] == "validated"
    assert body["attempts"] == 2
    assert all("SECRET-BYTES" not in text for text in provider.sent)


def test_local_draft_is_stored_with_its_status(
    server: ThreadingHTTPServer, draft_env: dict[str, FakeProvider]
) -> None:
    draft_env["provider"] = FakeProvider(hosted=False, replies=["not a rule"])
    status, body = call(server, "/api/yara/draft", "POST", draft_body(), POST)
    assert status == 200
    assert isinstance(body, dict)
    assert body["status"] == "unvalidated"
    assert body["reason"] == "does not compile"
    status, state = call(server, "/api/state")
    assert isinstance(state, dict)
    assert state["rules"][0]["status"] == "unvalidated"


def test_draft_input_validation(
    server: ThreadingHTTPServer, draft_env: dict[str, FakeProvider]
) -> None:
    draft_env["provider"] = FakeProvider(hosted=False, replies=[GOOD_RULE])
    assert call(server, "/api/yara/draft", "POST", {"description": " "}, POST)[0] == 400
    bad = draft_body(positives=[{"filename": "x", "data": "***"}])
    status, body = call(server, "/api/yara/draft", "POST", bad, POST)
    assert status == 400
    assert isinstance(body, dict)
    assert "base64" in body["error"]


def test_sample_listing_and_unknown_sample(server: ThreadingHTTPServer) -> None:
    status, body = call(server, "/api/samples")
    assert status == 200
    assert isinstance(body, dict)
    assert "plant_normal" in body["samples"]
    status, err = call(server, "/api/analyze-sample", "POST", {"name": "../../etc/passwd"}, POST)
    assert status == 400
    assert isinstance(err, dict)
    assert "unknown" in err["error"]


BOILER = "PROGRAM Boiler\nVAR\n    Setpoint : INT := 80;\nEND_VAR\nEND_PROGRAM\n"


def test_plc_check_without_approved_version(server: ThreadingHTTPServer) -> None:
    body = {"filename": "boiler.st", "text": BOILER + 'Password := "x";\n'}
    status, res = call(server, "/api/plc/check", "POST", body, POST)
    assert status == 200
    assert isinstance(res, dict)
    assert res["comparison"] is None
    assert res["counts"]["high"] == 1
    assert res["findings"][0]["why"]


def test_plc_approve_then_compare_shows_changes(server: ThreadingHTTPServer) -> None:
    status, _ = call(
        server,
        "/api/plc/approve",
        "POST",
        {"name": "boiler", "filename": "boiler.st", "text": BOILER},
        POST,
    )
    assert status == 200
    updated = BOILER.replace(":= 80;", ":= 120;").replace("END_PROGRAM", "STP();\nEND_PROGRAM")
    status, res = call(
        server, "/api/plc/check", "POST", {"filename": "boiler.st", "text": updated}, POST
    )
    assert status == 200
    assert isinstance(res, dict)
    comparison = res["comparison"]
    assert comparison["against"] == "boiler"
    assert comparison["value_changes"][0]["after"].endswith(":= 120;")
    assert [f["rule"] for f in comparison["new_findings"]] == ["cpu-stop"]
    status, state = call(server, "/api/state")
    assert isinstance(state, dict)
    assert state["plc_programs"][0]["name"] == "boiler"
    assert state["home"]


def test_plc_inputs_validated(server: ThreadingHTTPServer) -> None:
    assert call(server, "/api/plc/check", "POST", {"text": " "}, POST)[0] == 400
    assert call(server, "/api/plc/approve", "POST", {"name": "", "text": "x"}, POST)[0] == 400


def test_guide_answers_from_the_manual_without_a_model(server: ThreadingHTTPServer) -> None:
    status, res = call(
        server, "/api/guide", "POST", {"question": "where is my database stored"}, POST
    )
    assert status == 200
    assert isinstance(res, dict)
    assert res["source"] == "manual"
    assert "rehub.db" in res["answer"]
    status, res = call(
        server, "/api/guide", "POST", {"question": "how tall is the eiffel tower"}, POST
    )
    assert isinstance(res, dict)
    assert res["source"] == "none"
    assert res["topics"]


def test_guide_hosted_model_needs_confirmation_and_never_gets_more(
    server: ThreadingHTTPServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = FakeProvider(hosted=True, replies=["an answer"])
    monkeypatch.setattr(yara_ai, "make_provider", lambda name, model: provider)
    body = {"question": "explain new action", "use_model": True, "provider": "anthropic"}
    status, res = call(server, "/api/guide", "POST", body, POST)
    assert isinstance(res, dict)
    assert res["needs_confirmation"] is True
    assert provider.sent == []
    assert "MANUAL" in res["system"]
    status, res = call(server, "/api/guide", "POST", {**body, "yes": True}, POST)
    assert isinstance(res, dict)
    assert res["answer"] == "an answer"
    assert provider.sent == ["explain new action"]


def test_guide_validates_question(server: ThreadingHTTPServer) -> None:
    assert call(server, "/api/guide", "POST", {"question": ""}, POST)[0] == 400
    assert call(server, "/api/guide", "POST", {"question": "x" * 1001}, POST)[0] == 400


def test_device_labels_set_clear_and_validate(server: ThreadingHTTPServer) -> None:
    status, res = call(
        server, "/api/devices", "POST", {"ip": "10.0.0.20", "label": " Boiler PLC "}, POST
    )
    assert status == 200
    assert isinstance(res, dict)
    assert res["label"] == "Boiler PLC"
    status, state = call(server, "/api/state")
    assert isinstance(state, dict)
    assert state["device_labels"] == {"10.0.0.20": "Boiler PLC"}
    call(server, "/api/devices", "POST", {"ip": "10.0.0.20", "label": ""}, POST)
    _, state = call(server, "/api/state")
    assert isinstance(state, dict)
    assert state["device_labels"] == {}
    assert call(server, "/api/devices", "POST", {"ip": "not an ip", "label": "x"}, POST)[0] == 400
    assert (
        call(server, "/api/devices", "POST", {"ip": "10.0.0.1", "label": "x" * 61}, POST)[0] == 400
    )
    assert (
        call(server, "/api/devices", "POST", {"ip": "10.0.0.1", "label": "a\x01b"}, POST)[0] == 400
    )


def test_demo_runs_both_samples_and_saves_the_baseline_once(
    server: ThreadingHTTPServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    runs = iter(
        [
            [("10.0.0.10", "10.0.0.20", "s7comm", "conn")],
            [
                ("10.0.0.10", "10.0.0.20", "s7comm", "conn"),
                ("10.0.0.99", "10.0.0.20", "s7comm", "conn"),
            ],
            [("10.0.0.10", "10.0.0.20", "s7comm", "conn")],
            [("10.0.0.10", "10.0.0.20", "s7comm", "conn")],
        ]
    )

    def fake_analyze(self: web.Api, filename: str, source: Path) -> dict[str, Any]:
        return {
            "filename": filename,
            "zeek_run_id": seed(next(runs)),
            "runs": [],
            "observations": [],
        }

    monkeypatch.setattr(web.Api, "analyze", fake_analyze)
    status, res = call(server, "/api/demo", "POST", {}, POST)
    assert status == 200
    assert isinstance(res, dict)
    assert res["baseline"] == "plant-normal"
    status, state = call(server, "/api/state")
    assert isinstance(state, dict)
    assert [b["name"] for b in state["baselines"]] == ["plant-normal"]
    assert state["device_labels"]["10.0.0.20"] == "Boiler PLC"
    diff = state["diffs"][f"plant-normal|{res['changed_run']}"]
    assert diff["new_pairs"] == [["10.0.0.99", "10.0.0.20"]]
    call(server, "/api/devices", "POST", {"ip": "10.0.0.20", "label": "Main boiler"}, POST)
    status, again = call(server, "/api/demo", "POST", {}, POST)
    assert status == 200
    _, state = call(server, "/api/state")
    assert isinstance(state, dict)
    assert [b["name"] for b in state["baselines"]] == ["plant-normal"]
    assert state["device_labels"]["10.0.0.20"] == "Main boiler"
