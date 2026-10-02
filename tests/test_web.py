import json
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from rehub import baseline, db, web


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
