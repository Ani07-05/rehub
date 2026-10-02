import base64
import binascii
import hashlib
import json
import os
import tempfile
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from rehub import baseline, config, db, report
from rehub.analyze import analyze as run_analysis
from rehub.diff import summarize
from rehub.doctor import FIXTURES_DIR, record_reports, run_doctor
from rehub.runner import Runner, RunnerError, default_runner
from rehub.tools import Tool, suricata, tshark, yara, zeek

PCAP_TOOLS: list[Tool] = [zeek, suricata, tshark]
TOOLS: list[Tool] = [*PCAP_TOOLS, yara]
LOOPBACK = frozenset({"127.0.0.1", "::1", "localhost"})
MAX_PCAP = 256 * 1024 * 1024
MAX_JSON = 32 * 1024 * 1024
CSRF_HEADER = "X-Rehub"

Json = dict[str, Any]


class ApiError(Exception):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def check_bind(host: str) -> None:
    if host not in LOOPBACK:
        raise ValueError("the web UI has no authentication and only binds to loopback")


def host_allowed(header: str | None) -> bool:
    """Accept only loopback Host headers, which also blocks DNS rebinding."""
    if not header:
        return False
    if header.startswith("["):
        host = header[1 : header.find("]")] if "]" in header else header
    else:
        host = header.split(":", 1)[0]
    return host in LOOPBACK


class Api:
    def __init__(self, image: str | None = None) -> None:
        self.image = image

    def _image(self, override: object = None) -> str:
        if isinstance(override, str) and override.strip():
            return override.strip()
        return self.image or config.load().image

    def _runner(self, image: str | None = None) -> Runner:
        try:
            return default_runner(image or self.image)
        except RunnerError as exc:
            raise ApiError(str(exc), 500) from exc

    def state(self) -> Json:
        conn = db.connect()
        try:
            data = report.snapshot(conn)
        finally:
            conn.close()
        data["image"] = self._image()
        return data

    def tools(self) -> Json:
        runner = self._runner()
        rows = []
        for tool in TOOLS:
            with tempfile.TemporaryDirectory(prefix="rehub-tools-") as tmp:
                try:
                    found = tool.installed(runner, Path(tmp))
                except RunnerError as exc:
                    raise ApiError(f"{tool.NAME}: {exc}", 502) from exc
            for component, pinned in tool.PINNED.items():
                have = found.get(component, "missing")
                rows.append(
                    {
                        "component": component,
                        "pinned": pinned,
                        "installed": have,
                        "ok": have == pinned,
                    }
                )
        return {"image": self._image(), "tools": rows}

    def doctor(self, body: Json) -> Json:
        image = self._image(body.get("image"))
        try:
            reports = run_doctor(TOOLS, self._runner(image), FIXTURES_DIR, accept=False)
        except RunnerError as exc:
            raise ApiError(str(exc), 502) from exc
        conn = db.connect()
        try:
            record_reports(conn, reports, image)
        finally:
            conn.close()
        return {
            "image": image,
            "passed": all(r.passed for r in reports),
            "reports": [
                {
                    "tool": r.tool,
                    "version": r.version,
                    "passed": r.passed,
                    "results": [
                        {"fixture": x.fixture, "status": x.status, "lines": summarize(x.diff)}
                        for x in r.results
                    ],
                }
                for r in reports
            ],
        }

    def analyze(self, filename: str, source: Path) -> Json:
        conn = db.connect()
        try:
            result = run_analysis(source, PCAP_TOOLS, self._runner(), conn, db.home())
        finally:
            conn.close()
        return {
            "filename": filename,
            "zeek_run_id": result.zeek_run_id,
            "runs": [
                {
                    "tool": r.tool,
                    "run_id": r.run_id,
                    "version": r.version,
                    "summary": r.summary,
                    "error": r.error,
                }
                for r in result.runs
            ],
            "observations": [list(o) for o in sorted(result.observations)],
        }

    def save_baseline(self, body: Json) -> Json:
        name, run = body.get("name"), body.get("run")
        if not isinstance(name, str) or not name.strip() or not isinstance(run, int):
            raise ApiError("name (text) and run (number) are required")
        conn = db.connect()
        try:
            digest = baseline.save(conn, name.strip(), run)
        except baseline.BaselineError as exc:
            raise ApiError(str(exc), 409) from exc
        finally:
            conn.close()
        return {"name": name.strip(), "sha256": digest}

    def yara_scan(self, body: Json) -> Json:
        rules, data, filename = body.get("rules"), body.get("data"), body.get("filename")
        if not isinstance(rules, str) or not rules.strip() or not isinstance(data, str):
            raise ApiError("rules (text) and a sample file are required")
        try:
            blob = base64.b64decode(data, validate=True)
        except binascii.Error as exc:
            raise ApiError("sample is not valid base64") from exc
        name = Path(str(filename or "sample")).name or "sample"
        with tempfile.TemporaryDirectory(prefix="rehub-web-") as tmp:
            rule_file = Path(tmp) / "rules" / "rules.yar"
            rule_file.parent.mkdir()
            rule_file.write_text(rules)
            sample = Path(tmp) / "target" / name
            sample.parent.mkdir()
            sample.write_bytes(blob)
            work = Path(tmp) / "work"
            work.mkdir()
            try:
                found = yara.scan(self._runner(), rule_file, sample, work)
            except RunnerError as exc:
                raise ApiError(str(exc), 422) from exc
        return {"matches": sorted({m["rule"] for m in found})}


def _store_upload(handler: BaseHTTPRequestHandler) -> tuple[str, Path]:
    length = int(handler.headers.get("Content-Length", "0"))
    if length <= 0:
        raise ApiError("the upload is empty")
    if length > MAX_PCAP:
        raise ApiError("the capture is larger than 256 MB", 413)
    filename = Path(unquote(handler.headers.get("X-Filename", "upload.pcap"))).name or "upload.pcap"
    uploads = db.home() / "uploads"
    uploads.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    fd, tmp_name = tempfile.mkstemp(dir=uploads, suffix=".part")
    remaining = length
    try:
        with os.fdopen(fd, "wb") as out:
            while remaining:
                chunk = handler.rfile.read(min(1 << 20, remaining))
                if not chunk:
                    raise ApiError("the upload ended early")
                out.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
        final = uploads / f"{digest.hexdigest()}.pcap"
        os.replace(tmp_name, final)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return filename, final


class Handler(BaseHTTPRequestHandler):
    api = Api()
    server_version = "rehub"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "connect-src 'self'; base-uri 'none'; form-action 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj: Json) -> None:
        self._send(status, json.dumps(obj).encode(), "application/json")

    def _guard(self, post: bool) -> bool:
        if not host_allowed(self.headers.get("Host")):
            self._json(403, {"error": "unexpected Host header"})
            return False
        if post and self.headers.get(CSRF_HEADER) != "1":
            self._json(403, {"error": f"missing {CSRF_HEADER} header"})
            return False
        return True

    def _read_json(self) -> Json:
        length = int(self.headers.get("Content-Length", "0"))
        if length > MAX_JSON:
            raise ApiError("the request is too large", 413)
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as exc:
            raise ApiError("the request is not valid JSON") from exc
        if not isinstance(body, dict):
            raise ApiError("a JSON object is expected")
        return body

    def _dispatch(self, call: Callable[[], Json]) -> None:
        try:
            self._json(200, call())
        except ApiError as exc:
            self._json(exc.status, {"error": str(exc)})
        except Exception as exc:  # keep the UI informed instead of dropping the socket
            self._json(500, {"error": f"{type(exc).__name__}: {exc}"})

    def do_GET(self) -> None:
        if not self._guard(post=False):
            return
        path = urlparse(self.path).path
        if path == "/":
            page = report.TEMPLATE.read_text()
            self._send(200, page.encode(), "text/html; charset=utf-8")
        elif path == "/api/state":
            self._dispatch(self.api.state)
        elif path == "/api/tools":
            self._dispatch(self.api.tools)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if not self._guard(post=True):
            return
        path = urlparse(self.path).path
        if path == "/api/analyze":
            self._dispatch(lambda: self.api.analyze(*_store_upload(self)))
        elif path == "/api/doctor":
            self._dispatch(lambda: self.api.doctor(self._read_json()))
        elif path == "/api/baselines":
            self._dispatch(lambda: self.api.save_baseline(self._read_json()))
        elif path == "/api/yara/scan":
            self._dispatch(lambda: self.api.yara_scan(self._read_json()))
        else:
            self._json(404, {"error": "not found"})


def make_server(host: str, port: int, image: str | None = None) -> ThreadingHTTPServer:
    check_bind(host)
    handler = type("BoundHandler", (Handler,), {"api": Api(image)})
    return ThreadingHTTPServer((host, port), handler)


def serve_in_thread(server: ThreadingHTTPServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread
