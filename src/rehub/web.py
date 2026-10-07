import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
from collections.abc import Callable
from dataclasses import asdict
from email.message import Message
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from rehub import baseline, config, db, guide, plc, report, yara_ai
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
COOKIE = "rehub_session"

LOCKED_PAGE = Path(__file__).parent / "static" / "locked.html"

Json = dict[str, Any]


_IP = re.compile(r"^[0-9a-fA-F:.]{2,45}$")
DEMO_BASELINE = "plant-normal"
DEMO_LABELS = {"10.0.0.20": "Boiler PLC (sample)", "10.0.0.10": "Engineering laptop (sample)"}


def _api_key(body: Json) -> str | None:
    key = body.get("api_key")
    return key.strip() if isinstance(key, str) and key.strip() else None


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

    def set_device(self, body: Json) -> Json:
        ip, label = body.get("ip"), body.get("label", "")
        if not isinstance(ip, str) or not _IP.match(ip):
            raise ApiError("ip must be an address such as 10.0.0.20")
        if (
            not isinstance(label, str)
            or len(label.strip()) > 60
            or re.search(r"[\x00-\x1f]", label)
        ):
            raise ApiError("a device name is up to 60 characters of plain text")
        conn = db.connect()
        try:
            db.set_device_label(conn, ip, label)
        finally:
            conn.close()
        return {"ip": ip, "label": label.strip()}

    def demo(self) -> Json:
        names = self.samples()["samples"]
        if "plant_normal" not in names or "plant_changed" not in names:
            raise ApiError("the bundled sample recordings are missing from this install", 500)
        normal = self.analyze_sample({"name": "plant_normal"})
        if normal["zeek_run_id"] is None:
            raise ApiError(
                "the tools could not read the sample recording; check the tool image", 502
            )
        conn = db.connect()
        try:
            exists = conn.execute(
                "SELECT 1 FROM baselines WHERE name = ?", (DEMO_BASELINE,)
            ).fetchone()
            if not exists:
                baseline.save(conn, DEMO_BASELINE, normal["zeek_run_id"])
            for ip, label in DEMO_LABELS.items():
                db.set_device_label(conn, ip, label, replace=False)
        finally:
            conn.close()
        changed = self.analyze_sample({"name": "plant_changed"})
        if changed["zeek_run_id"] is None:
            raise ApiError(
                "the tools could not read the sample recording; check the tool image", 502
            )
        return {
            "baseline": DEMO_BASELINE,
            "normal_run": normal["zeek_run_id"],
            "changed_run": changed["zeek_run_id"],
        }

    def plc_check(self, body: Json) -> Json:
        filename, text = body.get("filename"), body.get("text")
        if not isinstance(text, str) or not text.strip():
            raise ApiError("choose a PLC program file with some text in it")
        name = Path(str(filename or "program")).name
        target = body.get("against") if isinstance(body.get("against"), str) else None
        target = (target or Path(name).stem).strip()
        findings = plc.analyze(text)
        conn = db.connect()
        try:
            approved = db.latest_plc_program(conn, target)
        finally:
            conn.close()
        comparison = None
        if approved:
            diff = plc.compare(approved[2], text)
            comparison = {
                "against": target,
                "approved_id": approved[0],
                "unchanged": diff.unchanged,
                "added": diff.added[:200],
                "removed": diff.removed[:200],
                "value_changes": [asdict(v) for v in diff.value_changes[:200]],
                "new_findings": [asdict(f) for f in diff.new_findings],
                "resolved_findings": [asdict(f) for f in diff.resolved_findings],
            }
        counts = {"high": 0, "medium": 0, "low": 0}
        for finding in findings:
            counts[finding.severity] += 1
        return {
            "filename": name,
            "name": Path(name).stem,
            "findings": [asdict(f) for f in findings],
            "counts": counts,
            "comparison": comparison,
        }

    def plc_approve(self, body: Json) -> Json:
        name, text = body.get("name"), body.get("text")
        if not isinstance(name, str) or not name.strip():
            raise ApiError("name the program, for example the controller or project name")
        if not isinstance(text, str) or not text.strip():
            raise ApiError("choose a PLC program file with some text in it")
        conn = db.connect()
        try:
            program_id = db.approve_plc_program(
                conn, name.strip(), Path(str(body.get("filename") or "program")).name, text
            )
        finally:
            conn.close()
        return {"id": program_id, "name": name.strip()}

    def ask_guide(self, body: Json) -> Json:
        question = body.get("question")
        if not isinstance(question, str) or not question.strip() or len(question) > 1000:
            raise ApiError("type a question of up to 1000 characters")
        home = str(db.home())
        answer = guide.ask(question, home)
        if not body.get("use_model"):
            if answer.found:
                return {"source": "manual", "title": answer.title, "answer": answer.text}
            return {"source": "none", "answer": None, "topics": guide.titles()}
        try:
            cfg = config.load()
            provider = yara_ai.make_provider(
                str(body.get("provider") or cfg.provider),
                body.get("model") or cfg.model,
                _api_key(body),
            )
        except (yara_ai.ProviderError, config.ConfigError) as exc:
            raise ApiError(str(exc)) from exc
        system = guide.model_system(home)
        if provider.hosted and body.get("yes") is not True:
            return {
                "needs_confirmation": True,
                "provider": provider.name,
                "system": system,
                "user": question.strip(),
            }
        try:
            reply = provider.complete(system, question.strip())
        except yara_ai.ProviderError as exc:
            raise ApiError(str(exc), 502) from exc
        return {"source": "model", "provider": provider.name, "answer": reply.strip()}

    def samples(self) -> Json:
        folder = FIXTURES_DIR / "scenarios"
        names = sorted(p.stem for p in folder.glob("*.pcap")) if folder.is_dir() else []
        return {"samples": names}

    def analyze_sample(self, body: Json) -> Json:
        name = body.get("name")
        if not isinstance(name, str) or name not in self.samples()["samples"]:
            raise ApiError("unknown sample capture")
        return self.analyze(f"{name}.pcap", FIXTURES_DIR / "scenarios" / f"{name}.pcap")

    def yara_draft(self, body: Json) -> Json:
        description = body.get("description")
        if not isinstance(description, str) or not description.strip():
            raise ApiError("describe what the rule should detect")
        try:
            cfg = config.load()
            name = body.get("provider") or cfg.provider
            model = body.get("model") or cfg.model
            provider = yara_ai.make_provider(
                str(name), str(model) if model else None, _api_key(body)
            )
        except (yara_ai.ProviderError, config.ConfigError) as exc:
            raise ApiError(str(exc)) from exc
        if provider.hosted and body.get("yes") is not True:
            return {
                "needs_confirmation": True,
                "provider": provider.name,
                "system": yara_ai.DRAFT_SYSTEM,
                "user": yara_ai.draft_prompt(description.strip()),
            }
        sent: list[str] = []

        def on_send(system: str, user: str) -> None:
            sent.append(user)

        with tempfile.TemporaryDirectory(prefix="rehub-draft-") as tmp:
            root = Path(tmp)
            (root / "positive").mkdir()
            (root / "benign").mkdir()
            positives = _decode_files(body.get("positives"), root / "positive", "positive")
            benign = _decode_files(body.get("benign"), root / "benign", "benign")
            try:
                result = yara_ai.draft(
                    provider,
                    yara_ai.RunnerEngine(self._runner()),
                    description.strip(),
                    positives,
                    root / "benign" if benign else None,
                    on_send,
                )
            except yara_ai.ProviderError as exc:
                raise ApiError(str(exc), 502) from exc
            except RunnerError as exc:
                raise ApiError(str(exc), 502) from exc
        conn = db.connect()
        try:
            db.record_yara_rule(conn, yara_ai.rule_name(result.rule), result.rule, result.status)
        finally:
            conn.close()
        return {
            "provider": provider.name,
            "rule": result.rule,
            "status": result.status,
            "reason": result.reason,
            "attempts": result.attempts,
            "compile_error": result.compile_error,
            "positives": result.positives,
            "benign_hits": result.benign_hits,
            "requests_sent": len(sent),
        }

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


def _decode_files(items: object, directory: Path, label: str) -> list[Path]:
    if items in (None, []):
        return []
    if not isinstance(items, list):
        raise ApiError(f"{label} must be a list of files")
    paths = []
    for index, item in enumerate(items):
        if not isinstance(item, dict) or not isinstance(item.get("data"), str):
            raise ApiError(f"{label} file {index + 1} is not valid")
        try:
            blob = base64.b64decode(item["data"], validate=True)
        except binascii.Error as exc:
            raise ApiError(f"{label} file {index + 1} is not valid base64") from exc
        name = Path(str(item.get("filename") or f"{label}-{index + 1}")).name
        path = directory / name
        if path.exists():
            path = directory / f"{index + 1}-{name}"
        path.write_bytes(blob)
        paths.append(path)
    return paths


def _content_length(headers: Message) -> int:
    try:
        length = int(headers.get("Content-Length", "0"))
    except ValueError as exc:
        raise ApiError("the Content-Length header is not a number") from exc
    if length < 0:
        raise ApiError("the Content-Length header is negative")
    return length


def _store_upload(handler: BaseHTTPRequestHandler) -> tuple[str, Path]:
    length = _content_length(handler.headers)
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
    token: str | None = None
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
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
            "connect-src 'self'; base-uri 'none'; form-action 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, obj: Json) -> None:
        self._send(status, json.dumps(obj).encode(), "application/json")

    def _token_ok(self, candidate: str | None) -> bool:
        return (
            self.token is not None
            and candidate is not None
            and hmac.compare_digest(candidate.encode(), self.token.encode())
        )

    def _has_session(self) -> bool:
        jar = SimpleCookie()
        try:
            jar.load(self.headers.get("Cookie", ""))
        except Exception:
            return False
        morsel = jar.get(COOKIE)
        return self._token_ok(morsel.value if morsel else None)

    def _locked(self, wants_page: bool) -> None:
        if wants_page:
            self._send(401, LOCKED_PAGE.read_bytes(), "text/html; charset=utf-8")
        else:
            self._json(401, {"error": "locked: open the link printed by rehub web"})

    def _guard(self, post: bool) -> bool:
        if not host_allowed(self.headers.get("Host")):
            self._json(403, {"error": "unexpected Host header"})
            return False
        if self.token is not None and not self._has_session():
            url = urlparse(self.path)
            offered = parse_qs(url.query).get("token", [None])[0]
            if not post and url.path == "/" and self._token_ok(offered):
                self.send_response(302)
                self.send_header("Location", "/")
                self.send_header(
                    "Set-Cookie", f"{COOKIE}={self.token}; HttpOnly; SameSite=Strict; Path=/"
                )
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return False
            self._locked(wants_page=not post and not url.path.startswith("/api/"))
            return False
        if post and self.headers.get(CSRF_HEADER) != "1":
            self._json(403, {"error": f"missing {CSRF_HEADER} header"})
            return False
        return True

    def _read_json(self) -> Json:
        length = _content_length(self.headers)
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
        elif path == "/api/samples":
            self._dispatch(self.api.samples)
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
        elif path == "/api/yara/draft":
            self._dispatch(lambda: self.api.yara_draft(self._read_json()))
        elif path == "/api/devices":
            self._dispatch(lambda: self.api.set_device(self._read_json()))
        elif path == "/api/demo":
            self._dispatch(self.api.demo)
        elif path == "/api/plc/check":
            self._dispatch(lambda: self.api.plc_check(self._read_json()))
        elif path == "/api/plc/approve":
            self._dispatch(lambda: self.api.plc_approve(self._read_json()))
        elif path == "/api/guide":
            self._dispatch(lambda: self.api.ask_guide(self._read_json()))
        elif path == "/api/analyze-sample":
            self._dispatch(lambda: self.api.analyze_sample(self._read_json()))
        else:
            self._json(404, {"error": "not found"})


def new_token() -> str:
    return secrets.token_urlsafe(24)


def make_server(
    host: str, port: int, image: str | None = None, token: str | None = None
) -> ThreadingHTTPServer:
    check_bind(host)
    handler = type("BoundHandler", (Handler,), {"api": Api(image), "token": token})
    return ThreadingHTTPServer((host, port), handler)


def serve_in_thread(server: ThreadingHTTPServer) -> threading.Thread:
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread
