import tempfile
import webbrowser
from collections.abc import Callable
from pathlib import Path

import typer

from rehub import baseline as baselines
from rehub import capture as packet_capture
from rehub import config, db, plc, yara_ai, yara_fetch
from rehub import report as report_page
from rehub import web as web_app
from rehub.analyze import analyze as run_analysis
from rehub.config import DEFAULT_IMAGE
from rehub.diff import summarize
from rehub.doctor import FIXTURES_DIR, record_reports, run_doctor
from rehub.runner import RunnerError, default_runner
from rehub.tools import Tool, suricata, tshark, yara, zeek

app = typer.Typer(no_args_is_help=True, add_completion=False, help="Safe OT analysis toolkit.")
baseline_app = typer.Typer(no_args_is_help=True, help="Immutable baselines of normal traffic.")
app.add_typer(baseline_app, name="baseline")

PCAP_TOOLS: list[Tool] = [zeek, suricata, tshark]
TOOLS: list[Tool] = [*PCAP_TOOLS, yara]


def _check_tools(image: str | None) -> bool:
    """Print pinned vs installed versions. Returns True when everything matches."""
    runner = default_runner(image)
    matched = True
    for tool in TOOLS:
        with tempfile.TemporaryDirectory(prefix="rehub-tools-") as tmp:
            try:
                found = tool.installed(runner, Path(tmp))
            except RunnerError as exc:
                typer.echo(f"{tool.NAME}: ERROR {exc}", err=True)
                raise typer.Exit(2) from exc
        for component, pinned in tool.PINNED.items():
            have = found.get(component, "missing")
            status = "OK" if have == pinned else "MISMATCH"
            matched &= status == "OK"
            typer.echo(f"{component:<16} pinned {pinned:<8} installed {have:<8} {status}")
    return matched


@app.command()
def tools(
    image: str | None = typer.Option(
        None, help=f"Docker image to inspect (default {DEFAULT_IMAGE})."
    ),
) -> None:
    """List tools with pinned and installed versions."""
    raise typer.Exit(0 if _check_tools(image) else 1)


@app.command()
def init(
    image: str | None = typer.Option(None, help="Docker image to check."),
) -> None:
    """Create the database and config file, then check the tool image."""
    try:
        created = config.write_default()
    except OSError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    db.connect().close()
    typer.echo(f"home: {db.home()}")
    typer.echo(f"config: {config.path()} ({'created' if created else 'kept'})")
    typer.echo(f"database: {db.home() / 'rehub.db'}")
    try:
        ok = _check_tools(image)
    except config.ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    if not ok:
        typer.echo("tool versions differ from the pins; build the image from docker/Dockerfile")
    raise typer.Exit(0 if ok else 1)


@app.command()
def doctor(
    image: str | None = typer.Option(
        None, help=f"Run against this Docker image (default {DEFAULT_IMAGE})."
    ),
    accept: bool = typer.Option(False, "--accept", help="Rewrite golden files from this run."),
) -> None:
    """Replay fixtures through every tool and compare with golden output."""
    runner = default_runner(image)
    try:
        reports = run_doctor(TOOLS, runner, FIXTURES_DIR, accept)
    except RunnerError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    record_reports(db.connect(), reports, image or config.load().image)
    failed = False
    for report in reports:
        typer.echo(f"{report.tool} {report.version}: {'PASS' if report.passed else 'FAIL'}")
        for component, pinned in report.pinned.items():
            have = report.installed.get(component, "missing")
            if have != pinned:
                typer.echo(f"  version: {component} {have} (pinned {pinned})")
        for result in report.results:
            typer.echo(f"  {result.fixture}: {result.status}")
            for line in summarize(result.diff):
                typer.echo(f"    {line}")
            if "golden_missing" in result.diff:
                typer.echo(f"    golden missing: {result.diff['golden_missing']}")
        failed |= not report.passed
    if accept:
        typer.echo("golden files rewritten (--accept)")
    raise typer.Exit(1 if failed else 0)


@app.command()
def analyze(
    pcap: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    image: str | None = typer.Option(
        None, help=f"Docker image to run tools in (default {DEFAULT_IMAGE})."
    ),
) -> None:
    """Run every tool over a pcap (read only) and store the results."""
    conn = db.connect()
    try:
        result = run_analysis(pcap, PCAP_TOOLS, default_runner(image), conn, db.home())
    except RunnerError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    failed = False
    for tool_run in result.runs:
        status = f"ERROR {tool_run.error}" if tool_run.error else "ok"
        typer.echo(f"{tool_run.tool} {tool_run.version} (run {tool_run.run_id}): {status}")
        for name, count in sorted(tool_run.summary.items()):
            typer.echo(f"  {name}: {count}")
        failed |= tool_run.error is not None
    typer.echo(
        f"observations ({len(result.observations)}), baseline with --run {result.zeek_run_id}:"
    )
    for obs in sorted(result.observations):
        typer.echo(f"  {obs.src} -> {obs.dst}  {obs.protocol}  {obs.action}")
    raise typer.Exit(1 if failed else 0)


@baseline_app.command("save")
def baseline_save(
    name: str = typer.Argument(...),
    run: int = typer.Option(..., "--run", help="Run id printed by analyze."),
) -> None:
    """Freeze a run's observations as a named baseline. Never overwrites."""
    conn = db.connect()
    try:
        digest = baselines.save(conn, name, run)
    except baselines.BaselineError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    typer.echo(f"baseline {name} saved ({digest[:12]})")


@baseline_app.command("list")
def baseline_list() -> None:
    """List saved baselines."""
    for name, created, digest, count in baselines.list_baselines(db.connect()):
        typer.echo(f"{name}  {count} items  {digest[:12]}  {created}")


@baseline_app.command("diff")
def baseline_diff(
    name: str = typer.Argument(...),
    run: int = typer.Option(..., "--run", help="Run id printed by analyze."),
) -> None:
    """Compare a run with a baseline. Read only; exits 1 if anything differs."""
    try:
        result = baselines.diff(db.connect(), name, run)
    except baselines.BaselineError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    for src, dst in result.new_pairs:
        typer.echo(f"NEW PAIR      {src} -> {dst}")
    for src, dst, protocol, action in result.new_actions:
        typer.echo(f"NEW ACTION    {src} -> {dst}  {protocol}  {action}")
    for src, dst in result.missing_pairs:
        typer.echo(f"MISSING PAIR  {src} -> {dst}")
    if result.clean:
        typer.echo("matches baseline")
    raise typer.Exit(0 if result.clean else 1)


yara_app = typer.Typer(no_args_is_help=True, help="Scan, explain and draft YARA rules (YARA-X).")
app.add_typer(yara_app, name="yara")

PROVIDER_HELP = "LLM backend: ollama (local, default) or anthropic (hosted, needs --yes)."


def _provider(name: str | None, model: str | None) -> yara_ai.Provider:
    try:
        cfg = config.load()
        return yara_ai.make_provider(name or cfg.provider, model or cfg.model)
    except config.ConfigError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    except yara_ai.ProviderError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc


def _confirm_hosted(provider: yara_ai.Provider, system: str, user: str, yes: bool) -> None:
    if not provider.hosted:
        return
    typer.echo(f"This text will be sent to {provider.name} (first request):", err=True)
    typer.echo(f"--- system ---\n{system}\n--- user ---\n{user}\n---", err=True)
    if not yes:
        typer.echo("nothing sent. Re-run with --yes to send it.", err=True)
        raise typer.Exit(2)


def _announce(provider: yara_ai.Provider) -> Callable[[str, str], None]:
    def send(system: str, user: str) -> None:
        if provider.hosted:
            typer.echo(f"sending to {provider.name}:\n{user}\n", err=True)

    return send


@yara_app.command("scan")
def yara_scan(
    rules: Path = typer.Argument(..., exists=True, readable=True),
    target: Path = typer.Argument(..., exists=True, readable=True),
    image: str | None = typer.Option(None, help="Docker image to run yr in."),
) -> None:
    """Run yr scan with the given rules over a file or directory."""
    try:
        with tempfile.TemporaryDirectory(prefix="rehub-yara-") as tmp:
            found = yara.scan(default_runner(image), rules, target, Path(tmp))
    except RunnerError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    for match in found:
        typer.echo(f"{match['rule']}  {match['file']}")
    if not found:
        typer.echo("no matches")


@yara_app.command("explain")
def yara_explain(
    rule: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    provider_name: str | None = typer.Option(None, "--provider", help=PROVIDER_HELP),
    model: str | None = typer.Option(None, help="Model name (or set REHUB_MODEL)."),
    yes: bool = typer.Option(False, "--yes", help="Confirm sending text to a hosted provider."),
) -> None:
    """Explain a rule in plain English. Only the rule text is sent to the model."""
    provider = _provider(provider_name, model)
    text = rule.read_text()
    _confirm_hosted(provider, yara_ai.EXPLAIN_SYSTEM, text, yes)
    try:
        typer.echo(yara_ai.explain(provider, text, _announce(provider)))
    except yara_ai.ProviderError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc


@yara_app.command("draft")
def yara_draft(
    description: str = typer.Argument(..., help="What the rule should detect."),
    positive: list[Path] = typer.Option([], "--positive", exists=True, dir_okay=False),
    benign: Path | None = typer.Option(None, "--benign", exists=True, file_okay=False),
    provider_name: str | None = typer.Option(None, "--provider", help=PROVIDER_HELP),
    model: str | None = typer.Option(None, help="Model name (or set REHUB_MODEL)."),
    yes: bool = typer.Option(False, "--yes", help="Confirm sending text to a hosted provider."),
    out: Path | None = typer.Option(None, "--out", help="Also write the rule to this file."),
    image: str | None = typer.Option(None, help="Docker image to run yr in."),
) -> None:
    """Draft a rule with a model, then compile and test it. Sample contents are never sent."""
    provider = _provider(provider_name, model)
    _confirm_hosted(provider, yara_ai.DRAFT_SYSTEM, yara_ai.draft_prompt(description), yes)
    engine = yara_ai.RunnerEngine(default_runner(image))
    try:
        result = yara_ai.draft(provider, engine, description, positive, benign, _announce(provider))
    except (yara_ai.ProviderError, RunnerError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc

    typer.echo(result.rule)
    typer.echo(f"\ncompile attempts: {result.attempts}")
    if result.compile_error:
        typer.echo(f"compile error:\n{result.compile_error}")
    for name, matched in result.positives.items():
        typer.echo(f"positive {name}: {'match' if matched else 'MISS'}")
    for name in result.benign_hits:
        typer.echo(f"benign {name}: MATCH")
    label = result.status.upper()
    typer.echo(f"status: {label}" + (f" ({result.reason})" if result.reason else ""))
    if result.status != "validated":
        typer.echo("model-written rule, not tested to a trusted standard. Review before use.")
    db.record_yara_rule(db.connect(), yara_ai.rule_name(result.rule), result.rule, result.status)
    if out:
        out.write_text(result.rule + "\n")
    raise typer.Exit(0 if result.status == "validated" else 1)


@yara_app.command("fetch")
def yara_fetch_rules(
    dest: Path = typer.Option(None, "--dest", help="Directory to clone into."),
) -> None:
    """Clone the pinned Yara-Rules commit into your own directory (needs network)."""
    target = dest or db.home() / "yara-rules"
    typer.echo(yara_fetch.LICENSE_NOTE)
    try:
        yara_fetch.fetch(target)
    except yara_fetch.FetchError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    typer.echo(f"rules at {target} (commit {yara_fetch.RULES_SHA[:12]})")


@app.command()
def capture(
    iface: str = typer.Option(..., "--iface", help="Interface to listen on (required)."),
    seconds: int = typer.Option(..., "--seconds", help="How long to listen."),
    out: Path = typer.Option(..., "--out", help="Pcap file to write; must not exist."),
) -> None:
    """Passive capture with tcpdump. Listens only; never transmits."""
    try:
        packet_capture.validate(iface, seconds, out)
        typer.echo(packet_capture.LISTEN_ONLY.format(out=out))
        packet_capture.capture(iface, seconds, out)
    except packet_capture.CaptureError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    typer.echo(f"wrote {out}")


@app.command()
def report(
    out: Path = typer.Option(
        None, "--out", help="HTML file to write (default $REHUB_HOME/report.html)."
    ),
) -> None:
    """Write a read only HTML report of stored runs, baselines and doctor results."""
    target = out or db.home() / "report.html"
    conn = db.connect()
    try:
        html = report_page.render(report_page.snapshot(conn))
    finally:
        conn.close()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(html)
    typer.echo(f"wrote {target}")


@app.command()
def web(
    host: str = typer.Option("127.0.0.1", help="Address to listen on. Loopback only."),
    port: int = typer.Option(8765, help="Port to listen on."),
    image: str | None = typer.Option(None, help="Docker image to run tools in."),
    open_browser: bool = typer.Option(False, "--open", help="Open the page in your browser."),
) -> None:
    """Serve the interface on this computer only. No login, so it never leaves loopback."""
    try:
        server = web_app.make_server(host, port, image)
    except (ValueError, OSError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    url = f"http://{host if host != '::1' else '[::1]'}:{port}/"
    typer.echo(f"rehub is at {url} (this computer only). Press Ctrl-C to stop.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        typer.echo("stopped")
    finally:
        server.server_close()


plc_app = typer.Typer(no_args_is_help=True, help="Review PLC program source and compare versions.")
app.add_typer(plc_app, name="plc")

SEVERITY_LABEL = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}
MAX_PLC_BYTES = 20 * 1024 * 1024


def _read_program(path: Path) -> str:
    if path.stat().st_size > MAX_PLC_BYTES:
        typer.echo("error: file is larger than 20 MB", err=True)
        raise typer.Exit(2)
    return path.read_text(errors="replace")


@plc_app.command("approve")
def plc_approve(
    file: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    name: str = typer.Option(..., "--name", help="Name of the program or controller."),
) -> None:
    """Save a program as the approved version. Saved versions cannot be changed."""
    conn = db.connect()
    try:
        version = db.approve_plc_program(conn, name, file.name, _read_program(file))
    finally:
        conn.close()
    typer.echo(f"approved {name} (version {version})")


@plc_app.command("list")
def plc_list() -> None:
    """List approved programs."""
    conn = db.connect()
    try:
        rows = db.list_plc_programs(conn)
    finally:
        conn.close()
    for row in rows:
        typer.echo(f"{row['id']}  {row['name']}  {row['filename']}  {row['approved_at']}")
    if not rows:
        typer.echo("no approved programs yet")


@plc_app.command("check")
def plc_check(
    file: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True),
    against: str | None = typer.Option(None, "--against", help="Approved program name."),
) -> None:
    """Review a program for risky patterns and compare it with the approved version.

    This is a heuristic review, not a vulnerability scan. Exits 1 if it finds high severity
    patterns or new risky patterns compared with the approved version.
    """
    text = _read_program(file)
    findings = plc.analyze(text)
    name = against or file.stem
    conn = db.connect()
    try:
        approved = db.latest_plc_program(conn, name)
    finally:
        conn.close()
    typer.echo(f"{file.name}: {len(findings)} thing(s) to review")
    for item in findings:
        typer.echo(f"  {SEVERITY_LABEL[item.severity]:<6} line {item.line}: {item.title}")
        typer.echo(f"         {item.code}")
        typer.echo(f"         why: {item.why}")
        typer.echo(f"         check: {item.check}")
    risky = any(f.severity == "high" for f in findings)
    if approved:
        diff = plc.compare(approved[2], text)
        typer.echo(f"compared with approved '{name}' (version {approved[0]}):")
        if diff.unchanged and not diff.value_changes:
            typer.echo("  no changes")
        for change in diff.value_changes:
            typer.echo(
                f"  value changed on line {change.line}: {change.before}  ->  {change.after}"
            )
        for line in diff.added[:50]:
            typer.echo(f"  + {line}")
        for line in diff.removed[:50]:
            typer.echo(f"  - {line}")
        for item in diff.new_findings:
            typer.echo(f"  NEW {SEVERITY_LABEL[item.severity]}: {item.title} (line {item.line})")
        risky = risky or bool(diff.new_findings)
    else:
        typer.echo(f"no approved version named '{name}'; approve one with: rehub plc approve")
    raise typer.Exit(1 if risky else 0)
