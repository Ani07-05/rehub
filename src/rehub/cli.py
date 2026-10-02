import tempfile
from pathlib import Path

import typer

from rehub import baseline as baselines
from rehub import db
from rehub.analyze import analyze as run_analysis
from rehub.diff import summarize
from rehub.doctor import FIXTURES_DIR, run_doctor
from rehub.runner import DEFAULT_IMAGE, RunnerError, default_runner
from rehub.tools import Tool, suricata, tshark, zeek

app = typer.Typer(no_args_is_help=True, add_completion=False, help="Safe OT analysis toolkit.")
baseline_app = typer.Typer(no_args_is_help=True, help="Immutable baselines of normal traffic.")
app.add_typer(baseline_app, name="baseline")

TOOLS: list[Tool] = [zeek, suricata, tshark]


@app.command()
def tools(
    image: str | None = typer.Option(
        None, help=f"Docker image to inspect (default {DEFAULT_IMAGE})."
    ),
) -> None:
    """List tools with pinned and installed versions."""
    runner = default_runner(image)
    mismatch = False
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
            mismatch |= status != "OK"
            typer.echo(f"{component:<16} pinned {pinned:<8} installed {have:<8} {status}")
    raise typer.Exit(1 if mismatch else 0)


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

    conn = db.connect()
    failed = False
    for report in reports:
        db.record_tool_version(conn, report.tool, report.version)
        typer.echo(f"{report.tool} {report.version}: {'PASS' if report.passed else 'FAIL'}")
        for component, pinned in report.pinned.items():
            have = report.installed.get(component, "missing")
            if have != pinned:
                typer.echo(f"  version: {component} {have} (pinned {pinned})")
        for result in report.results:
            db.record_doctor_run(
                conn, report.tool, report.version, image or DEFAULT_IMAGE,
                result.fixture, result.status, result.diff,
            )  # fmt: skip
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
        result = run_analysis(pcap, TOOLS, default_runner(image), conn, db.home())
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
