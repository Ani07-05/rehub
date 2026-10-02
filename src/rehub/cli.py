import tempfile
from pathlib import Path

import typer

from rehub import db
from rehub.diff import summarize
from rehub.doctor import FIXTURES_DIR, run_doctor
from rehub.runner import DEFAULT_IMAGE, RunnerError, default_runner
from rehub.tools import Tool, suricata, tshark, zeek

app = typer.Typer(no_args_is_help=True, add_completion=False, help="Safe OT analysis toolkit.")

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
