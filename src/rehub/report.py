import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rehub import baseline
from rehub.diff import summarize

TEMPLATE = Path(__file__).parent / "static" / "app.html"
PLACEHOLDER = "/*__REHUB_DATA__*/null"
MAX_RUNS = 20


def _diff_payload(result: baseline.BaselineDiff) -> dict[str, Any]:
    return {
        "clean": result.clean,
        "new_pairs": [list(p) for p in result.new_pairs],
        "new_actions": [list(i) for i in result.new_actions],
        "missing_pairs": [list(p) for p in result.missing_pairs],
    }


def snapshot(conn: sqlite3.Connection) -> dict[str, Any]:
    """Collect everything the report page shows. Read only."""
    runs = conn.execute(
        "SELECT r.id, r.tool, r.tool_version, r.input_sha256, r.started_at, r.exit_code,"
        " (SELECT COUNT(*) FROM observations o WHERE o.run_id = r.id)"
        " FROM runs r ORDER BY r.id DESC LIMIT 200"
    ).fetchall()
    run_keys = ("id", "tool", "version", "input_sha256", "started_at", "exit_code", "observations")
    run_rows = [dict(zip(run_keys, r, strict=True)) for r in runs]

    observed = [r for r in run_rows if r["observations"]][:MAX_RUNS]
    observations: dict[str, list[list[str]]] = {}
    for run in observed:
        items = baseline.run_items(conn, run["id"])
        observations[str(run["id"])] = [list(i) for i in sorted(items)]

    baselines = []
    diffs: dict[str, dict[str, Any]] = {}
    for name, created, digest, count in baseline.list_baselines(conn):
        items = baseline.baseline_items(conn, name)
        baselines.append(
            {
                "name": name,
                "created_at": created,
                "sha256": digest,
                "count": count,
                "items": [list(i) for i in sorted(items)],
            }
        )
        for run in observed:
            diffs[f"{name}|{run['id']}"] = _diff_payload(baseline.diff(conn, name, run["id"]))

    doctor = []
    for row in conn.execute(
        "SELECT d.tool, d.version, d.image, d.fixture, d.status, d.diff_json, d.at"
        " FROM doctor_runs d JOIN (SELECT tool, fixture, MAX(id) AS id FROM doctor_runs"
        " GROUP BY tool, fixture) latest ON latest.id = d.id ORDER BY d.tool, d.fixture"
    ):
        doctor.append(
            {
                "tool": row[0],
                "version": row[1],
                "image": row[2],
                "fixture": row[3],
                "status": row[4],
                "lines": summarize(json.loads(row[5])),
                "at": row[6],
            }
        )

    rules = [
        dict(zip(("id", "name", "text", "status", "created_at"), r, strict=True))
        for r in conn.execute(
            "SELECT id, name, text, status, created_at FROM yara_rules ORDER BY id DESC"
        )
    ]
    tools = [
        {"tool": t, "version": v, "seen_at": s}
        for t, v, s in conn.execute(
            "SELECT tool, version, MAX(seen_at) FROM tool_versions GROUP BY tool, version"
            " ORDER BY tool, MAX(seen_at) DESC"
        )
    ]
    return {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "runs": run_rows,
        "observations": observations,
        "baselines": baselines,
        "diffs": diffs,
        "doctor": doctor,
        "rules": rules,
        "tools": tools,
    }


def render(data: dict[str, Any]) -> str:
    """Embed the snapshot in the page. The JSON cannot close the script element."""
    payload = json.dumps(data, sort_keys=True).replace("<", "\\u003c").replace("\u2028", "\\u2028")
    template = TEMPLATE.read_text()
    if PLACEHOLDER not in template:
        raise RuntimeError("report template is missing its data placeholder")
    return template.replace(PLACEHOLDER, payload, 1)
