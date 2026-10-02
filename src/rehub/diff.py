import json
from collections import Counter
from typing import Any

Diff = dict[str, Any]


def _short(row: dict[str, Any], limit: int = 140) -> str:
    text = _key(row)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _key(row: dict[str, Any]) -> str:
    return json.dumps(row, sort_keys=True)


def _fields(rows: list[dict[str, Any]]) -> set[str]:
    return {k for row in rows for k in row}


def _log_diff(golden: list[dict[str, Any]], actual: list[dict[str, Any]]) -> Diff:
    out: Diff = {}
    gf, af = _fields(golden), _fields(actual)
    if af - gf:
        out["fields_added"] = sorted(af - gf)
    if gf - af:
        out["fields_removed"] = sorted(gf - af)

    gcount, acount = Counter(_key(r) for r in golden), Counter(_key(r) for r in actual)
    only_golden = [json.loads(k) for k in sorted((gcount - acount).elements())]
    only_actual = [json.loads(k) for k in sorted((acount - gcount).elements())]
    if len(only_golden) == len(only_actual):
        changed = []
        for before, after in zip(only_golden, only_actual, strict=True):
            fields = sorted(
                k for k in before.keys() | after.keys() if before.get(k) != after.get(k)
            )
            changed.append({"fields": fields, "before": before, "after": after})
        if changed:
            out["rows_changed"] = changed
    else:
        if only_golden:
            out["rows_removed"] = only_golden
        if only_actual:
            out["rows_added"] = only_actual
    return out


def diff_normalized(golden: dict[str, Any], actual: dict[str, Any]) -> Diff:
    """Empty result means identical. Rows are compared as multisets of normalized JSON."""
    out: Diff = {}
    glogs, alogs = golden["logs"], actual["logs"]
    if alogs.keys() - glogs.keys():
        out["logs_added"] = sorted(alogs.keys() - glogs.keys())
    if glogs.keys() - alogs.keys():
        out["logs_removed"] = sorted(glogs.keys() - alogs.keys())
    per_log = {}
    for name in sorted(glogs.keys() & alogs.keys()):
        entry = _log_diff(glogs[name], alogs[name])
        if entry:
            per_log[name] = entry
    if per_log:
        out["logs"] = per_log
    return out


def summarize(diff: Diff) -> list[str]:
    lines = [f"log added: {n}" for n in diff.get("logs_added", [])]
    lines += [f"log removed: {n}" for n in diff.get("logs_removed", [])]
    for name, entry in diff.get("logs", {}).items():
        for field in entry.get("fields_added", []):
            lines.append(f"{name}: field added: {field}")
        for field in entry.get("fields_removed", []):
            lines.append(f"{name}: field removed: {field}")
        for change in entry.get("rows_changed", []):
            for field in change["fields"]:
                lines.append(
                    f"{name}: field changed: {field}: "
                    f"{change['before'].get(field)!r} -> {change['after'].get(field)!r}"
                )
        lines += [f"{name}: row added: {_short(r)}" for r in entry.get("rows_added", [])]
        lines += [f"{name}: row removed: {_short(r)}" for r in entry.get("rows_removed", [])]
    return lines
