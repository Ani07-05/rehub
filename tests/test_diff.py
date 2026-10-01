from typing import Any

from rehub.diff import diff_normalized, summarize


def doc(**logs: list[dict[str, Any]]) -> dict[str, Any]:
    return {"logs": logs}


def test_identical_is_empty() -> None:
    d = doc(conn=[{"a": 1}, {"a": 2}])
    assert diff_normalized(d, d) == {}


def test_changed_value_names_field() -> None:
    diff = diff_normalized(doc(s7=[{"fn": "PLC Stop", "n": 1}]), doc(s7=[{"fn": "Stop", "n": 1}]))
    assert diff["logs"]["s7"]["rows_changed"][0]["fields"] == ["fn"]
    assert summarize(diff) == ["s7: field changed: fn: 'PLC Stop' -> 'Stop'"]


def test_field_added_and_removed() -> None:
    diff = diff_normalized(doc(c=[{"a": 1, "b": 2}]), doc(c=[{"a": 1, "z": 2}]))
    assert diff["logs"]["c"]["fields_added"] == ["z"]
    assert diff["logs"]["c"]["fields_removed"] == ["b"]


def test_rows_added_and_removed_when_counts_differ() -> None:
    diff = diff_normalized(doc(c=[{"a": 1}]), doc(c=[{"a": 1}, {"a": 2}]))
    assert diff["logs"]["c"]["rows_added"] == [{"a": 2}]
    diff = diff_normalized(doc(c=[{"a": 1}, {"a": 2}]), doc(c=[{"a": 1}]))
    assert diff["logs"]["c"]["rows_removed"] == [{"a": 2}]


def test_duplicate_rows_are_counted() -> None:
    diff = diff_normalized(doc(c=[{"a": 1}, {"a": 1}]), doc(c=[{"a": 1}]))
    assert diff["logs"]["c"]["rows_removed"] == [{"a": 1}]


def test_log_added_and_removed() -> None:
    diff = diff_normalized(doc(old=[]), doc(new=[]))
    assert diff["logs_added"] == ["new"]
    assert diff["logs_removed"] == ["old"]
