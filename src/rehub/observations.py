import re
from typing import Any, NamedTuple

CONN = "conn"

S7_ACTIONS = {
    "Request Download": "program download",
    "Download Block": "program download",
    "Download Ended": "program download",
    "Start Upload": "program upload",
    "Upload": "program upload",
    "End Upload": "program upload",
    "PLC Control": "mode change",
    "PLC Stop": "stop",
}
CIP_WRITE = re.compile(r"^(Set |Write|Read Modify Write)")
CIP_MODE = re.compile(r"^(Stop|Start|Reset|Restart)")
KNOWN_PROTOCOLS = ("s7comm", "modbus", "enip", "dnp3", "bacnet", "opcua-binary")


class Observation(NamedTuple):
    src: str
    dst: str
    protocol: str
    action: str


def _protocol(row: dict[str, Any]) -> str:
    services = str(row.get("service", "")).split(",")
    for known in KNOWN_PROTOCOLS:
        if known in services:
            return known
    return services[0] or str(row.get("proto", "unknown"))


def _pair(row: dict[str, Any]) -> tuple[str, str]:
    return row["id.orig_h"], row["id.resp_h"]


def extract(zeek: dict[str, Any]) -> set[Observation]:
    """Derive host-pair observations from normalized Zeek logs."""
    logs = zeek["logs"]
    found: set[Observation] = set()
    for row in logs.get("conn", []):
        src, dst = _pair(row)
        found.add(Observation(src, dst, _protocol(row), CONN))
    for row in logs.get("s7comm", []):
        action = S7_ACTIONS.get(row.get("function_name", ""))
        if action and row.get("rosctr_name") == "Job-Request":
            found.add(Observation(*_pair(row), "s7comm", action))
    for row in logs.get("modbus", []):
        if row.get("pdu_type") == "REQ" and str(row.get("func", "")).startswith("WRITE"):
            found.add(Observation(*_pair(row), "modbus", "parameter write"))
    for row in logs.get("cip", []):
        if row.get("direction") != "request":
            continue
        service = str(row.get("cip_service", ""))
        if CIP_WRITE.match(service):
            found.add(Observation(*_pair(row), "enip", "parameter write"))
        elif CIP_MODE.match(service):
            found.add(Observation(*_pair(row), "enip", "mode change"))
    return found
