from rehub.observations import Observation, extract


def conn_row(service: str = "modbus") -> dict[str, object]:
    return {"id.orig_h": "1.1.1.1", "id.resp_h": "2.2.2.2", "service": service, "proto": "tcp"}


def test_conn_uses_known_protocol_over_cotp() -> None:
    zeek = {"logs": {"conn": [conn_row("cotp,s7comm")]}}
    assert extract(zeek) == {Observation("1.1.1.1", "2.2.2.2", "s7comm", "conn")}


def test_unknown_service_falls_back() -> None:
    assert extract({"logs": {"conn": [conn_row("")]}}) == {
        Observation("1.1.1.1", "2.2.2.2", "tcp", "conn")
    }


def test_s7_engineering_functions_only_on_job_requests() -> None:
    base = conn_row("s7comm")
    zeek = {
        "logs": {
            "conn": [base],
            "s7comm": [
                {**base, "function_name": "PLC Stop", "rosctr_name": "Job-Request"},
                {**base, "function_name": "PLC Stop", "rosctr_name": "ACK-Data"},
                {**base, "function_name": "Setup Communication", "rosctr_name": "Job-Request"},
                {**base, "function_name": "Request Download", "rosctr_name": "Job-Request"},
            ],
        }
    }
    actions = {o.action for o in extract(zeek)}
    assert actions == {"conn", "stop", "program download"}


def test_modbus_writes_only_from_requests() -> None:
    base = conn_row()
    zeek = {
        "logs": {
            "modbus": [
                {**base, "func": "WRITE_SINGLE_REGISTER", "pdu_type": "REQ"},
                {**base, "func": "WRITE_SINGLE_REGISTER", "pdu_type": "RESP"},
                {**base, "func": "READ_HOLDING_REGISTERS", "pdu_type": "REQ"},
            ]
        }
    }
    assert extract(zeek) == {Observation("1.1.1.1", "2.2.2.2", "modbus", "parameter write")}


def test_cip_services_classified() -> None:
    base = conn_row("enip")
    rows = [
        {**base, "direction": "request", "cip_service": svc}
        for svc in ("Get Attributes All", "Set Attribute Single", "Stop", "Write Tag")
    ]
    actions = {o.action for o in extract({"logs": {"cip": rows}})}
    assert actions == {"parameter write", "mode change"}
