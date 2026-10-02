"""Deterministic synthetic OT pcap generator. Stdlib only, no packets are ever sent."""

import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
BASE_TS = 1_700_000_000

SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return int(~total & 0xFFFF)


def mac(host: int) -> bytes:
    return bytes([0x02, 0x00, 0x00, 0x00, 0x00, host])


def ip_bytes(addr: str) -> bytes:
    return bytes(int(p) for p in addr.split("."))


@dataclass
class Pcap:
    frames: list[tuple[float, bytes]] = field(default_factory=list)
    clock: float = 0.0

    def add(self, frame: bytes) -> None:
        self.clock += 0.001
        self.frames.append((BASE_TS + self.clock, frame))

    def to_bytes(self) -> bytes:
        out = struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)
        for ts, frame in self.frames:
            sec = int(ts)
            usec = round((ts - sec) * 1_000_000)
            out += struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame
        return out


@dataclass
class TcpFlow:
    pcap: Pcap
    client: str
    server: str
    cport: int
    sport: int
    cseq: int = 1000
    sseq: int = 5000
    ipid: int = 1

    def _frame(self, from_client: bool, flags: int, payload: bytes) -> bytes:
        src, dst = (self.client, self.server) if from_client else (self.server, self.client)
        sp, dp = (self.cport, self.sport) if from_client else (self.sport, self.cport)
        seq, ack = (self.cseq, self.sseq) if from_client else (self.sseq, self.cseq)
        tcp = (
            struct.pack(
                "!HHIIBBHHH", sp, dp, seq, ack if flags & ACK else 0, 5 << 4, flags, 8192, 0, 0
            )
            + payload
        )
        pseudo = ip_bytes(src) + ip_bytes(dst) + struct.pack("!BBH", 0, 6, len(tcp))
        tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
        ip = struct.pack("!BBHHHBBH", 0x45, 0, 20 + len(tcp), self.ipid, 0x4000, 64, 6, 0)
        ip += ip_bytes(src) + ip_bytes(dst)
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        self.ipid += 1
        eth = mac(int(dst.split(".")[-1])) + mac(int(src.split(".")[-1])) + b"\x08\x00"
        return eth + ip + tcp

    def send(self, from_client: bool, payload: bytes, flags: int = ACK | PSH) -> None:
        self.pcap.add(self._frame(from_client, flags, payload))
        advance = len(payload) + (1 if flags & (SYN | FIN) else 0)
        if from_client:
            self.cseq += advance
        else:
            self.sseq += advance

    def handshake(self) -> None:
        self.send(True, b"", SYN)
        self.send(False, b"", SYN | ACK)
        self.send(True, b"", ACK)

    def close(self) -> None:
        self.send(True, b"", FIN | ACK)
        self.send(False, b"", FIN | ACK)
        self.send(True, b"", ACK)


def tpkt(payload: bytes) -> bytes:
    return struct.pack("!BBH", 3, 0, 4 + len(payload)) + payload


COTP_DATA = b"\x02\xf0\x80"
COTP_PARAMS = b"\xc0\x01\x0a\xc1\x02\x01\x00\xc2\x02\x01\x02"
ROSCTR_JOB, ROSCTR_ACK_DATA = 1, 3


def s7_job(pdu_ref: int, param: bytes, data: bytes = b"") -> bytes:
    hdr = struct.pack("!BBHHHH", 0x32, ROSCTR_JOB, 0, pdu_ref, len(param), len(data))
    return tpkt(COTP_DATA + hdr + param + data)


def s7_ack(pdu_ref: int, param: bytes, data: bytes = b"") -> bytes:
    hdr = struct.pack("!BBHHHHBB", 0x32, ROSCTR_ACK_DATA, 0, pdu_ref, len(param), len(data), 0, 0)
    return tpkt(COTP_DATA + hdr + param + data)


def s7_session(pcap: Pcap, client: str, plc: str, cport: int, actions: tuple[str, ...]) -> None:
    flow = TcpFlow(pcap, client, plc, cport, 102)
    flow.handshake()
    flow.send(True, tpkt(b"\x11\xe0\x00\x00\x00\x01\x00" + COTP_PARAMS))
    flow.send(False, tpkt(b"\x11\xd0\x00\x01\x00\x01\x00" + COTP_PARAMS))

    setup = b"\xf0\x00\x00\x01\x00\x01\x01\xe0"
    flow.send(True, s7_job(1, setup))
    flow.send(False, s7_ack(1, setup))

    ref = 2
    for action in actions:
        if action == "download":
            fname = b"_0A00001P"
            req = b"\x1a\x01\x00\x00\x00\x00\x00\x00" + bytes([len(fname)]) + fname
            req += b"\x06" + b"100000"
            flow.send(True, s7_job(ref, req))
            flow.send(False, s7_ack(ref, b"\x1a"))
            blk = b"\x1b\x01\x00\x00\x00\x00\x00\x01" + bytes([len(fname)]) + fname
            flow.send(True, s7_job(ref + 1, blk, b"\x00\x04\x00\x00\xde\xad\xbe\xef"))
            flow.send(False, s7_ack(ref + 1, b"\x1b\x00\x00\x00\x00\x00"))
            end = b"\x1c\x00\x00\x00\x00\x00\x00\x01" + bytes([len(fname)]) + fname
            flow.send(True, s7_job(ref + 2, end))
            flow.send(False, s7_ack(ref + 2, b"\x1c"))
            ref += 3
        elif action == "stop":
            stop = b"\x29\x00\x00\x00\x00\x00\x09P_PROGRAM"
            flow.send(True, s7_job(ref, stop))
            flow.send(False, s7_ack(ref, b"\x29"))
            ref += 1
        else:
            raise ValueError(f"unknown action {action}")
    flow.close()


def build_s7_download_stop() -> Pcap:
    pcap = Pcap()
    s7_session(pcap, "10.0.0.10", "10.0.0.20", 49152, ("download", "stop"))
    return pcap


def modbus_session(pcap: Pcap, client: str, plc: str, cport: int, writes: bool = True) -> None:
    flow = TcpFlow(pcap, client, plc, cport, 502)
    flow.handshake()

    def adu(tid: int, pdu: bytes) -> bytes:
        return struct.pack("!HHHB", tid, 0, len(pdu) + 1, 1) + pdu

    regs = bytes(range(20))
    flow.send(True, adu(1, struct.pack("!BHH", 3, 0, 10)))
    flow.send(False, adu(1, bytes([3, len(regs)]) + regs))
    if writes:
        flow.send(True, adu(2, struct.pack("!BHH", 6, 1, 255)))
        flow.send(False, adu(2, struct.pack("!BHH", 6, 1, 255)))
        flow.send(True, adu(3, struct.pack("!BHHBHH", 16, 10, 2, 4, 1, 2)))
        flow.send(False, adu(3, struct.pack("!BHH", 16, 10, 2)))
    flow.close()


def enip_frame(command: int, session: int, data: bytes = b"") -> bytes:
    return struct.pack("<HHII8sI", command, len(data), session, 0, b"\x00" * 8, 0) + data


def enip_session(pcap: Pcap, client: str, plc: str, cport: int) -> None:
    flow = TcpFlow(pcap, client, plc, cport, 44818)
    flow.handshake()
    name = bytes([9]) + b"1756-L83E"
    attrs = struct.pack("<HHHBBHI", 1, 14, 166, 32, 11, 0x0030, 0x00C0FFEE) + name

    flow.send(True, enip_frame(0x63, 0))
    sock = struct.pack(">HH4s8s", 2, 44818, ip_bytes(plc), b"\x00" * 8)
    item = struct.pack("<H", 1) + sock + attrs + b"\x03"
    listing = struct.pack("<HHH", 1, 0x0C, len(item)) + item
    flow.send(False, enip_frame(0x63, 0, listing))

    flow.send(True, enip_frame(0x65, 0, struct.pack("<HH", 1, 0)))
    flow.send(False, enip_frame(0x65, 0x1A2B3C4D, struct.pack("<HH", 1, 0)))

    cip_req = bytes([0x01, 0x02, 0x20, 0x01, 0x24, 0x01])
    rr = struct.pack("<IHH", 0, 10, 2) + struct.pack("<HH", 0, 0)
    rr += struct.pack("<HH", 0xB2, len(cip_req)) + cip_req
    flow.send(True, enip_frame(0x6F, 0x1A2B3C4D, rr))
    cip_rsp = bytes([0x81, 0, 0, 0]) + attrs
    rr = struct.pack("<IHH", 0, 0, 2) + struct.pack("<HH", 0, 0)
    rr += struct.pack("<HH", 0xB2, len(cip_rsp)) + cip_rsp
    flow.send(False, enip_frame(0x6F, 0x1A2B3C4D, rr))
    flow.close()


def build_modbus_read_write() -> Pcap:
    pcap = Pcap()
    modbus_session(pcap, "10.0.0.11", "10.0.0.21", 50000)
    return pcap


def build_enip_identity() -> Pcap:
    pcap = Pcap()
    enip_session(pcap, "10.0.0.12", "10.0.0.22", 51000)
    return pcap


def build_plant_normal() -> Pcap:
    pcap = Pcap()
    s7_session(pcap, "10.0.0.10", "10.0.0.20", 49152, ())
    modbus_session(pcap, "10.0.0.11", "10.0.0.21", 50000, writes=False)
    return pcap


def build_plant_changed() -> Pcap:
    pcap = Pcap()
    s7_session(pcap, "10.0.0.10", "10.0.0.20", 49152, ("download", "stop"))
    s7_session(pcap, "10.0.0.99", "10.0.0.20", 49300, ())
    return pcap


SCENARIOS = {
    "plant_normal": build_plant_normal,
    "plant_changed": build_plant_changed,
}

FIXTURES = {
    "s7_download_stop": build_s7_download_stop,
    "modbus_read_write": build_modbus_read_write,
    "enip_identity": build_enip_identity,
}


def main(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, build in FIXTURES.items():
        (out_dir / "pcaps").mkdir(exist_ok=True)
        (out_dir / "pcaps" / f"{name}.pcap").write_bytes(build().to_bytes())
    for name, build in SCENARIOS.items():
        (out_dir / "scenarios").mkdir(exist_ok=True)
        (out_dir / "scenarios" / f"{name}.pcap").write_bytes(build().to_bytes())


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent)
