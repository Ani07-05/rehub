#!/bin/sh
# Fails if any source file could transmit packets or wraps an active scanner.
set -eu
cd "$(dirname "$0")/.."
pattern='(import socket|from socket|AF_PACKET|SOCK_RAW|scapy|\bsendp\b|\bsr1?\(|\.sendto\(|\bnmap\b|plcscan|masscan|\bhping)'
if grep -rEn "$pattern" src fixtures/generate.py docker/Dockerfile; then
    echo "forbidden packet-sending construct found" >&2
    exit 1
fi
echo "no packet-sending code paths"
