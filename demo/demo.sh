#!/bin/sh
# Five minute demo. Set DEMO_PAUSE=1 to wait for Enter between steps.
# Step 5 needs a local Ollama model: export REHUB_MODEL=<model> first.
set -eu
cd "$(dirname "$0")/.."
REHUB_HOME="$(mktemp -d)"
export REHUB_HOME
R="uv run rehub"

step() {
    printf '\n== %s\n' "$1"
    if [ -n "${DEMO_PAUSE:-}" ]; then read -r _; fi
}

step "1. pinned tools"
$R tools

step "2. analyze a normal plant capture (read only, nothing is sent)"
$R analyze fixtures/scenarios/plant_normal.pcap

step "3. freeze it as a baseline, then analyze a changed capture"
$R baseline save plant-normal --run 1
$R analyze fixtures/scenarios/plant_changed.pcap
$R baseline diff plant-normal --run 4 || true

step "4a. doctor on the pinned image"
$R doctor

step "4b. doctor on a candidate image with a modified Suricata rule"
docker build -q --build-arg RULES_FILE=demo/modified.rules -f docker/Dockerfile -t rehub:candidate .
$R doctor --image rehub:candidate || true

step "5. draft a YARA rule, compile it and test it"
if [ -z "${REHUB_MODEL:-}" ]; then
    echo "skipped: set REHUB_MODEL (and run Ollama) to see the draft loop"
else
    benign="$(mktemp -d)"
    cp fixtures/yara/samples/benign.txt "$benign/"
    $R yara draft "S7comm job request that stops the PLC (function 0x29, P_PROGRAM)" \
        --positive fixtures/yara/samples/s7_stop_payload.bin --benign "$benign" || true
fi
