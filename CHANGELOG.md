# Changelog

## 0.1.0 (unreleased)

- Pinned image: Zeek 8.0.10 with ICSNPP s7comm, enip and modbus, Suricata 8.0.7, tshark 4.4.18,
  YARA-X 1.21.0, tcpdump 4.99.5.
- `doctor`: replay synthetic fixtures through every tool, compare normalized output with golden
  files, check candidate images with `--image`, rewrite goldens only with `--accept`.
- `analyze`: Zeek, Suricata and tshark over a pcap, stored with raw output.
- `baseline save|list|diff`: immutable baselines, read only diff.
- `yara scan|explain|draft|fetch`: YARA-X wrapper and a validated draft loop with a local or
  opt-in hosted model.
- `web`: local interface (loopback only) to analyze captures, review baseline changes, run doctor
  and scan with rules.
- `report`: the same view as one offline, read only HTML file.
- `init`, `tools`, `capture` (passive tcpdump).
- CI: lint, types, tests, packet-send guard, image build with doctor.
