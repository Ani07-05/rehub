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
- `plc approve|check|list`: heuristic review of PLC source and comparison with an approved
  version (not a vulnerability scan).
- `web` has a one-click demo, device naming with guessed roles, a progress bar with time
  estimates, and a copy-summary button.
- `web` is written in plain language, shows changes as sentences, has a PLC code page, shows where
  your data lives, and has a help assistant that answers from a built-in manual.
- `web` opens on a guided Start page that walks the whole workflow in order.
- `web` can draft YARA rules (hosted models need a confirmation click) and analyze bundled samples.
- `report`: the same view as one offline, read only HTML file.
- `init`, `tools`, `capture` (passive tcpdump).
- CI: lint, types, tests, packet-send guard, image build with doctor.
