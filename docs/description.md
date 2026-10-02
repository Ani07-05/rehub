# Description

## What rehub is

rehub is a command line tool for one analyst working on OT network captures. It runs
Zeek with the CISA ICSNPP protocol parsers, Suricata, tshark and YARA-X, and keeps what it
learns in one local SQLite database.

It exists because of four problems with using those tools directly:

1. Each tool has its own flags and output format.
2. The tools change independently. Parser output, rule syntax and log fields can shift between
   versions, and nothing checks that before a sensor is upgraded.
3. Raw tools have no OT safety rails. One active scan can crash a PLC.
4. Each run is stateless. Nothing remembers a known good baseline.

A plain script can orchestrate the tools. rehub is only worth having for three things a
script does not give you: passive-only operation, `rehub doctor`, and the shared memory.

## Components

| Piece | Version in the image | Role |
|---|---|---|
| Zeek | 8.0.10 | Protocol logs and the source of observations |
| ICSNPP s7comm, enip, modbus | commits 7ebeb03, 808f90b, 27f22b4 | OT protocol parsers for Zeek |
| Suricata | 8.0.7 (built from source, sha256 pinned) | Rule based detection |
| tshark | 4.4.19 (Debian trixie) | Per packet summary |
| YARA-X (`yr`) | 1.21.0 (sha256 pinned) | Rule scanning and compile checks |
| tcpdump | 4.99.5 | Passive capture |

The wireshark.org download page lists 4.6.9 as the current stable release. The image uses the
Debian packaged 4.4.19 because building 4.6 means building from source. Doctor is how you find
out what moving to a newer tshark changes.

## How the pieces fit

- `analyze` runs Zeek, Suricata and tshark over a pcap and stores each run. Host pairs,
  protocols and engineering actions are derived from Zeek logs and stored as observations.
- `baseline save` freezes a run's observations. `baseline diff` compares a later run with it
  and never writes.
- `doctor` replays fixtures through every tool and compares with golden files.
- `yara` scans, explains and drafts rules. A model is optional and off by default.
- `plc` reviews PLC source for risky patterns and compares it with an approved version.
- `web` serves a local interface over all of the above. `report` writes it as a static file.

## Doctor normalization

Doctor compares normalized output so the diff is meaningful. For Zeek it removes timestamps,
connection and file UIDs, durations and ICSNPP packet correlation ids, and sorts the rows. For
Suricata it keeps alert, anomaly and flow events and removes timestamps, flow ids and flow
times. tshark rows keep frame number, addresses, TCP ports, protocol and info. Version strings
are compared separately and reported, not written into golden files.

## Safety rules

1. Passive only. No packet is sent. Tool containers run with no network.
2. `capture` needs an explicit interface (never `any`) and refuses to overwrite a file.
3. Baselines are immutable. The database rejects updates, deletes and late inserts.
4. No capture data goes to any model. A model sees a rule, or your description, and nothing else.
5. The only network calls are the optional model call and `yara fetch`.
6. The web interface listens on loopback only, has no login, and refuses other addresses, foreign
   `Host` headers and cross-site POSTs.

## Not verified

- That the PLC code patterns catch what matters in your plant. The list is short and heuristic.
  It is a review aid, not a vulnerability scanner, and it does not look at firmware.
- That no other OT tool does version compatibility checking. Only a few searches were made.
- That ICSNPP works unchanged on Zeek 9.0 for real traffic.
- Licensing of public ICS pcaps. None are bundled. Fixtures are generated.
- The quality of public OT YARA rules beyond a few examples.
- Singapore CCoP or any other compliance regime. No compliance claims are made.

## Related tools

Malcolm is a full stack with dashboards, while rehub is a small CLI for one analyst on one
capture. ICSForge generates test traffic and checks detection gaps, while rehub analyzes
captures and checks the tools themselves. The two can be used together. ICSForge is GPLv3 and
none of its code is bundled here.

## License

Apache-2.0. Yara-Rules is GPL-2.0, so `rehub yara fetch` clones a pinned commit into your own
directory and nothing from it is bundled.

## Changelog

See [../CHANGELOG.md](../CHANGELOG.md).
