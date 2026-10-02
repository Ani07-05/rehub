# rehub

A command line tool that runs the standard open source network analysis tools on OT traffic,
passively, remembers what "normal" looked like, and tells you what an upgrade of any of those
tools will change before you do it.

It wraps Zeek (with the CISA ICSNPP parsers), Suricata, tshark, YARA-X and tcpdump. It does
not replace any of them.

## Limits, stated first

- **Passive only.** No code path sends a packet to a network. No active scanner is wrapped. CI
  fails if a raw socket, scapy send call or scanner name appears in the source.
- **Three protocols in v0.1.** S7comm, EtherNet/IP (CIP) and Modbus/TCP, through the pinned
  ICSNPP parsers. Other ICSNPP parsers are not in the image yet.
- **Suricata has no S7comm parser.** S7 traffic is matched by raw content rules and shows
  `app_proto: failed` in Suricata output. Zeek is the source of S7 observations.
- **Fixtures are synthetic.** Doctor proves the tools behave the same on small generated
  captures. It does not prove they behave the same on your plant's traffic.
- **Doctor reports differences, it does not predict breakage.** On the three fixtures, a Zeek
  9.0.0 build with the same ICSNPP commits produced identical output. That says nothing about
  other traffic.
- **Model-written YARA rules are untrusted.** A rule is marked `validated` only when it compiles
  and matches every sample you give it and no benign file you give it. That is a test of your
  samples, not a guarantee of detection quality.
- **Single analyst, local only.** The web interface listens on loopback only behind a private link
  (token), so it refuses any other address and other users of the same computer cannot open it. No multi-user mode, no live PLC
  access, no compliance claims.
- **Needs Docker.** The pinned tools run inside one image. The host runs only `rehub`.

## What it adds

1. **Safe by default.** Tools run with `--network none` and read-only inputs. `capture` needs an
   explicit interface and says it only listens.
2. **`rehub doctor`.** Replays bundled synthetic fixtures through every wrapped tool, normalizes
   the output, compares it to committed golden files, and names what changed. Run it against a
   candidate image before you switch sensors to it.
3. **An interface.** `rehub web` serves a local page: drop in a capture, see baseline changes
   drawn as ladder rungs, run doctor, scan with a rule. `rehub report` writes the same view as
   one offline HTML file. A built-in help assistant answers common questions with no model.
4. **One memory.** Runs, tool versions and baselines live in one local SQLite file, so
   "is this new?" has an answer. Baselines are immutable.

## Where your data is

One SQLite file at `~/.rehub/rehub.db` (or `$REHUB_HOME`), with recordings you loaded in
`~/.rehub/uploads`, tool output in `~/.rehub/runs`, and settings in `~/.rehub/config.toml`. Delete
the folder to remove everything. Nothing leaves your computer unless you choose a hosted model.

## PLC program check

`rehub plc check program.st` reviews Structured Text, SCL or Rockwell L5X source for risky patterns
and compares it with an approved version. It is a review, not a vulnerability scan: there is no
standard database of PLC logic vulnerabilities and rehub does not test firmware.

## Quick start

```sh
uv sync
uv run rehub init
uv run rehub setup      # pulls the published image, or builds it from docker/Dockerfile
uv run rehub doctor
uv run rehub web --open
```

`setup` pulls the prebuilt image when `registry_image` is set in `~/.rehub/config.toml` (or you
pass `--source`), and builds it locally otherwise. A local build takes a while because Zeek
plugins and Suricata are compiled.

See [docs/install.md](docs/install.md), [docs/usage.md](docs/usage.md) and
[docs/description.md](docs/description.md). A five minute demo is in `demo/demo.sh`.

## License

Apache-2.0, see [LICENSE](LICENSE). Third party tools in the image keep their own licenses.
