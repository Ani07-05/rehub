# rehub

Know what normal looks like on your plant network.

rehub is a local app with a browser interface. Drop in a network capture and it runs the standard
open source analysis tools on it, passively. It remembers what "normal" looked like, shows what
changed, and tells you what an upgrade of any of those tools will change before you do it.

It only listens. Nothing in rehub sends a packet to a network.

## What you get

- **A recording becomes a readable picture.** Who talks to whom, over which protocol, and which
  risky actions they perform, for S7comm, EtherNet/IP and Modbus/TCP.
- **A memory of normal.** Save a recording as a baseline, compare later recordings with it, and see
  exactly what is new. Saved baselines never change.
- **An upgrade check.** Before you move sensors to a new Zeek, Suricata or tshark, replay test
  recordings through every tool and see what comes out different.
- **Detection rules with tests behind them.** Write a YARA rule, or draft one with a model (Groq
  or Anthropic, with your own key). A rule only counts as validated when it compiles, matches every
  file you say it must, and matches none of the clean ones.
- **A PLC program check.** Upload Structured Text, SCL or Rockwell L5X source and see risky
  patterns and what changed since the version you approved.
- **Built-in help.** Answers from the manual with no model. A model is optional.

## Install

macOS and Linux:

```sh
curl -fsSL https://rehub-rose.vercel.app/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://rehub-rose.vercel.app/install.ps1 | iex
```

It needs Docker running and git. It installs uv if you have none, gets rehub, builds or pulls the
tool image, checks the tools, and opens the interface in your browser. The first image build takes
several minutes. Read the script first at `scripts/install.sh`, or see
[docs/install.md](docs/install.md) to do each step yourself.

Already have the source:

```sh
uv sync
uv run rehub init
uv run rehub setup      # pulls the published image, or builds it from docker/Dockerfile
uv run rehub web --open
```

## The interface

`rehub web --open` starts a page on your own computer behind a private link. It has six pages.

| Page | What it answers |
|---|---|
| Start | Load a recording or try the one-click demo |
| What changed | How does this recording differ from the one I call normal? |
| Conversations | Who talks to whom, over which protocol, doing what? |
| PLC code | Is this program change risky, and what moved since I approved the last one? |
| Upgrade check | What will a new tool version change? |
| Detection rules | Write, draft and test a YARA rule |

`rehub report` writes the same view as one offline HTML file you can share.

## The tools

rehub wraps these. It does not replace any of them. They run together inside one Docker image.

| Tool | Version | What rehub uses it for |
|---|---|---|
| [Zeek](https://zeek.org) | 8.0.10 | Protocol logs and the main source of who talks to whom |
| [ICSNPP](https://github.com/cisagov/icsnpp) s7comm, enip, modbus | pinned commits | OT protocol parsers for Zeek, from CISA |
| [Suricata](https://suricata.io) | 8.0.7 | Rule-based detection |
| [tshark](https://www.wireshark.org) | 4.4.19 | Per-packet summary |
| [YARA-X](https://virustotal.github.io/yara-x/) | 1.21.0 | Compiling and testing detection rules |
| [tcpdump](https://www.tcpdump.org) | 4.99.5 | Passive capture on Linux hosts |

Versions are pinned, and `rehub doctor` checks that the installed tools still match.

## How it stays safe

- Analysis runs in containers with networking off and read-only inputs.
- `capture` needs an explicit interface and only listens.
- The interface listens on 127.0.0.1 behind a private link. Other computers and other users on
  the same computer cannot open it.
- CI fails if a raw socket, a scapy send call or a scanner name appears in the source.
- Nothing leaves your computer unless you choose a hosted model and approve the exact text first.

## Where your data is

One SQLite file at `~/.rehub/rehub.db` (or `$REHUB_HOME`), with recordings you loaded in
`~/.rehub/uploads`, tool output in `~/.rehub/runs`, and settings in `~/.rehub/config.toml`. Delete
the folder to remove everything. API keys you paste into the page are never saved.

## What version 0.1 covers

- **Protocols:** S7comm, EtherNet/IP and Modbus/TCP.
- **S7 traffic:** Zeek reads it. Suricata has no S7comm parser, so it matches S7 with raw content
  rules.
- **Upgrade check:** it replays small synthetic recordings through every tool and shows what each
  one does differently.
- **Rules from a model:** each one is compiled and tested against the files you give it. Review a
  rule before you rely on it.
- **PLC check:** a review of risky patterns and changes, not a vulnerability scan. It does not test
  firmware.
- **Who it is for:** one analyst on one computer.
- **Platforms:** macOS arm64 is tested. Linux should work. Windows is untested.

## More

[docs/install.md](docs/install.md), [docs/usage.md](docs/usage.md) and
[docs/description.md](docs/description.md). A five minute demo is in `demo/demo.sh`. The command
line is there for scripting.

## License

Apache-2.0, see [LICENSE](LICENSE). Third party tools in the image keep their own licenses.
