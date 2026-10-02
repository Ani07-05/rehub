# Usage

All commands run as `uv run rehub ...` on the host, or `rehub ...` inside the image. Exit codes:
0 success, 1 a check found a difference or failure, 2 a usage or runtime error.

Environment and files:

| Name | Meaning |
|---|---|
| `REHUB_HOME` | State directory, default `~/.rehub` (`rehub.db`, `config.toml`, `runs/`) |
| `REHUB_IN_IMAGE` | Set inside the image. Tools run directly instead of through Docker |
| `REHUB_MODEL` | Model name for `yara explain` and `yara draft` |
| `REHUB_OLLAMA_URL` | Ollama endpoint, default `http://localhost:11434` |
| `ANTHROPIC_API_KEY` | Needed only for `--provider anthropic` |
| `config.toml` | `image`, `provider`, `model` defaults. Flags and environment win |

## init

```sh
rehub init [--image IMAGE]
```

Creates the home directory, database and config file (an existing config is kept), then prints
pinned and installed tool versions. Exit 1 if any version differs from its pin.

## tools

```sh
rehub tools [--image IMAGE]
```

```
zeek             pinned 8.0.10   installed 8.0.10   OK
ICSNPP::S7COMM   pinned 1.3.0    installed 1.3.0    OK
suricata         pinned 8.0.7    installed 8.0.7    OK
```

## doctor

```sh
rehub doctor [--image IMAGE] [--accept]
```

Replays every fixture through every installed tool, normalizes, and compares with
`fixtures/golden/<tool>/<fixture>.json`. Prints PASS or FAIL per tool and fixture, and for each
difference a line naming the log and the field or row that was added, removed or changed. Also
prints a line when an installed version differs from its pin. Results are stored in the
`doctor_runs` table. Exit 1 if anything failed.

Check a candidate image before you switch to it:

```sh
docker build -f docker/Dockerfile -t rehub:candidate .          # for example with a newer base
rehub doctor --image rehub:candidate
```

`--accept` rewrites the golden files from the current run. Use it only after you have read the
differences and decided the new behavior is correct. Nothing else ever writes golden files.

Fixtures: three synthetic pcaps (S7 download and stop, EtherNet/IP identity, Modbus read and
write) and four YARA samples. Regenerate them with `python fixtures/generate.py`. The output is
byte for byte deterministic.

## analyze

```sh
rehub analyze FILE.pcap [--image IMAGE]
```

Runs Zeek, Suricata and tshark over the capture (read only, no network) and stores each as a
run with its raw output in `$REHUB_HOME/runs/<id>`. Prints a count per log, then the
observations: `source -> destination  protocol  action`.

An action is `conn` for a plain connection, or an engineering function: `program download`,
`program upload`, `stop`, `mode change`, `parameter write`. Observations come from the Zeek run.
Use the `--run N` value printed on the observations line with `baseline`.

## capture

```sh
rehub capture --iface IFACE --seconds N --out FILE.pcap
```

Passive tcpdump for a fixed time. `--iface` is required and must be one named interface (not
`any`). `--seconds` is 1 to 86400. The output file must not exist. It prints that rehub only
listens. Needs tcpdump and capture privileges, see [install.md](install.md).

## web

```sh
rehub web [--port 8765] [--image IMAGE] [--open]
```

Serves the interface at `http://127.0.0.1:8765/` on this computer only. There is no login, so
`--host` accepts loopback addresses and nothing else. The server also rejects any request whose
`Host` header is not loopback (DNS rebinding) and any POST without its `X-Rehub` header (other
websites).

- **Start:** the guided path. Six steps in order, each with its action on the same page: check the
  tools, analyze a capture, freeze a baseline, compare a new capture, run doctor before a tool
  upgrade, and optionally draft a rule. The next step is marked, steps that need an earlier one
  are locked, and every other page shows what to do next.
- **Traffic:** drop a `.pcap` or `.pcapng`. It is analyzed with Zeek, Suricata and tshark (tools
  run with no network), stored, and drawn as host pair rungs. Captures up to 256 MB.
- **Changes:** pick a baseline and a capture. Red rungs are new host pairs, amber rungs are new
  actions, dashed rungs are pairs not seen. Save the capture as a new baseline from here. An
  existing baseline can never be changed.
- **Doctor:** run doctor against the default image or a candidate image, and check tool versions.
- **Rules:** draft a rule with a model (pick local Ollama or hosted, add sample files it must
  match and clean files it must not), or scan a sample with a pasted rule. For a hosted model the
  page first shows the exact text that would be sent and sends nothing until you press the send
  button. Sample files stay on this computer. Drafted rules show Validated or Unvalidated.
- **Traffic** also offers the bundled sample captures with one click.

The page needs nothing from the internet. Stop the server with Ctrl-C.

## report

```sh
rehub report [--out FILE.html]
```

Writes one self-contained HTML file (default `$REHUB_HOME/report.html`) from the stored runs,
baselines, doctor results and drafted rules. Open it in a browser. It is a read only snapshot:
no server, no network, no external fonts or scripts, and it does not change the database. It is
the same view as `rehub web`, frozen at the time you ran it.

Views: **Changes** (a baseline against a capture, drawn as ladder rungs: red for a new host
pair, amber for a new action, dashed for a pair not seen), **Traffic** (everything seen in one
capture), **Doctor** (latest result per tool and fixture) and **Rules** (drafted YARA rules with
their status). The alarm row at the top lights only when something differs. Normal states stay
gray. Regenerate the file after new runs. Dark and light themes follow the system setting.

## baseline

```sh
rehub baseline save NAME --run N
rehub baseline list
rehub baseline diff NAME --run N
```

`save` freezes a run's observations under a new name. An existing name is refused, and the
database itself rejects any update or delete of a saved baseline. To adopt new behavior as
normal, save a new baseline under a new name.

`diff` is read only and prints:

```
NEW PAIR      10.0.0.99 -> 10.0.0.20
NEW ACTION    10.0.0.10 -> 10.0.0.20  s7comm  stop
MISSING PAIR  10.0.0.11 -> 10.0.0.21
```

New pairs are host pairs not in the baseline. New actions are a new protocol or action on a
pair the baseline knows. Missing pairs are baseline pairs absent from the run. Exit 1 if
anything differs, 0 if the run matches.

Example, from `fixtures/scenarios`:

```sh
rehub analyze fixtures/scenarios/plant_normal.pcap          # prints --run 1
rehub baseline save plant-normal --run 1
rehub analyze fixtures/scenarios/plant_changed.pcap         # prints --run 4
rehub baseline diff plant-normal --run 4
```

## yara

```sh
rehub yara scan RULES TARGET [--image IMAGE]
rehub yara explain RULE [--provider P] [--model M] [--yes]
rehub yara draft "description" --positive FILE [--positive FILE ...] --benign DIR [--provider P] [--model M] [--yes] [--out FILE]
rehub yara fetch [--dest DIR]
```

`scan` runs `yr scan` (YARA-X) with the given rules file or directory over a file or directory
and prints `rule  file` per match. Rules shipped for the doctor fixtures are in
`docker/yara/rules`.

`explain` sends only the rule text to the model and prints a plain English explanation.

`draft` asks a model for a rule, then:

1. strips markdown fences and leading prose,
2. compiles with `yr compile`; on an error it sends the rule and the compiler error back, up to
   3 retries,
3. checks that every `--positive` file matches and no file in `--benign` matches.

The status is `validated` only if it compiled and every check passed. Otherwise it is
`unvalidated` with the reason, and the output says to review the rule before use. At least one
positive sample is needed to validate. Sample contents are never sent to a model. The rule is
stored in the `yara_rules` table with its status. Exit 0 only when validated.

Providers: `ollama` (default, local) or `anthropic` (hosted). For a hosted provider rehub prints
exactly what will be sent and stops unless you pass `--yes`.

`fetch` clones the Yara-Rules repository at a pinned commit (GPL-2.0, legacy YARA syntax, last
updated 2022) into `--dest` (default `$REHUB_HOME/yara-rules`). It needs network and git.
