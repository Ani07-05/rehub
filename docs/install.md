# Install

## Requirements

- Docker (tested with Docker Desktop 29.8 on macOS arm64). The image builds for arm64 and amd64.
- Python 3.13 and [uv](https://docs.astral.sh/uv/) to run `rehub` on the host.
- Network access while building the image (Zeek image, ICSNPP sources, Suricata source, YARA-X
  release, Debian packages) and nothing else afterwards.
- Disk: a few GB for the image. The Suricata build takes a few minutes.

## Platforms

| Platform | Status |
|---|---|
| macOS arm64, Docker Desktop | Used for development. Analysis, doctor and baselines work. |
| Linux amd64 / arm64 | Expected to work. Not exercised by the author yet. |
| Windows 10/11, Docker Desktop | Untested. Analysis, doctor and baselines should work (needs Python 3.13 and `uv`). `capture` is not available on Windows. |

`capture` is different. It needs a real network interface and privileges, which Docker Desktop
on macOS does not give a container. Run `capture` on a Linux host or inside the image with host
networking:

```sh
docker run --rm --network host --cap-add NET_RAW --cap-add NET_ADMIN \
    -v "$PWD:/data" rehub:pinned rehub capture --iface eth0 --seconds 60 --out /data/site.pcap
```

Capturing is the only case where a rehub container gets a network. It only listens. This path
was tested on the loopback interface inside the image, not yet on a real interface.

## Get the image

```sh
uv run rehub setup
```

`setup` does nothing if `rehub:pinned` is already present. Otherwise it pulls the registry image
named by `registry_image` in `config.toml` (or `--source REGISTRY/IMAGE`) and tags it
`rehub:pinned`. If there is no registry image or the pull fails, it builds from
`docker/Dockerfile`. It then prints the pinned and installed tool versions. Published images are
built by `.github/workflows/publish-image.yml` for amd64 and arm64 on a `v*` tag, after `rehub
doctor` passes on the amd64 build.

To build by hand instead:

```sh
docker build -f docker/Dockerfile -t rehub:pinned .
```

The Zeek base image is pinned by digest. tshark and tcpdump are pinned to exact Debian
versions. The apt build dependencies used to compile ICSNPP and Suricata are not pinned, so a
rebuild on a later date can differ in those. Run `rehub doctor` after any rebuild.

## Install rehub

```sh
uv sync
uv run rehub init
```

`init` creates `~/.rehub` (or `$REHUB_HOME`) with `rehub.db` and `config.toml`, then checks that
the image has the pinned tool versions. It exits 1 and says so when they differ.

## Run everything inside the image instead

No host Python needed:

```sh
docker run --rm -v "$PWD/fixtures/scenarios:/data:ro" -v rehub-home:/root/.rehub \
    rehub:pinned rehub analyze /data/plant_normal.pcap
```

Inside the image `rehub` runs the tools directly. The named volume keeps the database between
runs.

## Optional: a local model for `yara explain` and `yara draft`

Install [Ollama](https://ollama.com), pull a model, then set `REHUB_MODEL` (or pass `--model`).
The default endpoint is `http://localhost:11434`, override with `REHUB_OLLAMA_URL`. The model
calls run on the host, so they work with the host CLI and not from inside the image.

A hosted provider is opt-in: set `ANTHROPIC_API_KEY` and pass `--provider anthropic`, or set
`GROQ_API_KEY` and pass `--provider groq`. rehub
prints the exact text it would send and sends nothing until you also pass `--yes`.

## Open the interface

```sh
uv run rehub web --open
```

It prints a private link (`...?token=...`) and listens on `127.0.0.1:8765` only. It refuses any
other address, so run it from the host
CLI. It is not meant to run inside the image; the image is for the tools.

## Verify

```sh
uv run rehub tools     # pinned vs installed versions
uv run rehub doctor    # all fixtures PASS
uv run pytest -q       # tests, including the ones that use the image
```
