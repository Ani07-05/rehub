#!/bin/sh
set -eu

REPO="${REHUB_REPO:-https://github.com/Ani07-05/rehub.git}"
SRC="${REHUB_SRC:-$HOME/.rehub/src}"
BIN="${REHUB_BIN:-$HOME/.local/bin}"
REF="${REHUB_REF:-}"

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

command -v git >/dev/null 2>&1 || die "git is required"
command -v docker >/dev/null 2>&1 || die "Docker is required. Install Docker Desktop or Docker Engine, start it, then run this again."
docker info >/dev/null 2>&1 || die "Docker is installed but not running. Start it, then run this again."

if ! command -v uv >/dev/null 2>&1; then
    say "Installing uv"
    curl -LsSf https://astral.sh/uv/install.sh | sh
    PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
    command -v uv >/dev/null 2>&1 || die "uv installed but not on PATH; open a new shell and run this again"
fi

if [ -d "$SRC/.git" ]; then
    say "Updating $SRC"
    if [ -n "$REF" ]; then
        git -C "$SRC" fetch --tags origin
        git -C "$SRC" checkout "$REF"
    else
        git -C "$SRC" pull --ff-only
    fi
else
    say "Cloning rehub to $SRC"
    mkdir -p "$(dirname "$SRC")"
    if [ -n "$REF" ]; then
        git clone "$REPO" "$SRC"
        git -C "$SRC" checkout "$REF"
    else
        git clone --depth 1 "$REPO" "$SRC"
    fi
fi

say "Installing rehub"
(cd "$SRC" && uv sync --frozen)

mkdir -p "$BIN"
cat > "$BIN/rehub" <<WRAP
#!/bin/sh
exec uv run --frozen --project "$SRC" rehub "\$@"
WRAP
chmod +x "$BIN/rehub"
export PATH="$BIN:$PATH"

say "Creating ~/.rehub"
rehub init || true

say "Getting the tool image (a local build can take several minutes)"
rehub setup

say "Checking the tools behave as pinned"
rehub doctor

case ":$PATH:" in
    *":$BIN:"*) ;;
    *) printf '\nAdd %s to PATH to use "rehub" from any shell.\n' "$BIN" ;;
esac

say "Opening the interface (Ctrl+C to stop)"
exec rehub web --open
