#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="$PROJECT_ROOT/build/release/linux"

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
need_command() { command -v "$1" >/dev/null 2>&1 || die "missing command: $1"; }

[[ "$(uname -s)" == "Linux" ]] || die "Linux releases must be built on Linux"
for command in cargo node npm sha256sum tar file install find; do need_command "$command"; done

case "$(uname -m)" in
    x86_64|amd64) RELEASE_ARCH="x86_64" ;;
    aarch64|arm64) RELEASE_ARCH="aarch64" ;;
    *) die "unsupported Linux architecture: $(uname -m)" ;;
esac

if [[ "${PHANTOM_SKIP_VERSION_BUMP:-0}" == "1" ]]; then
    node "$PROJECT_ROOT/tools/version.mjs" check
else
    node "$PROJECT_ROOT/tools/version.mjs" bump
fi
VERSION="$(node "$PROJECT_ROOT/tools/version.mjs" current)"
CLIENT_NAME="phantom-p2p-${VERSION}-linux-${RELEASE_ARCH}"
SERVER_NAME="phantom-server-${VERSION}-linux-${RELEASE_ARCH}"
CLIENT_ARCHIVE="${CLIENT_NAME}.tar.gz"
SERVER_ARCHIVE="${SERVER_NAME}.tar.gz"

rm -rf -- "$OUTPUT_DIR"
mkdir -p -- "$OUTPUT_DIR/client" "$OUTPUT_DIR/server"
cd "$PROJECT_ROOT"

printf '[1/5] Building shared WebUI...\n'
npm ci
npm run build

printf '[2/5] Building headless WebUI client...\n'
cargo build --locked --release -p phantom-p2p-web
[[ -x target/release/phantom-p2p-web ]] || die 'phantom-p2p-web binary was not produced'
install -m 0755 target/release/phantom-p2p-web "$OUTPUT_DIR/client/$CLIENT_NAME"

printf '[3/5] Building signaling/IPv4 relay server...\n'
cargo build --locked --release -p phantom-server
[[ -x target/release/phantom-server ]] || die 'phantom-server binary was not produced'
install -m 0755 target/release/phantom-server "$OUTPUT_DIR/server/$SERVER_NAME"
install -m 0644 server/config.toml "$OUTPUT_DIR/server/config.toml"

cat > "$OUTPUT_DIR/client/README-Linux.txt" <<EOF
PhantomP2P ${VERSION} Linux headless WebUI client

Grant TUN permission once (recommended):
  sudo setcap cap_net_admin+ep ./${CLIENT_NAME}

Run:
  ./${CLIENT_NAME}

The terminal prints the room code, Host virtual IP, and WebUI addresses.
The local WebUI defaults to http://127.0.0.1:9080/ and is also exposed on
the Host virtual IP after the TUN device is ready.
Alternatively, run the client as root without setcap.
EOF

cat > "$OUTPUT_DIR/server/README-Linux.txt" <<EOF
PhantomP2P ${VERSION} Linux signaling/IPv4 relay server

Run:
  ./${SERVER_NAME}

Keep config.toml in the same directory as the server binary.
EOF

printf '[4/5] Verifying binaries...\n'
file "$OUTPUT_DIR/client/$CLIENT_NAME" "$OUTPUT_DIR/server/$SERVER_NAME"
"$OUTPUT_DIR/client/$CLIENT_NAME" --help >/dev/null
"$OUTPUT_DIR/server/$SERVER_NAME" --help >/dev/null 2>&1 || true

printf '[5/5] Creating release archives...\n'
tar -C "$OUTPUT_DIR/client" -czf "$OUTPUT_DIR/$CLIENT_ARCHIVE" "$CLIENT_NAME" README-Linux.txt
tar -C "$OUTPUT_DIR/server" -czf "$OUTPUT_DIR/$SERVER_ARCHIVE" "$SERVER_NAME" config.toml README-Linux.txt
(
    cd "$OUTPUT_DIR"
    sha256sum "client/$CLIENT_NAME" "server/$SERVER_NAME" "$CLIENT_ARCHIVE" "$SERVER_ARCHIVE" > SHA256SUMS
)
printf 'Build complete: %s\n' "$OUTPUT_DIR"
find "$OUTPUT_DIR" -maxdepth 2 -type f -printf '  %P (%s bytes)\n' | sort
