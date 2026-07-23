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
CLIENT_ARCHIVE="${CLIENT_NAME}.tar.gz"

rm -rf -- "$OUTPUT_DIR"
mkdir -p -- "$OUTPUT_DIR/client"
cd "$PROJECT_ROOT"

printf '[1/5] Building shared WebUI...\n'
npm ci
npm run build

printf '[2/5] Building headless WebUI client...\n'
cargo build --locked --release -p phantom-p2p-web
[[ -x target/release/phantom-p2p ]] || die 'phantom-p2p binary was not produced'
install -m 0755 target/release/phantom-p2p "$OUTPUT_DIR/client/$CLIENT_NAME"

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

printf '[3/4] Verifying binary...\n'
file "$OUTPUT_DIR/client/$CLIENT_NAME"
"$OUTPUT_DIR/client/$CLIENT_NAME" --help >/dev/null

printf '[4/4] Creating release archive...\n'
tar -C "$OUTPUT_DIR/client" -czf "$OUTPUT_DIR/$CLIENT_ARCHIVE" "$CLIENT_NAME" README-Linux.txt
(
    cd "$OUTPUT_DIR"
    sha256sum "client/$CLIENT_NAME" "$CLIENT_ARCHIVE" > SHA256SUMS
)
printf 'Build complete: %s\n' "$OUTPUT_DIR"
find "$OUTPUT_DIR" -maxdepth 2 -type f -printf '  %P (%s bytes)\n' | sort
