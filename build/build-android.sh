#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
ANDROID_ROOT="$PROJECT_ROOT/android"
OUTPUT_DIR="$PROJECT_ROOT/build/release/android"

command -v node >/dev/null 2>&1 || { echo "error: node was not found" >&2; exit 1; }
command -v java >/dev/null 2>&1 || { echo "error: java was not found" >&2; exit 1; }
[[ -f "$ANDROID_ROOT/gradlew" ]] || { echo "error: Android Gradle wrapper was not found" >&2; exit 1; }

if [[ "${PHANTOM_SKIP_VERSION_BUMP:-0}" == "1" ]]; then
  node "$PROJECT_ROOT/tools/version.mjs" check
else
  node "$PROJECT_ROOT/tools/version.mjs" bump
fi
VERSION="$(node "$PROJECT_ROOT/tools/version.mjs" current)"

printf 'PhantomP2P Android build %s\n' "$VERSION"
cd "$ANDROID_ROOT"
./gradlew --no-daemon clean assembleStandardRelease -Pphantom.buildRustNative=true

APK_DIR="$ANDROID_ROOT/app/build/outputs/apk/standard/release"
APK_COUNT="$(find "$APK_DIR" -maxdepth 1 -type f -name '*.apk' -print | wc -l | tr -d ' ')"
[[ "$APK_COUNT" == "1" ]] || { echo "error: expected one release APK, found $APK_COUNT" >&2; exit 1; }
APK_SOURCE="$(find "$APK_DIR" -maxdepth 1 -type f -name '*.apk' -print -quit)"

rm -rf -- "$OUTPUT_DIR"
mkdir -p -- "$OUTPUT_DIR"
install -m 0644 -- "$APK_SOURCE" "$OUTPUT_DIR/phantom-p2p-${VERSION}-android.apk"
(
  cd "$OUTPUT_DIR"
  sha256sum "phantom-p2p-${VERSION}-android.apk" > SHA256SUMS
)

printf 'Build complete: %s\n' "$OUTPUT_DIR"
