#!/usr/bin/env bash
set -euo pipefail

APP_ID="${APP_ID:-com.buildin1.phantom_p2p}"
OUT_DIR="${OUT_DIR:-android-logs/$(date +%Y%m%d-%H%M%S)}"
ADB="${ADB:-adb}"

mkdir -p "$OUT_DIR"

echo "[phantom] adb: $($ADB version | head -n 1)"
echo "[phantom] output: $OUT_DIR"

if ! $ADB get-state >/dev/null 2>&1; then
  echo "[phantom] no adb device is ready. Plug in the phone, enable USB debugging, and accept the RSA prompt."
  exit 1
fi

{
  echo "== adb devices =="
  $ADB devices -l || true
  echo
  echo "== device =="
  $ADB shell getprop ro.product.manufacturer || true
  $ADB shell getprop ro.product.model || true
  $ADB shell getprop ro.build.version.release_or_codename || true
  $ADB shell getprop ro.build.version.sdk || true
  $ADB shell getprop ro.build.fingerprint || true
  echo
  echo "== package =="
  $ADB shell dumpsys package "$APP_ID" | grep -E "versionName|versionCode|targetSdk|firstInstallTime|lastUpdateTime" || true
  echo
  echo "== vpn =="
  $ADB shell dumpsys connectivity | grep -Ei "vpn|phantom|tun|uid|networkagent" | head -n 240 || true
} > "$OUT_DIR/device.txt" 2>&1

$ADB logcat -b all -d -v threadtime > "$OUT_DIR/logcat-all.txt" 2>&1 || true
$ADB logcat -b crash -d -v threadtime > "$OUT_DIR/logcat-crash.txt" 2>&1 || true
$ADB logcat -d -v threadtime \
  | grep -Ei "PhantomVpn|TcpVpn|NativeQuic|phantom|QUIC|tcp|vpn|timeout|closed|stream|AndroidRuntime|SIGABRT|panic|Minecraft|FCL" \
  > "$OUT_DIR/logcat-phantom-filtered.txt" 2>&1 || true

if $ADB shell run-as "$APP_ID" ls files >/dev/null 2>&1; then
  $ADB exec-out run-as "$APP_ID" sh -c 'find files -maxdepth 2 -type f -name "*.log" -print -exec cat {} \;' \
    > "$OUT_DIR/app-files-logs.txt" 2>&1 || true
fi

if $ADB shell ls /data/tombstones >/dev/null 2>&1; then
  $ADB shell ls -lt /data/tombstones > "$OUT_DIR/tombstones-list.txt" 2>&1 || true
  latest="$($ADB shell ls -t /data/tombstones/tombstone_* 2>/dev/null | head -n 1 | tr -d '\r' || true)"
  if [[ -n "$latest" ]]; then
    $ADB shell cat "$latest" > "$OUT_DIR/latest-tombstone.txt" 2>&1 || true
  fi
fi

echo "[phantom] captured files:"
find "$OUT_DIR" -type f -maxdepth 1 -print
