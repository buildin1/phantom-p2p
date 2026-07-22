# Versioning

The single source of truth is `version.json`. Versions use `x.x.x` with
minor and patch components from 0 through 10:

```text
2.7.1 -> 2.7.2 -> ... -> 2.7.10 -> 2.8.0
1.10.10 -> 2.0.0
```

Run `node tools/version.mjs bump` only from a release build entry point. The
tool synchronizes package, Tauri, Cargo, Android, NSIS and frontend metadata.
Use `node tools/version.mjs check` to verify without changing anything.

Each platform script bumps by default. When several platform artifacts belong
to one release, let one job bump and set this variable for the remaining jobs:

```bash
PHANTOM_SKIP_VERSION_BUMP=1 ./build/build-linux.sh
```

The Windows equivalent is:

```bat
set PHANTOM_SKIP_VERSION_BUMP=1
call build\build-windows.bat
```
