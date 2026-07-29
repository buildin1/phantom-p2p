@echo off
setlocal EnableExtensions EnableDelayedExpansion

rem Native (or MSVC-ARM64-toolchain-equipped) Windows build for the ARM64
rem target. Mirrors build-windows.bat but pins --target explicitly to
rem aarch64-pc-windows-msvc so this also works when invoked cross-target
rem from an x64 Windows host that has the ARM64 MSVC toolset installed via
rem Visual Studio Installer ("MSVC v143 - VS 2022 C++ ARM64 build tools").
rem On a native windows-11-arm machine this is simply the host target.

set "PROJECT_ROOT=%~dp0.."
set "BUILD_DIR=%PROJECT_ROOT%\build\release\windows-arm64"
set "APP_NAME=PhantomP2P"
set "NSIS_PATH=%PROGRAMFILES(x86)%\NSIS"
set "RUST_TARGET=aarch64-pc-windows-msvc"

where rustc >nul 2>&1 || (
  echo ERROR: rustc was not found in PATH.
  exit /b 1
)
where cargo >nul 2>&1 || (
  echo ERROR: cargo was not found in PATH.
  exit /b 1
)
where node >nul 2>&1 || (
  echo ERROR: node was not found in PATH.
  exit /b 1
)
where npm >nul 2>&1 || (
  echo ERROR: npm was not found in PATH.
  exit /b 1
)

rustup target add %RUST_TARGET% >nul 2>&1

if /i "%PHANTOM_SKIP_VERSION_BUMP%"=="1" (
  node "%PROJECT_ROOT%\tools\version.mjs" check || exit /b 1
) else (
  node "%PROJECT_ROOT%\tools\version.mjs" bump || exit /b 1
)
for /f "delims=" %%V in ('node "%PROJECT_ROOT%\tools\version.mjs" current') do set "APP_VERSION=%%V"
if not defined APP_VERSION (
  echo ERROR: failed to read application version.
  exit /b 1
)

echo ==========================================
echo %APP_NAME% Windows ARM64 build %APP_VERSION%
echo ==========================================

echo [1/4] Building frontend...
cd /d "%PROJECT_ROOT%"
call npm install || exit /b 1
call npm run build || exit /b 1

echo [2/4] Building Tauri release executable (target %RUST_TARGET%)...
call npx tauri build --target %RUST_TARGET% || exit /b 1

echo [3/4] Building signaling server executable (target %RUST_TARGET%)...
cargo build --release -p phantom-server --target %RUST_TARGET% || exit /b 1

echo [4/4] Staging executables and NSIS installer...
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
mkdir "%BUILD_DIR%" || exit /b 1
copy /y "%PROJECT_ROOT%\target\%RUST_TARGET%\release\phantom-p2p.exe" "%BUILD_DIR%\phantom-p2p.exe" >nul || exit /b 1
copy /y "%PROJECT_ROOT%\target\%RUST_TARGET%\release\phantom-server.exe" "%BUILD_DIR%\phantom-server.exe" >nul || exit /b 1

if exist "%NSIS_PATH%\makensis.exe" (
  cd /d "%PROJECT_ROOT%\build"
  "%NSIS_PATH%\makensis.exe" -INPUTCHARSET UTF8 -DSTAGING_DIR="%BUILD_DIR%" -DOUTPUT_DIR="%BUILD_DIR%" -DAPP_VERSION="%APP_VERSION%" windows-installer.nsi || exit /b 1
) else (
  where makensis >nul 2>&1 || (
    echo ERROR: NSIS makensis was not found.
    exit /b 1
  )
  cd /d "%PROJECT_ROOT%\build"
  makensis -INPUTCHARSET UTF8 -DSTAGING_DIR="%BUILD_DIR%" -DOUTPUT_DIR="%BUILD_DIR%" -DAPP_VERSION="%APP_VERSION%" windows-installer.nsi || exit /b 1
)

echo Build completed: %BUILD_DIR%
dir /b "%BUILD_DIR%"
exit /b 0
