@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "PROJECT_ROOT=%~dp0.."
set "BUILD_DIR=%PROJECT_ROOT%\build\release\windows"
set "APP_NAME=PhantomP2P"
set "NSIS_PATH=%PROGRAMFILES(x86)%\NSIS"

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
echo %APP_NAME% Windows build %APP_VERSION%
echo ==========================================

echo [1/4] Building frontend...
cd /d "%PROJECT_ROOT%"
call npm install || exit /b 1
call npm run build || exit /b 1

echo [2/4] Building Tauri release executable...
call npm run tauri build || exit /b 1

echo [3/4] Building signaling server executable...
cargo build --release -p phantom-server || exit /b 1

echo [4/4] Staging executables and NSIS installer...
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
mkdir "%BUILD_DIR%" || exit /b 1
copy /y "%PROJECT_ROOT%\target\release\phantom-p2p.exe" "%BUILD_DIR%\phantom-p2p.exe" >nul || exit /b 1
copy /y "%PROJECT_ROOT%\target\release\phantom-server.exe" "%BUILD_DIR%\phantom-server.exe" >nul || exit /b 1

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
