@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "PROJECT_ROOT=%~dp0.."
set "ANDROID_ROOT=%PROJECT_ROOT%\android"
set "BUILD_DIR=%PROJECT_ROOT%\build\release\android"

where node >nul 2>&1 || (
  echo ERROR: node was not found in PATH.
  exit /b 1
)
where java >nul 2>&1 || (
  echo ERROR: java was not found in PATH.
  exit /b 1
)
if not exist "%ANDROID_ROOT%\gradlew.bat" (
  echo ERROR: Android Gradle wrapper was not found.
  exit /b 1
)

if /i "%PHANTOM_SKIP_VERSION_BUMP%"=="1" (
  node "%PROJECT_ROOT%\tools\version.mjs" check || exit /b 1
) else (
  node "%PROJECT_ROOT%\tools\version.mjs" bump || exit /b 1
)
for /f "delims=" %%V in ('node "%PROJECT_ROOT%\tools\version.mjs" current') do set "APP_VERSION=%%V"
if not defined APP_VERSION exit /b 1

echo ==========================================
echo PhantomP2P Android build %APP_VERSION%
echo ==========================================

pushd "%ANDROID_ROOT%"
call gradlew.bat --no-daemon clean assembleStandardRelease -Pphantom.buildRustNative=true
if errorlevel 1 (
  popd
  exit /b 1
)
popd

if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
mkdir "%BUILD_DIR%" || exit /b 1

set "APK_COUNT=0"
for /r "%ANDROID_ROOT%\app\build\outputs\apk\standard\release" %%F in (*.apk) do (
  set /a APK_COUNT+=1
  copy /y "%%F" "%BUILD_DIR%\phantom-p2p-%APP_VERSION%-android.apk" >nul || exit /b 1
)
if not "!APK_COUNT!"=="1" (
  echo ERROR: expected one release APK, found !APK_COUNT!.
  exit /b 1
)

echo Build completed: %BUILD_DIR%
dir /b "%BUILD_DIR%"
exit /b 0
