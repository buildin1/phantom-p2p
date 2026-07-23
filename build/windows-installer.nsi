; 幻梦P2P Windows x64 安装程序
; 功能：自定义安装路径、记住上次路径、WebView2集成、自动更新支持
; 用法: makensis -INPUTCHARSET UTF8 -DSTAGING_DIR=/path -DOUTPUT_DIR=/path windows-installer.nsi

Unicode true

!ifndef APP_NAME
  !define APP_NAME "幻梦P2P"
!endif
!ifndef APP_VERSION
  !define APP_VERSION "2.7.7"
!endif
!define APP_EXE       "phantom-p2p.exe"
!define APP_PUBLISHER "Phantom P2P Project"
!define APP_URL       "https://github.com/phantom-p2p/phantom-p2p"

; ── 注册表键（用于记住安装路径&自动更新）──
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\phantom-p2p"
!define PUBLISHER_KEY "Software\PhantomP2P"
!define UPDATE_KEY    "Software\PhantomP2P\Updater"

Name "${APP_NAME} ${APP_VERSION}"
OutFile "${OUTPUT_DIR}\${APP_NAME}_${APP_VERSION}_x64-setup.exe"

; ── 安装默认路径 ──────────────────────────
; 优先读取上次安装路径，其次使用默认路径
InstallDir "$LOCALAPPDATA\Programs\phantom-p2p"
InstallDirRegKey HKCU "${UNINSTALL_KEY}" "InstallLocation"

RequestExecutionLevel admin
ShowInstDetails hide
ShowUninstDetails hide

SetCompressor /SOLID lzma
SetCompressorDictSize 64

; ── 安装向导页 ─────────────────────────────
!include "MUI2.nsh"
!include "WinMessages.nsh"
!include "FileFunc.nsh"

; 界面设置
!define MUI_ABORTWARNING
!define MUI_ICON "${STAGING_DIR}\..\..\png\icon.ico"
!define MUI_UNICON "${STAGING_DIR}\..\..\png\icon.ico"

; 安装目录选择页
!define MUI_DIRECTORYPAGE_VERIFYONINIT
!insertmacro MUI_PAGE_DIRECTORY

; 安装进度页
!insertmacro MUI_PAGE_INSTFILES

; 完成页
!define MUI_FINISHPAGE_RUN "$INSTDIR\${APP_EXE}"
!define MUI_FINISHPAGE_RUN_TEXT "立即启动 ${APP_NAME}"
!define MUI_FINISHPAGE_LINK "访问项目主页"
!define MUI_FINISHPAGE_LINK_LOCATION "${APP_URL}"
!insertmacro MUI_PAGE_FINISH

; 卸载页
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; 语言
!insertmacro MUI_LANGUAGE "SimpChinese"

; ── 安装节 ─────────────────────────────────
Section "Main" SEC_MAIN
  SectionIn RO
  SetShellVarContext current
  SetOutPath "$INSTDIR"

  ; 复制主程序文件
  File "${STAGING_DIR}\${APP_EXE}"

  ; 创建桌面快捷方式
  CreateShortCut "$DESKTOP\${APP_NAME}.lnk" "$INSTDIR\${APP_EXE}" \
    "" "$INSTDIR\${APP_EXE}" 0 SW_SHOWNORMAL

  ; 创建开始菜单
  CreateDirectory "$SMPROGRAMS\${APP_NAME}"
  CreateShortCut "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" \
    "$INSTDIR\${APP_EXE}" "" "$INSTDIR\${APP_EXE}" 0 SW_SHOWNORMAL
  CreateShortCut "$SMPROGRAMS\${APP_NAME}\卸载 ${APP_NAME}.lnk" \
    "$INSTDIR\uninstall.exe"

  ; 写入卸载信息到"程序和功能"
  WriteUninstaller "$INSTDIR\uninstall.exe"

  WriteRegStr  HKCU "${UNINSTALL_KEY}" "DisplayName"       "${APP_NAME}"
  WriteRegStr  HKCU "${UNINSTALL_KEY}" "UninstallString"   '"$INSTDIR\uninstall.exe"'
  WriteRegStr  HKCU "${UNINSTALL_KEY}" "InstallLocation"   "$INSTDIR"
  WriteRegStr  HKCU "${UNINSTALL_KEY}" "Publisher"         "${APP_PUBLISHER}"
  WriteRegStr  HKCU "${UNINSTALL_KEY}" "DisplayVersion"    "${APP_VERSION}"
  WriteRegStr  HKCU "${UNINSTALL_KEY}" "DisplayIcon"       "$INSTDIR\${APP_EXE},0"
  WriteRegStr  HKCU "${UNINSTALL_KEY}" "URLInfoAbout"      "${APP_URL}"
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoModify"         1
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoRepair"         1
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "EstimatedSize"    51200  ; ~50MB 估算

  ; 保存当前安装路径，供下次升级时 InstallDirRegKey 读取
  WriteRegStr HKCU "${UPDATE_KEY}" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "${UPDATE_KEY}" "LastVersion" "${APP_VERSION}"
  WriteRegStr HKCU "${UPDATE_KEY}" "LastInstalled" ""

SectionEnd

; ── 卸载节 ─────────────────────────────────
Section "Uninstall"
  SetShellVarContext current

  ; 停止可能正在运行的程序进程
  ExecWait 'taskkill /f /im ${APP_EXE}' $0

  ; 询问是否保留配置
  MessageBox MB_YESNO|MB_ICONQUESTION \
    "是否保留配置文件和日志数据？$\r$\n\
     (选择「是」可保留设置，下次安装时沿用)" \
    IDYES keep_data

    ; 不保留：删除所有文件
    RMDir /r "$INSTDIR"
    Goto done_delete

  keep_data:
    ; 保留 config.toml，只删除程序文件
    Delete "$INSTDIR\${APP_EXE}"
    Delete "$INSTDIR\uninstall.exe"
    Delete "$INSTDIR\wintun.dll"
    Delete "$INSTDIR\WebView2Loader.dll"

  done_delete:

  ; 删除快捷方式
  Delete "$DESKTOP\${APP_NAME}.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk"
  Delete "$SMPROGRAMS\${APP_NAME}\卸载 ${APP_NAME}.lnk"
  RMDir  "$SMPROGRAMS\${APP_NAME}"

  ; 删除注册表项
  DeleteRegKey HKCU "${UNINSTALL_KEY}"

SectionEnd

; ── 安装前检查 ─────────────────────────────
Function .onInit
  ; 检查是否已安装旧版本
  ReadRegStr $0 HKCU "${UNINSTALL_KEY}" "InstallLocation"
  StrCmp $0 "" no_previous

    ReadRegStr $1 HKCU "${UNINSTALL_KEY}" "DisplayVersion"
    StrCmp $1 "" no_previous

    MessageBox MB_YESNO|MB_ICONQUESTION \
      "检测到已安装 ${APP_NAME} $1。$\r$\n\
       是否卸载旧版本后安装新版本？$\r$\n\
       (选择「否」将直接覆盖安装)" \
      IDNO do_overwrite

      ; 执行旧版本的卸载程序
      ExecWait '"$0\uninstall.exe" /S _?=$0'

  do_overwrite:
    StrCpy $INSTDIR $0

  no_previous:

FunctionEnd

; ── 卸载前检查 ─────────────────────────────
Function un.onInit
  MessageBox MB_OKCANCEL|MB_ICONQUESTION \
    "确定要卸载 ${APP_NAME} ${APP_VERSION} 吗？" \
    IDOK +2
  Abort
FunctionEnd
