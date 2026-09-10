# 生成 release 签名密钥，并打印配置 GitHub Actions secrets 需要的四个值。
#
#     cd mobile\android\tools
#     .\new-keystore.ps1
#
# 只需要跑一次。生成的 .jks 不会进仓库（.gitignore 已覆盖）。

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# 找 keytool。它随 JDK 走，Android Studio 自带一个。
# ---------------------------------------------------------------------------
function Find-Keytool {
    $cmd = Get-Command keytool -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $candidates = @(
        "$env:JAVA_HOME\bin\keytool.exe",
        "$env:ProgramFiles\Android\Android Studio\jbr\bin\keytool.exe",
        "$env:LOCALAPPDATA\Programs\Android Studio\jbr\bin\keytool.exe",
        "$env:ProgramFiles\Android\Android Studio\jre\bin\keytool.exe"
    )
    foreach ($p in $candidates) {
        if ($p -and (Test-Path $p)) { return $p }
    }

    throw "找不到 keytool。装了 Android Studio 的话它在 <安装目录>\jbr\bin\keytool.exe，或者设置 JAVA_HOME。"
}

$keytool = Find-Keytool
Write-Host "keytool: $keytool" -ForegroundColor DarkGray

# ---------------------------------------------------------------------------
# 参数
# ---------------------------------------------------------------------------
$moduleDir = Split-Path -Parent $PSScriptRoot
$keystore = Join-Path $moduleDir 'phantom-release.jks'
$alias = 'phantom'

if (Test-Path $keystore) {
    Write-Host ""
    Write-Host "已经存在：$keystore" -ForegroundColor Yellow
    Write-Host "覆盖它意味着换掉应用身份，已装旧版的用户将无法升级、只能卸载重装。" -ForegroundColor Yellow
    $answer = Read-Host "确定要覆盖吗？输入 yes 继续"
    if ($answer -ne 'yes') { Write-Host "已取消。"; exit 0 }
    Remove-Item $keystore
}

Write-Host ""
Write-Host "设置 keystore 密码（至少 6 位）。这个密码和下面生成的文件都要备份好。" -ForegroundColor Cyan
$pass1 = Read-Host "密码" -AsSecureString
$pass2 = Read-Host "再输一次" -AsSecureString

$plain1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass1))
$plain2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass2))

if ($plain1 -ne $plain2) { throw "两次输入不一致。" }
if ($plain1.Length -lt 6) { throw "密码至少 6 位。" }

# ---------------------------------------------------------------------------
# 生成
#
# 有效期 10000 天（约 27 年）：Play 商店要求签名密钥至少在 2033 年后过期，
# 而且密钥一旦过期就再也不能给应用推更新，没有理由设短。
# ---------------------------------------------------------------------------
& $keytool -genkeypair -v `
    -keystore $keystore `
    -alias $alias `
    -keyalg RSA -keysize 2048 -validity 10000 `
    -storepass $plain1 -keypass $plain1 `
    -dname "CN=Phantom, OU=buildin1, O=buildin1, C=CN"

if ($LASTEXITCODE -ne 0) { throw "keytool 失败。" }

# ---------------------------------------------------------------------------
# 本地配置文件
# ---------------------------------------------------------------------------
$propsPath = Join-Path $moduleDir 'keystore.properties'
@"
storeFile=phantom-release.jks
storePassword=$plain1
keyAlias=$alias
keyPassword=$plain1
"@ | Set-Content -Path $propsPath -Encoding utf8

# ---------------------------------------------------------------------------
# CI 用的 base64
# ---------------------------------------------------------------------------
$base64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($keystore))
$b64Path = Join-Path $env:TEMP 'phantom-keystore.base64.txt'
$base64 | Set-Content -Path $b64Path -Encoding ascii -NoNewline

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Green
Write-Host " 完成" -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "生成了两个文件（都不会进仓库）："
Write-Host "  $keystore"
Write-Host "  $propsPath"
Write-Host ""
Write-Host "现在去 GitHub 配 4 个 secrets：" -ForegroundColor Cyan
Write-Host "  仓库 → Settings → Secrets and variables → Actions → New repository secret"
Write-Host ""
Write-Host "  ANDROID_KEYSTORE_BASE64    ← 内容在这个文件里，全选复制："
Write-Host "                                $b64Path" -ForegroundColor Yellow
Write-Host "  ANDROID_KEYSTORE_PASSWORD  ← 刚才设的密码"
Write-Host "  ANDROID_KEY_ALIAS          ← $alias"
Write-Host "  ANDROID_KEY_PASSWORD       ← 同 ANDROID_KEYSTORE_PASSWORD"
Write-Host ""
Write-Host "配完把 base64 那个临时文件删掉：" -ForegroundColor DarkGray
Write-Host "  Remove-Item `"$b64Path`"" -ForegroundColor DarkGray
Write-Host ""
Write-Host "⚠ 把 $keystore 备份到仓库之外的安全地方。" -ForegroundColor Red
Write-Host "  这个文件丢了，就再也无法给已发布的应用推更新——只能换应用 ID 重新来过。" -ForegroundColor Red
Write-Host ""
