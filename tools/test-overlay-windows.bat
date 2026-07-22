@echo off
setlocal EnableExtensions EnableDelayedExpansion
title PhantomP2P Overlay Network Test

echo ============================================================
echo PhantomP2P Windows Overlay Test
echo ============================================================
echo [1] Host: check TUN/listener and add a scoped firewall rule
echo [2] Guest: check TUN/route and test the Host TCP port
echo [Q] Quit
echo.
choice /c 12Q /n /m "Select role [1/2/Q]: "
if errorlevel 3 goto :end
if errorlevel 2 goto :guest
goto :host

:host
echo.
echo -------------------------- HOST -----------------------------
set "PHANTOM_TEST_HOST_IP=172.16.1.1"
set "PHANTOM_TEST_PORT=10005"
set "TEST_INPUT="
set /p "TEST_INPUT=Host virtual IP [172.16.1.1]: "
if defined TEST_INPUT for /f "tokens=*" %%A in ("!TEST_INPUT!") do set "PHANTOM_TEST_HOST_IP=%%A"
set "TEST_INPUT="
set /p "TEST_INPUT=Service TCP port [10005]: "
if defined TEST_INPUT for /f "tokens=*" %%A in ("!TEST_INPUT!") do set "PHANTOM_TEST_PORT=%%A"

echo Testing Host IP=!PHANTOM_TEST_HOST_IP!, Port=!PHANTOM_TEST_PORT!
call :validate_inputs || goto :failed

echo.
echo [1/5] Checking administrator privileges...
fltmc >nul 2>&1
if errorlevel 1 (
  set "PHANTOM_TEST_ADMIN=0"
  echo [WARN] Not running as Administrator. Firewall setup will be skipped.
  echo        Restart this BAT with "Run as administrator" on the Host.
) else (
  set "PHANTOM_TEST_ADMIN=1"
  echo [OK] Administrator privileges available.
)

echo.
echo [2/5] Checking the Host virtual interface...
powershell.exe -NoLogo -NoProfile -NonInteractive -Command ^
  "$ip=$env:PHANTOM_TEST_HOST_IP; $items=Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue ^| Where-Object { $_.IPAddress -eq $ip -and $_.InterfaceAlias -like 'PhantomP2P*' }; if(!$items){Write-Host '[FAIL] Host virtual IP is not assigned to a PhantomP2P adapter.' -ForegroundColor Red; exit 1}; $items ^| Select-Object InterfaceAlias,IPAddress,PrefixLength,AddressState ^| Format-Table -AutoSize; exit 0"
if errorlevel 1 (
  echo [HINT] Create the room on this machine and wait for TUN ready first.
  goto :failed
)

echo.
echo [3/5] Checking the overlay route...
powershell.exe -NoLogo -NoProfile -NonInteractive -Command ^
  "$ip=[ipaddress]$env:PHANTOM_TEST_HOST_IP; $o=$ip.GetAddressBytes(); $subnet=('{0}.{1}.{2}.0/24' -f $o[0],$o[1],$o[2]); $routes=Get-NetRoute -AddressFamily IPv4 -ErrorAction SilentlyContinue ^| Where-Object { $_.DestinationPrefix -eq $subnet -and $_.InterfaceAlias -like 'PhantomP2P*' }; if(!$routes){Write-Host ('[FAIL] Missing route: '+$subnet) -ForegroundColor Red; exit 1}; $routes ^| Select-Object DestinationPrefix,InterfaceAlias,NextHop,RouteMetric,State ^| Format-Table -AutoSize; exit 0"
if errorlevel 1 goto :failed

echo.
echo [4/5] Checking TCP/UDP listeners on port !PHANTOM_TEST_PORT!...
powershell.exe -NoLogo -NoProfile -NonInteractive -Command ^
  "$port=[int]$env:PHANTOM_TEST_PORT; $tcp=Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue; $udp=Get-NetUDPEndpoint -LocalPort $port -ErrorAction SilentlyContinue; if($tcp){Write-Host 'TCP listeners:' -ForegroundColor Cyan; $tcp ^| Select-Object LocalAddress,LocalPort,OwningProcess ^| Format-Table -AutoSize}; if($udp){Write-Host 'UDP listeners:' -ForegroundColor Cyan; $udp ^| Select-Object LocalAddress,LocalPort,OwningProcess ^| Format-Table -AutoSize}; if(!$tcp -and !$udp){Write-Host '[WARN] Nothing is listening on this port.' -ForegroundColor Yellow; exit 2}; if(!$tcp){Write-Host '[WARN] No TCP listener. Guest TCP test will fail.' -ForegroundColor Yellow; exit 2}; if($tcp.LocalAddress -notcontains '0.0.0.0' -and $tcp.LocalAddress -notcontains '::' -and $tcp.LocalAddress -notcontains $env:PHANTOM_TEST_HOST_IP){Write-Host '[WARN] TCP service is not bound to all addresses or the Host virtual IP.' -ForegroundColor Yellow; exit 2}; exit 0"
if errorlevel 2 echo [HINT] Paper should use server-ip= and server-port=!PHANTOM_TEST_PORT!.

echo.
echo [5/5] Configuring the scoped Host firewall rule...
if "!PHANTOM_TEST_ADMIN!"=="0" goto :host_ready
set "PHANTOM_TEST_RULE=PhantomP2P Test !PHANTOM_TEST_HOST_IP!"
powershell.exe -NoLogo -NoProfile -NonInteractive -Command ^
  "$ip=[ipaddress]$env:PHANTOM_TEST_HOST_IP; $o=$ip.GetAddressBytes(); $subnet=('{0}.{1}.{2}.0/24' -f $o[0],$o[1],$o[2]); Get-NetFirewallRule -DisplayName $env:PHANTOM_TEST_RULE -ErrorAction SilentlyContinue ^| Remove-NetFirewallRule -ErrorAction SilentlyContinue; New-NetFirewallRule -DisplayName $env:PHANTOM_TEST_RULE -Direction Inbound -Action Allow -Protocol Any -LocalAddress $env:PHANTOM_TEST_HOST_IP -RemoteAddress $subnet -Profile Any -ErrorAction Stop ^| Out-Null; Write-Host ('[OK] Firewall rule added: '+$env:PHANTOM_TEST_RULE); Write-Host ('     Local='+$env:PHANTOM_TEST_HOST_IP+', Remote='+$subnet+', Protocol=Any')"
if errorlevel 1 (
  echo [FAIL] Could not create the firewall rule.
  goto :failed
)

:host_ready
echo.
echo ============================================================
echo HOST READY
echo Guest target: !PHANTOM_TEST_HOST_IP!:!PHANTOM_TEST_PORT!
echo Leave this window open while running Guest mode remotely.
echo ============================================================

:host_menu
echo.
choice /c RDK /n /m "[R] Refresh connections  [D] Delete test rule and exit  [K] Keep rule and exit: "
if errorlevel 3 goto :end
if errorlevel 2 goto :delete_rule
powershell.exe -NoLogo -NoProfile -NonInteractive -Command ^
  "$port=[int]$env:PHANTOM_TEST_PORT; $items=Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue ^| Where-Object { $_.State -ne 'Listen' }; if($items){$items ^| Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess ^| Format-Table -AutoSize}else{Write-Host '[INFO] No non-listening TCP connections observed yet.'}"
goto :host_menu

:delete_rule
if not defined PHANTOM_TEST_RULE goto :end
powershell.exe -NoLogo -NoProfile -NonInteractive -Command ^
  "Get-NetFirewallRule -DisplayName $env:PHANTOM_TEST_RULE -ErrorAction SilentlyContinue ^| Remove-NetFirewallRule -ErrorAction SilentlyContinue"
echo [OK] Test firewall rule removed.
goto :end

:guest
echo.
echo ------------------------- GUEST -----------------------------
set "PHANTOM_TEST_HOST_IP=172.16.1.1"
set "PHANTOM_TEST_PORT=10005"
set "TEST_INPUT="
set /p "TEST_INPUT=Host virtual IP [172.16.1.1]: "
if defined TEST_INPUT for /f "tokens=*" %%A in ("!TEST_INPUT!") do set "PHANTOM_TEST_HOST_IP=%%A"
set "TEST_INPUT="
set /p "TEST_INPUT=Host service TCP port [10005]: "
if defined TEST_INPUT for /f "tokens=*" %%A in ("!TEST_INPUT!") do set "PHANTOM_TEST_PORT=%%A"

echo Testing Host IP=!PHANTOM_TEST_HOST_IP!, Port=!PHANTOM_TEST_PORT!
call :validate_inputs || goto :failed

echo.
echo [1/3] Checking Guest virtual interfaces...
powershell.exe -NoLogo -NoProfile -NonInteractive -Command ^
  "$items=Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue ^| Where-Object { $_.InterfaceAlias -like 'PhantomP2P*' }; if(!$items){Write-Host '[FAIL] No PhantomP2P IPv4 interface found.' -ForegroundColor Red; exit 1}; $items ^| Select-Object InterfaceAlias,IPAddress,PrefixLength,AddressState ^| Format-Table -AutoSize; exit 0"
if errorlevel 1 goto :failed

echo.
echo [2/3] Checking route to !PHANTOM_TEST_HOST_IP!...
powershell.exe -NoLogo -NoProfile -NonInteractive -Command ^
  "$route=Find-NetRoute -RemoteIPAddress $env:PHANTOM_TEST_HOST_IP -ErrorAction SilentlyContinue; if(!$route){Write-Host '[FAIL] No route to the Host virtual IP.' -ForegroundColor Red; exit 1}; $route ^| Select-Object IPAddress,InterfaceAlias,DestinationPrefix,NextHop,RouteMetric ^| Format-Table -AutoSize; if($route.InterfaceAlias -notlike 'PhantomP2P*'){Write-Host '[FAIL] Route does not use a PhantomP2P adapter.' -ForegroundColor Red; exit 1}; exit 0"
if errorlevel 1 goto :failed

echo.
echo [3/3] Running 3 TCP connection attempts...
powershell.exe -NoLogo -NoProfile -NonInteractive -Command ^
  "$hostIp=$env:PHANTOM_TEST_HOST_IP; $port=[int]$env:PHANTOM_TEST_PORT; $success=0; 1..3 ^| ForEach-Object { $client=[Net.Sockets.TcpClient]::new(); try { $async=$client.BeginConnect($hostIp,$port,$null,$null); if(!$async.AsyncWaitHandle.WaitOne(3000)){throw 'timeout'}; $client.EndConnect($async); $success++; Write-Host ('[OK] Attempt '+$_+': connected, local endpoint '+$client.Client.LocalEndPoint) -ForegroundColor Green } catch { Write-Host ('[FAIL] Attempt '+$_+': '+$_.Exception.Message) -ForegroundColor Red } finally { $client.Dispose() }; Start-Sleep -Milliseconds 300 }; if($success -eq 0){exit 1}; exit 0"
if errorlevel 1 (
  echo.
  echo [FAIL] The Host TCP port is unreachable through the overlay.
  echo Check Host TUN IP, service listener, firewall rule, and tunnel traffic.
  goto :failed
)

echo.
echo ============================================================
echo GUEST TEST PASSED: !PHANTOM_TEST_HOST_IP!:!PHANTOM_TEST_PORT!
echo The virtual network and TCP path are working end to end.
echo ============================================================
goto :success

:validate_inputs
powershell.exe -NoLogo -NoProfile -NonInteractive -Command ^
  "try { $rawIp=($env:PHANTOM_TEST_HOST_IP).Trim(); $ip=[ipaddress]$rawIp; if($ip.AddressFamily.ToString() -ne 'InterNetwork'){throw ('IPv4 required, received: '+$rawIp)}; $rawPort=($env:PHANTOM_TEST_PORT).Trim(); $port=[int]$rawPort; if($port -lt 1 -or $port -gt 65535){throw ('port must be 1-65535, received: '+$rawPort)}; exit 0 } catch { Write-Host ('[FAIL] Invalid input: '+$_.Exception.Message) -ForegroundColor Red; exit 1 }"
exit /b %errorlevel%

:failed
echo.
echo Test failed. Review the messages above.
pause
exit /b 1

:success
echo.
pause
exit /b 0

:end
echo.
echo Test finished.
endlocal
exit /b 0
