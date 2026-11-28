@echo off
REM ============================================================================
REM  Vulnerability Assessment - Windows Server standard check script
REM  Target : Windows Server 2016 or later
REM  Basis  : KISA critical information infrastructure technical assessment (Windows server)
REM
REM  READ-ONLY: this script changes no settings. It only collects evidence and
REM  saves it to <COMPUTERNAME>_windows_<timestamp>.txt in the current folder.
REM  Password hashes and other secrets are never collected.
REM
REM  Run from an elevated (Administrator) command prompt:
REM      kisa_check_windows.bat
REM ============================================================================
setlocal EnableExtensions
chcp 65001 >nul

net session >nul 2>&1
if errorlevel 1 (
  echo Administrator privileges are required. Right-click and "Run as administrator".
  exit /b 1
)

set "SCRIPT_VERSION=1.0.0"
set "PS=powershell -NoProfile -ExecutionPolicy Bypass -Command [Console]::OutputEncoding=[Text.Encoding]::UTF8;"
for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyyMMddHHmmss"') do set "STAMP=%%i"
for /f %%i in ('powershell -NoProfile -Command "Get-Date -Format yyyy-MM-ddTHH:mm:sszzz"') do set "ISO_DATE=%%i"
set "OUT=%COMPUTERNAME%_windows_%STAMP%.txt"

call :collect > "%OUT%" 2>&1
echo Check finished. Result file: %CD%\%OUT%
echo Upload this file on the "New assessment" page of the web console.
exit /b 0

:collect
echo [START] OS=Windows HOSTNAME=%COMPUTERNAME% DATE=%ISO_DATE% SCRIPT=kisa_check_windows VERSION=%SCRIPT_VERSION%
%PS% "$o=Get-CimInstance Win32_OperatingSystem; '[INFO] DISTRO=' + $o.Caption + ' ' + $o.Version"
%PS% "Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -ne '127.0.0.1' } | ForEach-Object { '[INFO] IP=' + $_.IPAddress + '/' + $_.PrefixLength }"
echo.

echo ==== WIN-LOCAL_USERS BEGIN ====
REM Account names, enabled state and well-known RID (500 = built-in Administrator, 501 = Guest)
%PS% "Get-LocalUser | ForEach-Object { 'ACCOUNT=' + $_.Name + ' ENABLED=' + $_.Enabled + ' RID=' + $_.SID.Value.Split('-')[-1] + ' PASSWORD_LAST_SET=' + $_.PasswordLastSet + ' LAST_LOGON=' + $_.LastLogon }"
echo $ net localgroup Administrators
net localgroup Administrators
echo ==== WIN-LOCAL_USERS END ====
echo.

echo ==== WIN-ACCOUNT_POLICY BEGIN ====
echo $ net accounts
net accounts
echo ==== WIN-ACCOUNT_POLICY END ====
echo.

echo ==== WIN-SECURITY_POLICY BEGIN ====
REM Export local security policy to a temporary file, print selected keys, then delete it
set "SECCFG=%TEMP%\kisa_secpol_%STAMP%.inf"
secedit /export /cfg "%SECCFG%" /areas SECURITYPOLICY USER_RIGHTS >nul 2>&1
if exist "%SECCFG%" (
  %PS% "Get-Content -Path $env:SECCFG | Select-String -Pattern '^(PasswordComplexity|ClearTextPassword|MinimumPasswordLength|MaximumPasswordAge|MinimumPasswordAge|PasswordHistorySize|LockoutBadCount|ResetLockoutCount|LockoutDuration|NewAdministratorName|NewGuestName|EnableGuestAccount|LSAAnonymousNameLookup|SeRemoteShutdownPrivilege|SeNetworkLogonRight|SeRemoteInteractiveLogonRight|MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\(RestrictAnonymous|RestrictAnonymousSAM|LimitBlankPasswordUse|EveryoneIncludesAnonymous|NoLMHash)|MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\(DontDisplayLastUserName|LegalNoticeCaption|LegalNoticeText|InactivityTimeoutSecs))\b' | ForEach-Object { $_.Line }"
  del /q "%SECCFG%" >nul 2>&1
) else (
  echo NOT_AVAILABLE=secedit export failed
)
echo ==== WIN-SECURITY_POLICY END ====
echo.

echo ==== WIN-SERVICES BEGIN ====
%PS% "Get-Service -Name TlntSvr,FTPSVC,MSFTPSVC,SNMP,RemoteRegistry,W3SVC,SharedAccess,Spooler -ErrorAction SilentlyContinue | ForEach-Object { 'SERVICE=' + $_.Name + ' STATUS=' + $_.Status + ' START=' + $_.StartType }"
echo ==== WIN-SERVICES END ====
echo.

echo ==== WIN-SHARES BEGIN ====
echo $ net share
net share
%PS% "Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -ErrorAction SilentlyContinue | ForEach-Object { 'AutoShareServer=' + $_.AutoShareServer; 'AutoShareWks=' + $_.AutoShareWks }"
echo ==== WIN-SHARES END ====
echo.

echo ==== WIN-HOTFIX BEGIN ====
%PS% "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 | ForEach-Object { 'HOTFIX=' + $_.HotFixID + ' INSTALLED=' + $_.InstalledOn + ' DESC=' + $_.Description }"
echo ==== WIN-HOTFIX END ====
echo.

echo ==== WIN-AUDIT_POLICY BEGIN ====
echo $ auditpol /get /category:*
auditpol /get /category:*
echo ==== WIN-AUDIT_POLICY END ====
echo.

echo ==== WIN-EVENTLOG BEGIN ====
for %%L in (Security System Application) do (
  echo $ wevtutil gl %%L
  wevtutil gl %%L | findstr /i "name: maxSize: retention: autoBackup:"
)
echo ==== WIN-EVENTLOG END ====
echo.

echo ==== WIN-REMOTE_ACCESS BEGIN ====
%PS% "$ts=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue; 'fDenyTSConnections=' + $ts.fDenyTSConnections; $rdp=Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -ErrorAction SilentlyContinue; 'UserAuthentication=' + $rdp.UserAuthentication; 'MinEncryptionLevel=' + $rdp.MinEncryptionLevel; 'PortNumber=' + $rdp.PortNumber"
%PS% "$w=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -ErrorAction SilentlyContinue; 'AutoAdminLogon=' + $w.AutoAdminLogon"
echo ==== WIN-REMOTE_ACCESS END ====
echo.

echo ==== WIN-ANTIVIRUS BEGIN ====
%PS% "Get-MpComputerStatus -ErrorAction SilentlyContinue | ForEach-Object { 'AMServiceEnabled=' + $_.AMServiceEnabled; 'RealTimeProtectionEnabled=' + $_.RealTimeProtectionEnabled; 'AntivirusSignatureLastUpdated=' + $_.AntivirusSignatureLastUpdated }"
echo ==== WIN-ANTIVIRUS END ====
echo.

echo [END]
exit /b 0
