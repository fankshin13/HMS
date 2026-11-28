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

set "SCRIPT_VERSION=1.1.0"
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
  %PS% "Get-Content -Path $env:SECCFG | Select-String -Pattern '^(PasswordComplexity|ClearTextPassword|MinimumPasswordLength|MaximumPasswordAge|MinimumPasswordAge|PasswordHistorySize|LockoutBadCount|ResetLockoutCount|LockoutDuration|NewAdministratorName|NewGuestName|EnableGuestAccount|LSAAnonymousNameLookup|SeRemoteShutdownPrivilege|SeNetworkLogonRight|SeRemoteInteractiveLogonRight|MACHINE\\System\\CurrentControlSet\\Control\\Lsa\\(RestrictAnonymous|RestrictAnonymousSAM|LimitBlankPasswordUse|EveryoneIncludesAnonymous|NoLMHash|CrashOnAuditFail)|MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\(DontDisplayLastUserName|LegalNoticeCaption|LegalNoticeText|InactivityTimeoutSecs|ShutdownWithoutLogon)|MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\AllocateDASD)\b' | ForEach-Object { $_.Line }"
  del /q "%SECCFG%" >nul 2>&1
) else (
  echo NOT_AVAILABLE=secedit export failed
)
echo ==== WIN-SECURITY_POLICY END ====
echo.

echo ==== WIN-SERVICES BEGIN ====
%PS% "Get-Service -Name TlntSvr,FTPSVC,MSFTPSVC,SNMP,RemoteRegistry,W3SVC,SharedAccess,Spooler,DNS,Alerter,ClipSrv,Browser,TrkWks,TrkSvr,HidServ,ImapiService,Irmon,Messenger,mnmsrvc,WmdmPmSN,simptcp,upnphost,WZCSVC,WerSvc -ErrorAction SilentlyContinue | ForEach-Object { 'SERVICE=' + $_.Name + ' STATUS=' + $_.Status + ' START=' + $_.StartType }"
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

echo ==== WIN-ACCOUNTS BEGIN ====
REM Days since last logon ("never" = no logon yet) and members of the Administrators group (SID S-1-5-32-544)
%PS% "Get-LocalUser | ForEach-Object { $d = if ($_.LastLogon) { [int]((Get-Date) - $_.LastLogon).TotalDays } else { 'never' }; 'ACCOUNT=' + ($_.Name -replace '\s','_') + ' ENABLED=' + $_.Enabled + ' RID=' + $_.SID.Value.Split('-')[-1] + ' LAST_LOGON_DAYS=' + $d }"
echo $ Get-LocalGroupMember -SID S-1-5-32-544
%PS% "try { Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { 'ADMIN_MEMBER=' + ($_.Name -replace '\s','_') + ' CLASS=' + $_.ObjectClass + ' SOURCE=' + $_.PrincipalSource } } catch { 'ADMIN_MEMBER_ERROR=' + $_.Exception.GetType().Name }"
echo ==== WIN-ACCOUNTS END ====
echo.

echo ==== WIN-REGISTRY BEGIN ====
REM Selected registry values (NOT_SET = value does not exist). HKCU is the profile of the account running this script.
%PS% "function R($l,$p,$n) { $v = (Get-ItemProperty -Path $p -Name $n -ErrorAction SilentlyContinue).$n; if ($null -eq $v) { $v = 'NOT_SET' }; $l + '=' + $v }; R 'ForceKeyProtection' 'HKLM:\SOFTWARE\Policies\Microsoft\Cryptography' 'ForceKeyProtection'; R 'ScreenSaveActive' 'HKCU:\Control Panel\Desktop' 'ScreenSaveActive'; R 'ScreenSaverIsSecure' 'HKCU:\Control Panel\Desktop' 'ScreenSaverIsSecure'; R 'ScreenSaveTimeOut' 'HKCU:\Control Panel\Desktop' 'ScreenSaveTimeOut'; R 'PolicyScreenSaveActive' 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop' 'ScreenSaveActive'; R 'PolicyScreenSaverIsSecure' 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop' 'ScreenSaverIsSecure'; R 'PolicyScreenSaveTimeOut' 'HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop' 'ScreenSaveTimeOut'; R 'CurrentBuild' 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'CurrentBuild'; R 'UBR' 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'UBR'"
echo $ NetBIOS over TCP/IP (0 = DHCP default, 1 = enabled, 2 = disabled)
%PS% "Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { 'NETBIOS_ADAPTER=' + $_.Index + ' OPTION=' + $_.TcpipNetbiosOptions }"
echo ==== WIN-REGISTRY END ====
echo.

echo ==== WIN-SHARE_ACL BEGIN ====
echo $ Get-SmbShareAccess (non-default shares)
%PS% "Get-SmbShare -ErrorAction SilentlyContinue | Where-Object { -not $_.Special } | ForEach-Object { $s = $_.Name; Get-SmbShareAccess -Name $s -ErrorAction SilentlyContinue | ForEach-Object { 'SHARE=' + ($s -replace '\s','_') + ' ACCOUNT=' + ($_.AccountName -replace '\s','_') + ' RIGHT=' + $_.AccessRight + ' TYPE=' + $_.AccessControlType } }"
echo $ Get-Acl SAM
%PS% "(Get-Acl -Path (Join-Path $env:windir 'System32\config\SAM')).Access | ForEach-Object { 'SAM_ACE=' + ($_.IdentityReference.Value -replace '\s','_') + ' RIGHTS=' + ($_.FileSystemRights -replace '[\s,]','') + ' TYPE=' + $_.AccessControlType }"
echo ==== WIN-SHARE_ACL END ====
echo.

echo ==== WIN-IIS_FTP BEGIN ====
echo $ IIS FTP sites
%PS% "try { Import-Module WebAdministration -ErrorAction Stop; Get-ChildItem IIS:\Sites | Where-Object { $_.bindings.Collection.protocol -contains 'ftp' } | ForEach-Object { $n = $_.name; $sec = $_.ftpServer.security; $path = [Environment]::ExpandEnvironmentVariables($_.physicalPath); $every = [bool]((Get-Acl -Path $path -ErrorAction SilentlyContinue).Access | Where-Object { $_.IdentityReference.Value -match 'Everyone' }); $allow = (Get-WebConfigurationProperty -PSPath 'IIS:\' -Location $n -Filter 'system.ftpServer/security/ipSecurity' -Name allowUnlisted -ErrorAction SilentlyContinue).Value; 'FTP_SITE=' + ($n -replace '\s','_') + ' SSL_CONTROL=' + $sec.ssl.controlChannelPolicy + ' SSL_DATA=' + $sec.ssl.dataChannelPolicy + ' ANONYMOUS=' + $sec.authentication.anonymousAuthentication.enabled + ' EVERYONE=' + $every + ' ALLOW_UNLISTED=' + $allow } } catch { 'IIS_MODULE=unavailable' }"
echo $ MSADC virtual directory
%PS% "try { Import-Module WebAdministration -ErrorAction Stop; 'MSADC_VDIR=' + [bool](Get-WebVirtualDirectory -Site 'Default Web Site' -Name 'MSADC' -ErrorAction SilentlyContinue) } catch { 'MSADC_VDIR=unknown' }"
echo ==== WIN-IIS_FTP END ====
echo.

echo ==== WIN-DNS BEGIN ====
echo $ Get-DnsServerZone (0 = any server, 1 = name servers, 2 = listed servers, 3 = no transfer)
%PS% "try { Get-DnsServerZone -ErrorAction Stop | Where-Object { -not $_.IsAutoCreated -and $_.ZoneType -eq 'Primary' } | ForEach-Object { 'DNS_ZONE_TRANSFER=' + [int]$_.SecureSecondaries } } catch { 'DNS_ZONES=unavailable' }"
echo ==== WIN-DNS END ====
echo.

echo ==== WIN-PATCH_AV BEGIN ====
%PS% "$h = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1; if ($h) { 'LAST_HOTFIX=' + $h.HotFixID + ' DAYS_AGO=' + [int]((Get-Date) - $h.InstalledOn).TotalDays } else { 'LAST_HOTFIX=none' }"
%PS% "Get-MpComputerStatus -ErrorAction SilentlyContinue | ForEach-Object { 'DefenderAntivirusEnabled=' + $_.AntivirusEnabled; 'DefenderSignatureAge=' + $_.AntivirusSignatureAge }"
echo $ antivirus services
%PS% "Get-CimInstance Win32_Service | Where-Object { $_.DisplayName -match 'AhnLab|V3 |ALYac|Symantec|McAfee|Trellix|Trend Micro|Kaspersky|ESET|Sophos|CrowdStrike|SentinelOne|Bitdefender' } | ForEach-Object { 'AV_SERVICE=' + ($_.Name -replace '\s','_') + ' STATE=' + $_.State }"
echo ==== WIN-PATCH_AV END ====
echo.

echo [END]
exit /b 0
