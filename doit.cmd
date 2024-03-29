@echo off

:: Prepare
echo Preparing...
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: run this file as admin
    goto eof
)
mkdir %windir%\AcaplaStd
icacls %windir%\AcaplaStd /grant *S-1-1-0:F
set psexec=%~dp0bin\psexec.exe -accepteula -nobanner -i -s
set iwt=%~dp0install_wim_tweak.exe /o /r /c
powershell -command "Set-ExecutionPolicy Unrestricted" > nul

:: Functions
goto start
:disable_svc
sc stop %~1
sc config %~1 start= disabled
exit /b 0

:disable_svc_sudo
%psexec% cmd.exe /c sc config %~1 start= disabled ^& sc stop %~1
exit /b 0

:disable_svc_lite
sc stop %~1
sc config %~1 start= demand
exit /b 0

:disable_svc_sudo_lite
%psexec% cmd.exe /c sc config %~1 start= demand ^& sc stop %~1
exit /b 0

:disable_svc_rand
for /f "tokens=5 delims=\" %%a in ('reg query HKLM\SYSTEM\CurrentControlSet\Services /k /f %~1_') do (
    sc stop %%a
    reg add "HKLM\SYSTEM\CurrentControlSet\Services\%%a" /v "Start" /t REG_DWORD /d 3 /f
)
call :disable_svc_lite %~1
exit /b 0

:disable_svc_hard
%psexec% sc stop %~1
powershell -command "Import-Module -DisableNameChecking "%~dp0\takeown.psm1"; Takeown-Registry(\"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\%~1\"); Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\%~1" "Start" 4"
exit /b 0

:rm_uwp
powershell -command "Get-AppxPackage *%~1* | Remove-AppxPackage -allusers"
exit /b 0
:start

echo.
echo ---------------------------------------------
echo --------------------Common-------------------
echo ---------------------------------------------
echo.

:: Update
set conf=Y
set /p "conf= Disable windows update? [Y/n] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto endupdate
echo Disabling windows update...
call :disable_svc_lite wuauserv
call :disable_svc_sudo_lite UsoSvc
call :disable_svc_sudo WaaSMedicSvc
%psexec% cmd.exe /c schtasks /change /disable /tn \Microsoft\Windows\WaaSMedic\PerformRemediation ^& schtasks /change /disable /tn \Microsoft\Windows\WindowsUpdate\sihpostreboot ^& schtasks /change /disable /tn "\Microsoft\Windows\WindowsUpdate\Scheduled Start"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUOptions" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "DetectionFrequencyEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownLoadMode" /t REG_DWORD /d 100 /f
:endupdate

:: OneDrive
set conf=Y
set /p "conf= Remove onedrive? [Y/n] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto enddrive
%SystemRoot%\SysWOW64\OneDriveSetup.exe /Uninstall
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f
rd "%UserProfile%\OneDrive" /Q /S
rd "%LocalAppData%\Microsoft\OneDrive" /Q /S
rd "%ProgramData%\Microsoft OneDrive" /Q /S
rd "C:\OneDriveTemp" /Q /S
reg add "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 1 /f
reg add "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /v System.IsPinnedToNameSpaceTree /t REG_DWORD /d 1 /f
:enddrive

:: Telemetry
set conf=Y
set /p "conf= Disable telemetry, diagnostics, crash reporting, feedback, mobile devices services? [Y/n] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto endtel
echo Disabling telemetry...
taskkill /f /im explorer.exe
schtasks /change /disable /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
schtasks /change /disable /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
schtasks /change /disable /tn "\Microsoft\Windows\Application Experience\StartupAppTask"
schtasks /change /disable /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
schtasks /change /disable /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
schtasks /change /disable /tn "\Microsoft\Windows\Autochk\Proxy"
schtasks /change /disable /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo"
schtasks /change /disable /tn "\Microsoft\Windows\LanguageComponentsInstaller\Installation"
schtasks /change /disable /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
schtasks /change /disable /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"
schtasks /change /disable /tn "\Microsoft\Windows\Shell\FamilySafetyMonitor"
schtasks /change /disable /tn "\Microsoft\Windows\Shell\FamilySafetyRefreshTask"
schtasks /change /disable /tn "\Microsoft\Windows\Feedback\Siuf\DmClient"
schtasks /change /disable /tn "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload"
schtasks /change /disable /tn "\Microsoft\Windows\PI\Sqm-Tasks"
schtasks /change /disable /tn "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser"
schtasks /change /disable /tn "\Microsoft\Windows\WDI\ResolutionHost"
schtasks /change /disable /tn "\Microsoft\Windows\Device Information\Device"
schtasks /change /disable /tn "\Microsoft\Windows\DUSM\dusmtask"
schtasks /change /disable /tn "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
schtasks /change /disable /tn "\Microsoft\Windows\Flighting\OneSettings\RefreshCache"
schtasks /change /disable /tn "\Microsoft\Windows\SettingSync\BackgroundUpLoadTask"
schtasks /change /disable /tn "\Microsoft\Windows\SettingSync\NetworkStateChangeTask"
schtasks /change /disable /tn "\Microsoft\Windows\Device Setup\Metadata Refresh"
schtasks /change /disable /tn "\Microsoft\Windows\DeviceDirectoryClient\HandleCommand"
schtasks /change /disable /tn "\Microsoft\Windows\DeviceDirectoryClient\HandleWnsCommand"
schtasks /change /disable /tn "\Microsoft\Windows\DeviceDirectoryClient\IntegrityCheck"
schtasks /change /disable /tn "\Microsoft\Windows\DeviceDirectoryClient\LocateCommandUserSession"
schtasks /change /disable /tn "\Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceAccountChange"
schtasks /change /disable /tn "\Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceLocationRightsChange"
schtasks /change /disable /tn "\Microsoft\Windows\DeviceDirectoryClient\RegisterDevicePeriodic24"
schtasks /change /disable /tn "\Microsoft\Windows\DeviceDirectoryClient\RegisterDevicePolicyChange"
schtasks /change /disable /tn "\Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceProtectionStateChanged"
schtasks /change /disable /tn "\Microsoft\Windows\DeviceDirectoryClient\RegisterDeviceSettingChange"
schtasks /change /disable /tn "\Microsoft\Windows\DeviceDirectoryClient\RegisterUserDevice"
schtasks /change /disable /tn "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"
schtasks /change /disable /tn "\Microsoft\Windows\ApplicationData\appuriverifierdaily"
schtasks /change /disable /tn "\Microsoft\Windows\ApplicationData\appuriverifierinstall"
schtasks /change /disable /tn "\Microsoft\Windows\License Manager\TempSignedLicenseExchange"
auditpol /set /subcategory:"{0CCE9226-69AE-11D9-BED3-505054503030}" /success:disable /failure:disable
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "WakeUp" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "WakeUp" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AllowUntriggeredNetworkTrafficOnSettingsPage" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg delete "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "StudyId" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowTelemetry" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" /v "DisableWerReporting" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\TraceManager" /v "MiniTraceSlotEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Input\Settings" /v "InsightsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Input\Settings" /v "InsightsEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatformTel" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "NoTileApplicationNotification" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310091Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310092Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338380Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338381Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing" /v "DisableWerReporting" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting" /v "DoReport" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "BypassDataThrottling" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "BypassDataThrottling" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{C295FBBA-FD47-46ac-8BEE-B1715EC634E5}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{C295FBBA-FD47-46ac-8BEE-B1715EC634E5}" /v "DownloadToolsEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "DisableQueryRemoteServer" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\PerfTrack" /v "Disabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "Disabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "DisableAutomaticTelemetryKeywordReporting" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "TelemetryServiceDisabled" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\TestHooks" /v "DisableAsimovUpLoad" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Troubleshooter" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Inventory" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Telemetry" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Steps-Recorder" /v "Enabled" /t REG_DWORD /d 0 /f
call :disable_svc DiagTrack
call :disable_svc dmwappushservice
call :disable_svc diagnosticshub.standardcollector.service
start explorer.exe
:endtel

:: Defender
set conf=Y
set /p "conf= Disable windows defender, firewall and smartscreen? [Y/n] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto enddefender
echo Disabling windows defender and smartscreen...
%psexec% regedit /s %~dp0defender.reg
netsh advfirewall set allprofiles state off
call :disable_svc_hard WinDefend
call :disable_svc_hard WdNisSvc
call :disable_svc_hard Sense
call :disable_svc_hard SecurityHealthService
::call :disable_svc_hard wscsvc
echo ---------------------------
echo ---- Ignore any errors ----
echo ---------------------------
taskkill /f /im SecurityHealthSystray.exe
reg add "HKLM\SOFTWARE\Microsoft\Security Center" /v "AntiVirusDisableNotify" /t REG_DWORD /d 1 /f
%psexec% reg add "HKLM\SOFTWARE\Microsoft\Security Center\Svc" /v "AntiVirusOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Security Center" /v "FirewallDisableNotify" /t REG_DWORD /d 1 /f
%psexec% reg add "HKLM\SOFTWARE\Microsoft\Security Center\Svc" /v "FirewallOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Security Center" /v "AntiSpywareDisableNotify" /t REG_DWORD /d 1 /f
%psexec% reg add "HKLM\SOFTWARE\Microsoft\Security Center\Svc" /v "AntiSpywareOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Security Center" /v "UpdatesDisableNotify" /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg delete "HKLM\SOFTWARE\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}\InprocServer32" /v "" /f
echo Done!
:enddefender

:: Services
set conf=Y
set /p "conf= Disable useless services? [Y/n] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto endsvc
echo Disabling services...
call :disable_svc_rand OneSyncSvc
call :disable_svc_rand MessagingService
call :disable_svc_rand UserDataSvc
call :disable_svc_rand PimIndexMaintenanceSvc
call :disable_svc_rand CDPUserSvc
call :disable_svc_rand WpnUserService
call :disable_svc_rand WpnService
call :disable_svc_rand UnistoreSvc
call :disable_svc_rand cbdhsvc
call :disable_svc_lite MapsBroker
call :disable_svc_lite lfsvc
call :disable_svc_lite WMPNetworkSvc
call :disable_svc_lite WerSvc
call :disable_svc SSDPSRV
call :disable_svc_lite SCardSvr
call :disable_svc_lite SensorService
call :disable_svc_lite SensrSvc
call :disable_svc_hard WinHttpAutoProxySvc
call :disable_svc_lite DPS
call :disable_svc_sudo_lite DoSvc
call :disable_svc FDResPub
call :disable_svc_lite CDPSvc
call :disable_svc_lite RetailDemo
call :disable_svc_lite SensorDataService
call :disable_svc_lite DusmSvc
call :disable_svc_lite NcdAutoSetup
call :disable_svc SEMgrSvc
call :disable_svc_lite VaultSvc
call :disable_svc_lite StorSvc
call :disable_svc_lite WdiServiceHost
call :disable_svc_lite AppMgmt
call :disable_svc_lite fdPHost
call :disable_svc PolicyAgent
call :disable_svc IKEEXT
call :disable_svc WPDBusEnum
call :disable_svc_sudo NgcCtnrSvc
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "EnableLegacyBalloonNotifications" /t REG_DWORD /d 1 /f
echo ---------------------------
echo ---- Ignore any errors ----
echo ---------------------------
:endsvc

:: Print Services
set conf=Y
set /p "conf= Disable print and scan services? [Y/n] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto endprsvc
echo Disabling print and scan services...
call :disable_svc_rand PrintWorkflowUserSvc
call :disable_svc_sudo_lite PrintWorkflowUserSvc
call :disable_svc_lite Spooler
echo ---------------------------
echo ---- Ignore any errors ----
echo ---------------------------
:endprsvc

:: Print Services
set conf=Y
set /p "conf= Disable biometry services? [Y/n] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto endprsvc
echo Disabling biometry services...
call :disable_svc_lite WbioSrvc
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f
:endprsvc

:: Search
set conf=Y
set /p "conf= Disable search indexing? [Y/n] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto endsearch
echo Disabling search indexing...
sc config WSearch start= disabled
sc stop WSearch
%psexec% cmd.exe /c del /f /q C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb
echo Done!
:endsearch


echo.
echo ---------------------------------------------
echo -------------------UWP Apps------------------
echo ---------------------------------------------
echo.

:: Paint 3D
set conf=Y
set /p "conf= Remove Paint 3D, Print 3D and 3D viewer? [Y/n] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto endpaint
echo Removing Paint 3D and Print 3D...
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.3ds\Shell\3D Print" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.3mf\Shell\3D Edit" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.3mf\Shell\3D Print" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.bmp\Shell\3D Edit" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.dae\Shell\3D Print" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.dxf\Shell\3D Print" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.fbx\Shell\3D Edit" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.gif\Shell\3D Edit" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.glb\Shell\3D Edit" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.jfif\Shell\3D Edit" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.jpe\Shell\3D Edit" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.jpeg\Shell\3D Edit" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.jpg\Shell\3D Edit" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.obj\Shell\3D Edit" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.obj\Shell\3D Print" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.ply\Shell\3D Edit" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.ply\Shell\3D Print" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.png\Shell\3D Edit" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.stl\Shell\3D Edit" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.stl\Shell\3D Print" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.tif\Shell\3D Edit" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.tiff\Shell\3D Edit" /f
reg delete "HKLM\SOFTWARE\Classes\SystemFileAssociations\.wrl\Shell\3D Print" /f
call :rm_uwp Print3D
call :rm_uwp MSPaint
call :rm_uwp 3DViewer
echo Done!
:endpaint

:: Remove UWP 
set conf=Y
set /p "conf= Remove useless UWP Apps (Not all apps, see cmd file for details)? [Y/n] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto enduwp
echo Removing UWP Apps...
call :rm_uwp ZuneVideo
call :rm_uwp ZuneMusic
call :rm_uwp communicationsapps
call :rm_uwp Alarms
call :rm_uwp YourPhone
call :rm_uwp SoundRecorder
call :rm_uwp Maps
call :rm_uwp People
call :rm_uwp OneNote
call :rm_uwp MixedReality
call :rm_uwp OfficeHub
call :rm_uwp Messaging
call :rm_uwp Getstarted
call :rm_uwp GetHelp
call :rm_uwp BingWeather
call :rm_uwp ScreenSketch
call :rm_uwp Yandex.Music
call :rm_uwp DolbyAccess
call :rm_uwp FeedbackHub
call :rm_uwp OneConnect
call :rm_uwp SolitaireCollection
call :rm_uwp Photos
:: Not faced this app myself, but i think it's preinstalled adware
call :rm_uwp fitbit
:: Shitogames
call :rm_uwp king.com
echo ---------------------------
echo ---- Ignore any errors ----
echo ---------------------------
echo Done!
:enduwp

:: Remove Store
set conf=N
set /p "conf= Remove MSStore and related services? [y/N] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto endstore
echo Removing MSStore...
call :rm_uwp store
echo ---------------------------
echo ---- Ignore any errors ----
echo ---------------------------
echo Done!
:endstore

:: Remove Xbox
set conf=N
set /p "conf= Remove Xbox and related services? [y/N] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto endxbox
echo Removing Xbox...
call :rm_uwp xbox
echo ---------------------------
echo ---- Ignore any errors ----
echo ---------------------------
echo Done!
:endxbox

:: Remove UWP 2
set conf=N
set /p "conf= Remove skype, sticky notes and camera? [y/N] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto enduwp2
echo Removing UWP 2...
call :rm_uwp Camera
call :rm_uwp SkypeApp
call :rm_uwp StickyNotes
echo ---------------------------
echo ---- Ignore any errors ----
echo ---------------------------
echo Done!
:enduwp2

:: Remove UWP 2
set conf=N
set /p "conf= Remove calcualtor (You need to install other calculator)? [y/N] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto endcalc
echo Removing calcualtor...
call :rm_uwp Calculator
echo ---------------------------
echo ---- Ignore any errors ----
echo ---------------------------
echo Done!
:endcalc

:: Remove Edge
set conf=Y
set /p "conf= Remove Edge? [Y/n] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto endedge
%iwt% Microsoft-Windows-Internet-Browser-Package
echo Done! Restart your computer.
:endedge


echo.
echo ---------------------------------------------
echo ---------------Default settings--------------
echo ---------------------------------------------
echo.

:: Fix windows setings
set conf=Y
set /p "conf= Fix windows default settings (show hidden files, autorun delay, fast startup, etc.) and disable useless context menu entries (see cmd file for details)? [Y/n] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto endsettings
taskkill /f /im explorer.exe
reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoNewAppAlert" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /t REG_SZ /d "8192" /f
reg add "HKLM\SOFTWARE\Classes\Drive\shell\change-passphrase" /v "LegacyDisable" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Classes\Drive\shell\change-pin" /v "LegacyDisable" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Classes\Drive\shell\encrypt-bde-elev" /v "LegacyDisable" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Classes\Drive\shell\encrypt-bde" /v "LegacyDisable" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Classes\Drive\shell\manage-bde" /v "LegacyDisable" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Classes\Drive\shell\resume-bde-elev" /v "LegacyDisable" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Classes\Drive\shell\resume-bde" /v "LegacyDisable" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Classes\Drive\shell\unlock-bde" /v "LegacyDisable" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d 0 /f
reg add "HKCU\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d 100 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{1d27f844-3a1f-4410-85ac-14651078412d}" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{E2BF9676-5F8F-435C-97EB-11607A5BEDF7}" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "NoPreviousVersionsPage" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "HidePeopleBar" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "PersistBrowsers" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSecondsInSystemClock" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "ConfirmFileDelete" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" /v "FullPath" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Internet Explorer\Download" /v "CheckExeSignatures" /t REG_SZ /d "no" /f
reg add "HKCU\Software\Microsoft\Internet Explorer\Suggested Sites" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableThumbsDBOnNetworkFolders" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "UseOLEDTaskbarTransparency" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HideRecentlyAddedApps" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" /v "MinimizedStateTabletModeOff" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "DefaultFileTypeRisk" /t REG_DWORD /d 6152 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Associations" /v "LowRiskFileTypes" /t REG_SZ /d ".exe;.vbs;.msi;.bat;.cmd;.url;.com;.lnk;.chm;.hta;" /f
reg add "HKCR\batfile\shell\print" /v "ProgrammaticAccessOnly" /t REG_SZ /d "" /f
reg add "HKCR\cmdfile\shell\print" /v "ProgrammaticAccessOnly" /t REG_SZ /d "" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "AllItemsIconView" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "StartupPage" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\Shell\Bags\1\Desktop" /v "IconSize" /t REG_DWORD /d 32 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" /f
start explorer.exe
echo Done!
:endsettings

:: Meltdown Spectre
set conf=Y
set /p "conf= Disable Meltdown and Spectre fixes? [Y/n] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto endmeltdown
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 3 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d 3 /f
echo Done!
:endmeltdown


echo.
echo ---------------------------------------------
echo --------------------Apps---------------------
echo ---------------------------------------------
echo.

:: QTTabBar
set conf=Y
set /p "conf= Install QTTabBar? [Y/n] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto endqttabbar
if not exist "%~dp0apps\QTTabBar_1038.exe" goto qttabbarnotfound
if not exist "%~dp0apps\QTTabBar_Update_1040.exe" goto qttabbarnotfound
"%~dp0apps\QTTabBar_1038.exe" /I
"%~dp0apps\QTTabBar_Update_1040.exe" /I
taskkill /f /im explorer.exe
start explorer.exe
echo Done!
goto endqttabbar

:qttabbarnotfound
echo Sublime Text not found!
:endqttabbar

:: Sublime text
:subl
set conf=Y
set /p "conf= Replace notepad with sublime text (Not recommended to run multiple times)? [Y/n] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto endsubl
if not exist "%~dp0Sublime Text 3\sublime_text.exe" goto sublnotfound
if not exist "%~dp0Sublime Text 3\subl.exe" goto sublnotfound
if not exist "%~dp0Sublime Text 3\sublime_launcher.bat" goto sublnotfound

set conf=N
set /p "conf= Copy sublime text to system? [y/N] "
echo Replacing notepad with sublime text...
reg add "HKCR\*\shell\Open with Notepad" /v "" /t REG_SZ /d "Žâªàëâì ¢ Sublime Text" /f
reg add "HKCR\*\shell\Open with Notepad\command" /v "" /t REG_SZ /d "notepad.exe %1" /f
if "%conf%" neq "Y" if "%Conf%" neq "y" goto subl_nocopysys

mkdir "%windir%\AcaplaStd\Sublime Text 3"
xcopy "%~dp0Sublime Text 3" "%windir%\AcaplaStd\Sublime Text 3\" /h /e /c
setx /M PATH "%PATH%;%windir%\AcaplaStd\Sublime Text 3"
set PATH=%PATH%;%windir%\AcaplaStd\Sublime Text 3
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v "Debugger" /t REG_SZ /d "\"%windir%\AcaplaStd\Sublime Text 3\sublime_launcher.ps1\" -z" /f
echo Done!
goto endsubl

:subl_nocopysys
setx /M PATH "%PATH%;%~dp0Sublime Text 3"
set PATH=%PATH%;%~dp0Sublime Text 3
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe" /v "Debugger" /t REG_SZ /d "\"%~dp0Sublime Text 3\sublime_launcher.bat\" -z" /f
echo Done!
goto endsubl

:sublnotfound
echo Sublime Text not found!
:endsubl

:: Tools
set conf=Y
set /p "conf= Add tools to path (Not recommended to run multiple times)? [Y/n] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto endtools
set conf=N
set /p "conf= Copy tools to system? [y/N] "
echo Adding tools...
if "%conf%" neq "Y" if "%Conf%" neq "y" goto nocopysys

mkdir "%windir%\AcaplaStd\bin"
xcopy "%~dp0bin" "%windir%\AcaplaStd\bin\" /h /e /c
setx /M PATH "%PATH%;%windir%\AcaplaStd\bin"
set PATH=%PATH%;%windir%\AcaplaStd\bin
echo Done!
goto endtools

:nocopysys
echo "%PATH%;%~dp0bin"
setx /M PATH "%PATH%;%~dp0bin"
set PATH=%PATH%;%~dp0bin
echo Done!
:endtools


echo.
echo ---------------------------------------------
echo --------------------Other--------------------
echo ---------------------------------------------
echo.

:: .NET Framework 3.5
set conf=Y
set /p "conf= Install .NET Framework 2.0-3.5? [Y/n] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto endnet
echo Installing .NET Framework...
dism /online /enable-feature /featurename:NetFx3
echo Done!
:endnet

:: WSL
set conf=Y
set /p "conf= Install WSL? [Y/n] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto endwsl
echo Installing WSL...
dism /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /All /NoRestart
echo Done! Reboot your computer.
:endwsl

:: Hyper-V
set conf=N
set /p "conf= Install Hyper-V? [y/N] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto endhyperv
echo Installing Hyper-V...
dism /online /enable-feature /featurename:Microsoft-Hyper-V /All /NoRestart
echo Done! Reboot your computer.
:endhyperv

:: Hyper-V
set conf=Y
set /p "conf= Remove outdated drivers? [Y/n] "
if "%conf%" neq "Y" if "%Conf%" neq "y" goto enddrivers
echo Removing outdated drivers...
powershell -file "%~dp0Drivers.ps1"
echo Done!
:enddrivers

:eof
pause