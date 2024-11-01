# Windows Security Hardening Script

# Ensure script is run with administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run this script as an Administrator!"
    Exit 1
}

## Enable Windows Defender
Write-Host "Configuring Windows Defender..."
Set-MpPreference -CheckForSignaturesBeforeRunningScan $true
Set-MpPreference -CloudBlockLevel "High"
Set-MpPreference -CloudExtendedTimeout 50
Set-MpPreference -DisableArchiveScanning $false
Set-MpPreference -DisableArchiveScanningAlternateDataStream $false
Set-MpPreference -DisableBehaviorMonitoring $false
Set-MpPreference -DisableBehaviorMonitoringAlternateDataStream $false
Set-MpPreference -DisableBehaviorMonitoringMemoryDoubleFree $false
Set-MpPreference -DisableBehaviorMonitoringNonMsSigned $false
Set-MpPreference -DisableBehaviorMonitoringNonMsSystem $false
Set-MpPreference -DisableBehaviorMonitoringNonMsSystemProtected $false
Set-MpPreference -DisableBehaviorMonitoringNonSystemSigned $false
Set-MpPreference -DisableBehaviorMonitoringPowershellScripts $false
Set-MpPreference -DisableBehaviorMonitoringUnsigned $false
Set-MpPreference -DisableBlockAtFirstSeen $false
Set-MpPreference -DisableDnsParsing $false
Set-MpPreference -DisableDnsOverTcpParsing $false
Set-MpPreference -DisableEmailScanning $false
Set-MpPreference -DisableIntrusionPreventionSystem $false
Set-MpPreference -DisableIOAVProtection $false
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -DisableRemovableDriveScanning $false
Set-MpPreference -DisableScriptScanning $false
Set-MpPreference -DisableSshParsing $false
Set-MpPreference -EnableControlledFolderAccess Enabled
Set-MpPreference -EnableControlledFolderAccessMemoryProtection $true
Set-MpPreference -EnableControlledFolderAccessNonMsSigned $true
Set-MpPreference -EnableControlledFolderAccessNonMsSystem $true
Set-MpPreference -EnableControlledFolderAccessNonMsSystemProtected $true
Set-MpPreference -EnableControlledFolderAccessNonScriptableDlls $true
Set-MpPreference -EnableDnsSinkhole $true
Set-MpPreference -EnableFileHashComputation $true
Set-MpPreference -EnableNetworkProtection Enabled
Set-MpPreference -EnableNetworkProtectionControlledFolderAccessInspection $true
Set-MpPreference -EnableNetworkProtectionExploitInspection $true
Set-MpPreference -EnableNetworkProtectionRealtimeInspection $true
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -MP_FORCE_USE_SANDBOX 1
Set-MpPreference -PUAProtection 1
Set-MpPreference -ScanArchiveFilesWithPassword $true
Set-MpPreference -ScanDownloads 2
Set-MpPreference -ScanIncomingMail 2
Set-MpPreference -ScanMappedNetworkDrivesDuringFullScan $true
Set-MpPreference -ScanMappedNetworkDrivesDuringQuickScan $true
Set-MpPreference -ScanNetworkFiles 2
Set-MpPreference -ScanNetworkFilesDuringFullScan $true
Set-MpPreference -ScanNetworkFilesDuringQuickScan $true
Set-MpPreference -ScanRemovableDriveDuringFullScan $true
Set-MpPreference -ScanRemovableDrivesDuringFullScan $true
Set-MpPreference -ScanRemovableDrivesDuringQuickScan $true
Set-MpPreference -ScanScriptsLoadedInInternetExplorer $true
Set-MpPreference -ScanScriptsLoadedInOfficeApplications $true
Set-MpPreference -ScanSubDirectoriesDuringQuickScan $true
Set-MpPreference -SignatureDisableUpdateOnStartupWithoutEngine $false
Set-MpPreference -SubmitSamplesConsent Always

## Set PowerShell Execution Policy
Write-Host "Setting PowerShell Execution Policy to RemoteSigned..."
Set-ExecutionPolicy RemoteSigned -Force

## Enable Windows Firewall
Write-Host "Enabling Windows Firewall..."
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

## Disable SMBv1
Write-Host "Disabling SMBv1..."
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

## Enable User Account Control (UAC)
Write-Host "Enabling User Account Control..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 1

## Enable BitLocker (if supported)
Write-Host "Checking BitLocker support..."
if (Get-Command "Enable-BitLocker" -ErrorAction SilentlyContinue) {
    $systemDrive = $env:SystemDrive
    if (-not (Get-BitLockerVolume -MountPoint $systemDrive).ProtectionStatus) {
        Write-Host "Enabling BitLocker on system drive..."
        Enable-BitLocker -MountPoint $systemDrive -EncryptionMethod Aes256 -UsedSpaceOnly -SkipHardwareTest
    } else {
        Write-Host "BitLocker is already enabled on system drive."
    }
} else {
    Write-Host "BitLocker is not available on this system."
}

## Disable Guest account
Write-Host "Disabling Guest account..."
Disable-LocalUser -Name "Guest"

## Enable automatic Windows updates
Write-Host "Enabling automatic Windows updates..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -Name "AUOptions" -Value 4

Write-Host "Security hardening complete. Make sure to restart system!"
