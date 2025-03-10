# Elevate to Admin
$AdminCheck = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $AdminCheck.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Requesting administrator privileges..."
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Enable TLS for downloads
Write-Host "Enabling TLS for secure downloads..."
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Ensure the user is an Administrator
$CurrentUser = $env:UserName
Write-Host "Adding $CurrentUser to Administrators group..."
Add-LocalGroupMember -Group "Administrators" -Member "$CurrentUser"

# Prompt for SharePoint Site Name
$CompanyName = Read-Host "Enter your company name"
$SharePointLibrary = "https://$CompanyName.sharepoint.com/sites/$CompanyNameDrive"

Write-Host "Using SharePoint Library: $SharePointLibrary"

# Disable Windows Telemetry & Tracking
Write-Host "Disabling Windows telemetry and data collection..."
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v EnableConfigFlighting /t REG_DWORD /d 0 /f

Write-Host "Disabling Windows tracking services..."
Stop-Service "DiagTrack" -Force
Set-Service "DiagTrack" -StartupType Disabled
Stop-Service "dmwappushservice" -Force
Set-Service "dmwappushservice" -StartupType Disabled

# Install 1Password
Write-Host "Installing 1Password..."
winget install -e --id AgileBits.1Password

# Install Microsoft 365
Write-Host "Installing Microsoft 365..."
winget install -e --id Microsoft.Office

# Install Microsoft Teams
Write-Host "Installing Microsoft Teams..."
winget install -e --id Microsoft.Teams

# Install Microsoft Edge
Write-Host "Installing Microsoft Edge..."
winget install -e --id Microsoft.Edge

# Install Adobe Creative Cloud
Write-Host "Installing Adobe Creative Cloud..."
winget install -e --id Adobe.AdobeCreativeCloud

# Install OneDrive and Configure Auto-Sync
Write-Host "Ensuring OneDrive is installed..."
Start-Process -FilePath "C:\Windows\SysWOW64\OneDriveSetup.exe" -Wait

# Configure OneDrive Auto-Sync for User Files (Desktop, Documents, Pictures)
Write-Host "Configuring OneDrive to restore user files..."
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager" /v EnableAutoConfig /t REG_DWORD /d 1 /f

# Sync SharePoint Document Library
Write-Host "Configuring OneDrive to auto-sync SharePoint Library..."
Start-Process "C:\Program Files\Microsoft OneDrive\OneDrive.exe" -ArgumentList "/url $SharePointLibrary /silent"

Write-Host "OneDrive is now syncing the SharePoint Library!"

# Set Microsoft Edge as Default Browser
Write-Host "Setting Microsoft Edge as the default browser..."
$EdgeAssociations = @"
<?xml version="1.0" encoding="UTF-8"?>
<DefaultAssociations>
    <Association Identifier=".htm" ProgId="MSEdgeHTM" ApplicationName="Microsoft Edge" />
    <Association Identifier=".html" ProgId="MSEdgeHTM" ApplicationName="Microsoft Edge" />
    <Association Identifier=".pdf" ProgId="MSEdgePDF" ApplicationName="Microsoft Edge" />
    <Association Identifier="http" ProgId="MSEdgeHTM" ApplicationName="Microsoft Edge" />
    <Association Identifier="https" ProgId="MSEdgeHTM" ApplicationName="Microsoft Edge" />
</DefaultAssociations>
"@
$EdgeAssociations | Out-File "$env:TEMP\EdgeAssociations.xml"
Dism /Online /Import-DefaultAppAssociations:$env:TEMP\EdgeAssociations.xml

# Enable Windows Hello PIN and YubiKey Login
Write-Host "Enabling Windows Hello PIN and YubiKey Login..."
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\FIDO" /v EnableFIDODeviceLogon /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableWebSignIn /t REG_DWORD /d 1 /f

# Configure Edge to Use YubiKey for Microsoft 365 Login
Write-Host "Configuring Edge to auto-login with YubiKey..."
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v BrowserSignin /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v EnableWebAuthn /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v SyncDisabled /t REG_DWORD /d 0 /f

# Enable Microsoft Teams Auto Login
Write-Host "Configuring Microsoft Teams auto sign-in..."
reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\Teams" /v AutoLoginEnabled /t REG_DWORD /d 1 /f

# Set Outlook as the Default Email Client
Write-Host "Setting Outlook as the default email client..."
reg add "HKEY_CLASSES_ROOT\mailto\shell\open\command" /ve /t REG_SZ /d "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE\" -c IPM.Note /m \"%1\"" /f

# Auto-Configure Outlook for Corporate Account
Write-Host "Configuring Outlook for automatic login..."
reg add "HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Outlook\AutoDiscover" /v ZeroConfigExchange /t REG_DWORD /d 1 /f

# Prompt User to Enroll YubiKey and Windows Hello
Write-Host "Prompting user to enroll YubiKey or Windows Hello..."
Start-Process "ms-settings:signinoptions"

# Prompt User to Sign In to Microsoft 365
Write-Host "Prompting user to sign into Microsoft 365 work account..."
Start-Process "ms-settings:emailandaccounts"

Write-Host "Setup Complete! Please restart your computer."