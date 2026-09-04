Param(
    [string] $AzureUserName,
    [string] $AzurePassword,
    [string] $AzureTenantID,
    [string] $AzureSubscriptionID,
    [string] $ODLID,
    [string] $InstallCloudLabsShadow,
    [string] $DeploymentID,
    [string] $vmAdminUsername,
    [string] $vmAdminPassword,
    [string] $trainerUserName,
    [string] $trainerUserPassword
)

# CSE has a 90-minute Windows hard limit. The Zava bootstrap installs Azure CLI, seeds a custom
# Log Analytics table, creates baseline Sentinel analytics rules, and waits for SecurityAlert
# evidence. On a slow tenant that combined work can approach 90 minutes and trip
# VMExtensionProvisioningTimeout. This launcher copies the real bootstrap to a durable path,
# registers a one-shot Scheduled Task running as SYSTEM to invoke it 30 seconds later, and
# exits success in seconds so CSE never times out. The task survives CSE cleanup and Job
# Object teardown, and seeding continues during the CloudLabs pre-provisioning window.

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$labRoot = 'C:\LabFiles'
$bootstrapRoot = Join-Path $labRoot 'bootstrap'
$logDir = 'C:\WindowsAzure\Logs'
New-Item -ItemType Directory -Path $labRoot, $bootstrapRoot, $logDir -Force | Out-Null

$launcherLog = Join-Path $logDir 'ZavaBootstrapLauncher.log'
function Write-LauncherLog {
    param([string]$Message)
    $line = "[$((Get-Date).ToUniversalTime().ToString('s'))Z] $Message"
    Add-Content -Path $launcherLog -Value $line -Encoding UTF8
    Write-Host $line
}

try {
    Write-LauncherLog "Launcher started. PSScriptRoot=$PSScriptRoot"

    $sourceScript = Join-Path $PSScriptRoot 'psscript-01.ps1'
    if (-not (Test-Path $sourceScript)) {
        $candidate = Get-ChildItem -Path $PSScriptRoot -Recurse -Filter 'psscript-01.ps1' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($candidate) { $sourceScript = $candidate.FullName }
    }
    if (-not (Test-Path $sourceScript)) {
        throw "psscript-01.ps1 not found next to launcher at $PSScriptRoot."
    }

    $targetScript = Join-Path $bootstrapRoot 'psscript-01.ps1'
    Copy-Item -Path $sourceScript -Destination $targetScript -Force
    Write-LauncherLog "Copied bootstrap to $targetScript."

    $argsFile = Join-Path $bootstrapRoot 'bootstrap-args.psd1'
    $encoded = @{
        AzureUserName        = $AzureUserName
        AzurePassword        = $AzurePassword
        AzureTenantID        = $AzureTenantID
        AzureSubscriptionID  = $AzureSubscriptionID
        ODLID                = $ODLID
        InstallCloudLabsShadow = $InstallCloudLabsShadow
        DeploymentID         = $DeploymentID
        vmAdminUsername      = $vmAdminUsername
        vmAdminPassword      = $vmAdminPassword
        trainerUserName      = $trainerUserName
        trainerUserPassword  = $trainerUserPassword
    }
    $psdLines = @('@{')
    foreach ($key in $encoded.Keys) {
        $value = [string]$encoded[$key]
        $escaped = $value.Replace("'", "''")
        $psdLines += "  $key = '$escaped'"
    }
    $psdLines += '}'
    [System.IO.File]::WriteAllText($argsFile, ($psdLines -join "`r`n"), (New-Object System.Text.UTF8Encoding $false))
    Write-LauncherLog "Wrote bootstrap args to $argsFile."

    $runnerPath = Join-Path $bootstrapRoot 'run-bootstrap.ps1'
    $runnerBody = @"
`$ErrorActionPreference = 'Continue'
`$argsPath = '$argsFile'
`$scriptPath = '$targetScript'
try {
    `$params = Import-PowerShellDataFile -Path `$argsPath
    & `$scriptPath @params
}
catch {
    `$msg = "Background bootstrap failed: `$(`$_.Exception.Message)"
    Add-Content -Path 'C:\WindowsAzure\Logs\ZavaBootstrapLauncher.log' -Value `$msg -Encoding UTF8
    Set-Content -Path 'C:\LabFiles\bootstrap-failure.txt' -Value `$msg -Encoding UTF8
}
finally {
    try { Unregister-ScheduledTask -TaskName 'ZavaSocBootstrap' -Confirm:`$false -ErrorAction SilentlyContinue } catch {}
}
"@
    Set-Content -Path $runnerPath -Value $runnerBody -Encoding UTF8
    Write-LauncherLog "Wrote runner at $runnerPath."

    # A Scheduled Task running as SYSTEM survives CSE cleanup and Job Object teardown.
    $taskName = 'ZavaSocBootstrap'
    try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-ExecutionPolicy Unrestricted -WindowStyle Hidden -NoProfile -File `"$runnerPath`"" -WorkingDirectory $bootstrapRoot
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(30)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::FromHours(4))
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Write-LauncherLog "Registered scheduled task '$taskName' to launch bootstrap in 30 seconds. CSE will return success now; bootstrap continues detached."
}
catch {
    Write-LauncherLog "Launcher error (CSE will still exit success to avoid throwing the environment away): $($_.Exception.Message)"
    Set-Content -Path (Join-Path $labRoot 'bootstrap-launcher-failure.txt') -Value $_.Exception.Message -Encoding UTF8
}

exit 0
