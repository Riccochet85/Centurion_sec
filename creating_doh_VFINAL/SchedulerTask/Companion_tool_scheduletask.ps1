<#
.SYNOPSIS
    Creates a Windows Scheduled Task to run a PowerShell script daily.
.DESCRIPTION
    This script registers a scheduled task that runs a specified PowerShell script
    at a given time every day. Includes validation and error handling.
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$ScriptPath,   # Full path to the PowerShell script to run

    [Parameter(Mandatory = $true)]
    [string]$TaskName,     # Name of the scheduled task

    [Parameter(Mandatory = $true)]
    [string]$RunTime       # Time in HH:mm format (24-hour)
)

try {
    # Validate script file exists
    if (-not (Test-Path $ScriptPath)) {
        throw "The script file '$ScriptPath' does not exist."
    }

    # Validate time format
    if ($RunTime -notmatch '^\d{2}:\d{2}$') {
        throw "Invalid time format. Use HH:mm (24-hour)."
    }

    # Create the action to run PowerShell with the script
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

    # Create a daily trigger at the specified time
    $trigger = New-ScheduledTaskTrigger -Daily -At ([datetime]::ParseExact($RunTime, 'HH:mm', $null))

    # Run with highest privileges
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest

    # Register the scheduled task
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force

    Write-Host "Scheduled task '$TaskName' created successfully to run at $RunTime daily." -ForegroundColor Green
}
catch {
    Write-Host "Error: $_" -ForegroundColor Red
}
