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
    # Code review comment -> Good: Validates that the script file exists before proceeding.
    if (-not (Test-Path $ScriptPath)) {
        throw "The script file '$ScriptPath' does not exist."
    }

    # Code review comment -> Good: Validates time format using regex.
    # Code review comment -> Suggestion: Could also validate that the time is a valid 24-hour time (e.g., not 25:99).
    if ($RunTime -notmatch '^\d{2}:\d{2}$') {
        throw "Invalid time format. Use HH:mm (24-hour)."
    }

    # Code review comment -> Enhancement: Wrap ParseExact in try/catch to handle invalid times like 25:00.
    try {
        $parsedTime = [datetime]::ParseExact($RunTime, 'HH:mm', $null)
    }
    catch {
        throw "Invalid time value. Please provide a valid 24-hour time."
    }

    # Code review comment -> Good: Uses New-ScheduledTaskAction to define the action.
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`""

    # Code review comment -> Good: Creates a daily trigger at the specified time.
    $trigger = New-ScheduledTaskTrigger -Daily -At $parsedTime

    # Code review comment -> Good: Runs with highest privileges.
    # Code review comment -> Suggestion: Allow user to specify a different account if needed.
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest

    # Code review comment -> Enhancement: Check if task already exists and remove or update it to avoid duplicate errors.
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }

    # Code review comment -> Good: Registers the scheduled task.
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force

    Write-Host "Scheduled task '$TaskName' created successfully to run at $RunTime daily." -ForegroundColor Green
}
catch {
    # Code review comment -> Good: Catches and displays errors.
    # Code review comment -> Suggestion: Could log errors to a file for auditing.
    Write-Host "Error: $_" -ForegroundColor Red
}

