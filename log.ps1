#
# Helper script for collecting logs.
#

param (
    [Parameter(Mandatory = $false, ParameterSetName='Start')]
    [switch]$Start = $false,

    [Parameter(Mandatory = $true, ParameterSetName='Start')]
    [ValidateSet("Full.Light", "Full.Verbose")]
    [string]$LogProfile,

    [Parameter(Mandatory = $false, ParameterSetName='Cancel')]
    [switch]$Cancel = $false,

    [Parameter(Mandatory = $false, ParameterSetName='Stop')]
    [switch]$Stop = $false,

    [Parameter(Mandatory = $true, ParameterSetName='Stop')]
    [string]$Output = "",

    [Parameter(Mandatory = $false)]
    [string]$InstanceName = "msquic"
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Helper to determine if we're running on Windows.
$IsWindows = $Env:OS -eq "Windows_NT"

# Path for the WPR profile.
$WprpFile = (Get-Item -Path ".\").FullName + "\manifest\msquic.wprp"

# Start log collection.
function Log-Start {
    if ($IsWindows) {
        wpr.exe -start "$($WprpFile)!$($LogProfile)" -filemode -instancename $InstanceName
    } else {
        # TODO
        Write-Error "Not supported yet!"
    }
}

# Cancels log collection, discarding any logs.
function Log-Cancel {
    if ($IsWindows) {
        wpr.exe -cancel -instancename $InstanceName
    } else {
        # TODO
        Write-Error "Not supported yet!"
    }
}

# Stops log collection, keeping the logs.
function Log-Stop {
    if ($IsWindows) {
        wpr.exe -stop $Output -instancename $InstanceName
    } else {
        # TODO
        Write-Error "Not supported yet!"
    }
}

if ($Start)  { Log-Start }
if ($Cancel) { Log-Cancel }
if ($Stop)   { Log-Stop }
