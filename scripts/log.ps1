<#

.SYNOPSIS
This script provides helpers for starting, stopping and canceling log collection.

.PARAMETER Start
    Starts the logs being collected with the given profile.

.PARAMETER LogProfile
    The name of the profile to use for log collection.

.PARAMETER Cancel
    Stops the logs from being collected and discards any collected so far.

.PARAMETER Stop
    Stops the logs from being collected and saves them to the -Output location.

.PARAMETER Output
    The output file name or directory for the logs.

.PARAMETER ConvertToText
    Converts the output logs to text.

.PARAMETER InstanceName
    A unique name for the logging instance.

.EXAMPLE
    logs.ps1 -Start -LogProfile Basic.Light

.EXAMPLE
    logs.ps1 -Cancel

.EXAMPLE
    logs.ps1 -Stop -Output quic.etl

#>

param (
    [Parameter(Mandatory = $false, ParameterSetName='Start')]
    [switch]$Start = $false,

    [Parameter(Mandatory = $false, ParameterSetName='Start')]
    [switch]$Stream = $false,

    [Parameter(Mandatory = $true, ParameterSetName='Start')]
    [ValidateSet("Basic.Light", "Basic.Verbose", "Full.Light", "Full.Verbose", "SpinQuic.Light")]
    [string]$LogProfile,

    [Parameter(Mandatory = $false, ParameterSetName='Cancel')]
    [switch]$Cancel = $false,

    [Parameter(Mandatory = $false, ParameterSetName='Stop')]
    [switch]$Stop = $false,

    [Parameter(Mandatory = $true, ParameterSetName='Stop')]
    [string]$OutputDirectory = "",

    [Parameter(Mandatory = $false, ParameterSetName='Stop')]
    [switch]$ConvertToText = $false,

    [Parameter(Mandatory = $false, ParameterSetName='Stop')]
    [string]$TmfPath = "",

    [Parameter(Mandatory = $false, ParameterSetName='Decode')]
    [switch]$Decode = $false,

    [Parameter(Mandatory = $true, ParameterSetName='Decode')]
    [string]$LogFile,

    [Parameter(Mandatory = $true, ParameterSetName='Decode')]
    [string]$WorkingDirectory,

    [Parameter(Mandatory = $false)]
    [string]$InstanceName = "msquic"
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Path for the WPR profile.
$WprpFile = $RootDir + "\src\manifest\msquic.wprp"
$SideCar = Join-Path $RootDir "src/manifest/clog.sidecar"
$Clog2Text_lttng = Join-Path $RootDir "artifacts/clog/clog2text_lttng"

$TempDir = $null
if ($IsLinux) {
    $InstanceName = $InstanceName.Replace(".", "_")
    $TempDir = Join-Path $HOME "QUICLogs" $InstanceName

    # Set Linux env variables to include dotnet.
    $env:PATH+=":$HOME/.dotnet"
    $env:PATH+=":$HOME/.dotnet/tools"
    $env:DOTNET_ROOT="$HOME/.dotnet/"
}

# Start log collection.
function Log-Start {
    if ($IsWindows) {
        wpr.exe -start "$($WprpFile)!$($LogProfile)" -filemode -instancename $InstanceName
    } else {
        if (Test-Path $TempDir) {
            Write-Error "LTTng session ($InstanceName) already running! ($TempDir)"
        }

        try {
            if ($Stream) {
                lttng -q create msquiclive --live
            } else {
                New-Item -Path $TempDir -ItemType Directory -Force | Out-Null
                $Command = "lttng create $InstanceName -o=$TempDir"
                Invoke-Expression $Command | Write-Debug
            }
            lttng enable-event --userspace CLOG_* | Write-Debug
            lttng start | Write-Debug

            if ($Stream) {
                lttng list | Write-Debug
                babeltrace -i lttng-live net://localhost | Write-Debug
                Write-Host "Now decoding LTTng events in realtime...`n"
                Invoke-Expression "babeltrace --names all -i lttng-live net://localhost/host/$env:NAME/msquiclive | $Clog2Text_lttng -s $SideCar"
            }
        } finally {
            if ($Stream) {
                Invoke-Expression "lttng destroy msquiclive" | Write-Debug
            }
        }
    }
}

# Cancels log collection, discarding any logs.
function Log-Cancel {
    if ($IsWindows) {
        wpr.exe -cancel -instancename $InstanceName
    } else {
        if (!(Test-Path $TempDir)) {
            Write-Error "LTTng session ($InstanceName) not currently running!"
        }

        Invoke-Expression "lttng destroy $InstanceName" | Write-Debug
        Remove-Item -Path $TempDir -Recurse -Force | Out-Null
        Write-Debug "Destroyed LTTng session ($InstanceName) and deleted $TempDir"
    }
}

# Stops log collection, keeping the logs.
function Log-Stop {
    if ($IsWindows) {
        $EtlPath = Join-Path $OutputDirectory "quic.etl"
        wpr.exe -stop $EtlPath -instancename $InstanceName
        if ($ConvertToText) {
            $LogPath = Join-Path $OutputDirectory "quic.log"
            $Command = "netsh trace convert $($EtlPath) output=$($LogPath) overwrite=yes report=no"
            Invoke-Expression $Command
        }
    } else {
        $ClogOutputDecodeFile = Join-Path $OutputDirectory "quic.log"

        if (!(Test-Path $OutputDirectory)) {
            New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
        }
    
        if (!(Test-Path $TempDir)) {
            Write-Error "LTTng session ($InstanceName) not currently running!"
        }

        Invoke-Expression "lttng stop $InstanceName" | Write-Debug

        $LTTNGTarFile = Join-Path $OutputDirectory "lttng_trace.tgz"
        $BableTraceFile = Join-Path $OutputDirectory "babeltrace.txt"

        Write-Host "tar/gzip LTTng log files: $LTTNGTarFile"
        tar -cvzf $LTTNGTarFile $TempDir | Write-Debug

        if ($ConvertToText) {
            Write-Debug "Decoding LTTng into BabelTrace format ($BableTraceFile)"
            babeltrace --names all $TempDir/* > $BableTraceFile

            Write-Host "Decoding into human-readable text: $ClogOutputDecodeFile"
            $Command = "$Clog2Text_lttng -i $BableTraceFile -s $SideCar -o $ClogOutputDecodeFile"
            Write-Debug $Command
            Invoke-Expression $Command | Write-Debug
            Remove-Item -Path $BableTraceFile -Force | Out-Null
        }

        Invoke-Expression "lttng destroy $InstanceName" | Write-Debug
        Remove-Item -Path $TempDir -Recurse -Force | Out-Null
        Write-Debug "Destroyed LTTng session ($InstanceName) and deleted $TempDir"
    }
}
# Decodes a log file.
function Log-Decode {

    if (!(Test-Path $WorkingDirectory)) {
        New-Item -Path $WorkingDirectory -ItemType Directory -Force | Out-Null
    }

    if ($IsWindows) {
       Write-Error "Not supported on Windows"
    } else {
        Write-Host $LogFile

        $DecompressedLogs = Join-Path $WorkingDirectory "DecompressedLogs"
        $ClogOutputDecodeFile = Join-Path $WorkingDirectory "clog_decode.txt"
        $BableTraceFile = Join-Path $WorkingDirectory "decoded_babeltrace.txt"

        mkdir $WorkingDirectory
        mkdir $DecompressedLogs

        Write-Host "Decompressing $Logfile into $DecompressedLogs"
        tar xvfz $Logfile -C $DecompressedLogs

        Write-Host "Decoding LTTng into BabelTrace format ($BableTraceFile)"
        babeltrace --names all $DecompressedLogs/* > $BableTraceFile

        Write-Host "Decoding Babeltrace into human text using CLOG"
        $Command = "$Clog2Text_lttng -i $BableTraceFile -s $SideCar -o $ClogOutputDecodeFile"
        Write-Host $Command
        Invoke-Expression $Command
    }
}

##############################################################
#                     Main Execution                         #
##############################################################

if ($Start)  { Log-Start }
if ($Cancel) { Log-Cancel }
if ($Stop)   { Log-Stop }
if ($Decode) { Log-Decode }
