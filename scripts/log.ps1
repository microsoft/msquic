<#

.SYNOPSIS
This script provides helpers for starting, stopping and canceling log collection.

.PARAMETER Start
    Starts the logs being collected with the given profile.

.PARAMETER Profile
    The name of the profile to use for log collection.

.PARAMETER Cancel
    Stops the logs from being collected and discards any collected so far.

.PARAMETER Stop
    Stops the logs from being collected and saves them to the -Output location.

.PARAMETER Output
    The output file name or directory for the logs.

.PARAMETER RawLogOnly
    Does not convert the output logs to text. Only keeps raw files.

.PARAMETER InstanceName
    A unique name for the logging instance.

.PARAMETER ProfileInScriptDirectory
    Flag for if the MsQuic wprp file is in the same directory as the script.

.EXAMPLE
    logs.ps1 -Start -Profile Basic.Light

.EXAMPLE
    logs.ps1 -Cancel

.EXAMPLE
    logs.ps1 -Stop -Output .\quic

#>

param (
    [Parameter(Mandatory = $false, ParameterSetName='Start')]
    [switch]$Start = $false,

    [Parameter(Mandatory = $false, ParameterSetName='Start')]
    [switch]$Stream = $false,

    [Parameter(Mandatory = $false, ParameterSetName='Start')]
    [ValidateSet("Basic.Light", "Datapath.Light", "Datapath.Verbose", "Stacks.Light", "RPS.Light", "Performance.Light", "Basic.Verbose", "Performance.Light", "Performance.Verbose", "Full.Light", "Full.Verbose", "SpinQuic.Light")]
    [string]$Profile = "Full.Light",

    [Parameter(Mandatory = $false, ParameterSetName='Cancel')]
    [switch]$Cancel = $false,

    [Parameter(Mandatory = $false, ParameterSetName='Stop')]
    [switch]$Stop = $false,

    [Parameter(Mandatory = $true, ParameterSetName='Stop')]
    [string]$OutputPath = "",

    [Parameter(Mandatory = $false, ParameterSetName='Stop')]
    [switch]$RawLogOnly = $false,

    [Parameter(Mandatory = $false, ParameterSetName='Stop')]
    [string]$TmfPath = "",

    [Parameter(Mandatory = $false, ParameterSetName='Decode')]
    [switch]$Decode = $false,

    [Parameter(Mandatory = $true, ParameterSetName='Decode')]
    [string]$LogFile,

    [Parameter(Mandatory = $true, ParameterSetName='Decode')]
    [string]$WorkingDirectory,

    [Parameter(Mandatory = $false)]
    [string]$InstanceName = "msquic",

    [Parameter(Mandatory = $false)]
    [switch]$ProfileInScriptDirectory = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Path for the WPR profile.
$WprpFile = $RootDir + "\src\manifest\msquic.wprp"
if ($ProfileInScriptDirectory) {
    $WprpFile = Join-Path $PSScriptRoot MsQuic.wprp
}
$SideCar = Join-Path $RootDir "src/manifest/clog.sidecar"
$Clog2Text_lttng = "$HOME/.dotnet/tools/clog2text_lttng"

$TempDir = $null
if ($IsLinux) {
    $InstanceName = $InstanceName.Replace(".", "_")
    $TempDir = Join-Path $HOME "QUICLogs" $InstanceName
}

# Start log collection.
function Log-Start {
    if ($IsWindows) {
        wpr.exe -start "$($WprpFile)!$($Profile)" -filemode -instancename $InstanceName 2>&1
    } elseif ($IsMacOS) {
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
            lttng add-context --userspace --type=vpid --type=vtid | Write-Debug
            lttng start | Write-Debug

            if ($Stream) {
                lttng list | Write-Debug
                babeltrace -i lttng-live net://localhost | Write-Debug
                $myHostName = hostname
                Write-Host "Now decoding LTTng events in realtime on host=$myHostName...`n"
                $args = "babeltrace --names all -i lttng-live net://localhost/host/$myHostName/msquiclive | $Clog2Text_lttng  -s $SideCar --showTimestamp --showCpuInfo"
                Write-Host $args
                Invoke-Expression $args
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
        try {
            wpr.exe -cancel -instancename $InstanceName 2>&1
        } catch {
        }
        $global:LASTEXITCODE = 0
    } elseif ($IsMacOS) {
    } else {
        if (!(Test-Path $TempDir)) {
            Write-Debug "LTTng session ($InstanceName) not currently running"
        } else {
            Invoke-Expression "lttng destroy -n $InstanceName" | Write-Debug
            Remove-Item -Path $TempDir -Recurse -Force | Out-Null
            Write-Debug "Destroyed LTTng session ($InstanceName) and deleted $TempDir"
        }
    }
}

# Stops log collection, keeping the logs.
function Log-Stop {
    if ($IsWindows) {
        $EtlPath = $OutputPath + ".etl"
        wpr.exe -stop $EtlPath -instancename $InstanceName 2>&1
        if (!$RawLogOnly) {
            $LogPath = $OutputPath + ".log"
            $Command = "netsh trace convert $($EtlPath) output=$($LogPath) overwrite=yes report=no"
            if ($TmfPath -ne "" -and (Test-Path $TmfPath)) {
                $Command += " tmfpath=$TmfPath"
            }
            Invoke-Expression $Command
        }
    } elseif ($IsMacOS) {
    } else {
        $ClogOutputDecodeFile = $OutputPath + ".log"

        if (!(Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }

        if (!(Test-Path $TempDir)) {
            Write-Error "LTTng session ($InstanceName) not currently running!"
        }

        Invoke-Expression "lttng stop $InstanceName" | Write-Debug

        $LTTNGTarFile = $OutputPath + ".tgz"
        $BableTraceFile = $OutputPath + ".babel.txt"

        Write-Host "tar/gzip LTTng log files: $LTTNGTarFile"
        tar -cvzf $LTTNGTarFile $TempDir | Write-Debug

        if (!$RawLogOnly) {
            Write-Debug "Decoding LTTng into BabelTrace format ($BableTraceFile)"
            babeltrace --names all $TempDir/* > $BableTraceFile
            Write-Host "Decoding into human-readable text: $ClogOutputDecodeFile"
            $Command = "$Clog2Text_lttng -i $BableTraceFile -s $SideCar -o $ClogOutputDecodeFile --showTimestamp --showCpuInfo"
            Write-Host $Command

            try {
                Invoke-Expression $Command | Write-Debug
            } catch {
                $err = $_
                Write-Host "Failed to decode logs."
                Write-Host "Babeltrace ran. Run `"prepare-machine.ps1 -InstallClog2Text`" and run the following command"
                $Command
                Write-Host $err
            }
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
    } elseif ($IsMacOS) {
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

        try {
            Invoke-Expression $Command
        } catch {
            $err = $_
            Write-Host "Failed to decode logs."
            Write-Host "Babeltrace ran. Run `"prepare-machine.ps1 -InstallClog2Text`" and run the following command"
            $Command
            Write-Host $err
        }
    }
}

##############################################################
#                     Main Execution                         #
##############################################################

if ($Start)  { Log-Start }
if ($Cancel) { Log-Cancel }
if ($Stop)   { Log-Stop }
if ($Decode) { Log-Decode }
