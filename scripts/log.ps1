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

.PARAMETER TmfPath
    Used for converting Windows WPP logs.

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

    [Parameter(Mandatory = $true, ParameterSetName='Start')]
    [ValidateSet("Basic.Light", "Basic.Verbose", "Full.Light", "Full.Verbose", "SpinQuic.Light", "Stream")]
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

    [Parameter(Mandatory = $false, ParameterSetName='DecodeTrace')]
    [switch]$DecodeTrace = $false,

     [Parameter(Mandatory = $true, ParameterSetName='DecodeTrace')]
    [string]$LogFile,

     [Parameter(Mandatory = $true, ParameterSetName='DecodeTrace')]
    [string]$WorkingDirectory,

    [Parameter(Mandatory = $false)]
    [string]$InstanceName = "msquic"
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Start log collection.
function Log-Start {
    if ($IsWindows) {
        # Path for the WPR profile.
        $WprpFile = $RootDir + "\src\manifest\msquic.wprp"

        wpr.exe -start "$($WprpFile)!$($LogProfile)" -filemode -instancename $InstanceName
    } else {
        lttng -q destroy

        $LogProfile = "QuicLTTNG"

        $OutputDirectoryRoot = Join-Path $HOME "QUICLogs"
        $LTTNGRawDirectory = Join-Path $OutputDirectoryRoot "LTTNGRaw"

        if (Test-Path $LTTNGRawDirectory) {
            Remove-Item -Path $LTTNGRawDirectory -Recurse -Force
        }
        New-Item -Path $LTTNGRawDirectory -ItemType Directory -Force | Out-Null

        $Command = "lttng create $LogProfile -o=$LTTNGRawDirectory"
        Invoke-Expression $Command

        lttng -q enable-event --userspace CLOG_*
        lttng -q start | Write-Host

        Write-Host "Recording QUIC LTTNG into $LTTNGRawDirectory"
    }
}

# Cancels log collection, discarding any logs.
function Log-Cancel {
    if ($IsWindows) {
        wpr.exe -cancel -instancename $InstanceName
    } else {
        lttng -q destroy

        $OutputDirectoryRoot = Join-Path $HOME "QUICLogs"

        if (Test-Path $OutputDirectoryRoot) {
           Remove-Item -Path $OutputDirectoryRoot -Recurse -Force
            Write-Host "Stopped LTTNG recording and deleted $OutputDirectoryRoot"
        } else {
            Write-Host "ERROR : LTTNG events we not being recorded"
        }
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
            if ($TmfPath -ne "") {
                $Command += " tmfpath=$($TmfPath)"
            }
            Invoke-Expression $Command
        }
    } else {
        $LogProfile = "QuicLTTNG"

        lttng -q stop

        $LTTNGTempDirectory = Join-Path $HOME "QUICLogs"
        $LTTNGRawDirectory = Join-Path $LTTNGTempDirectory "LTTNGRaw"
        $LTTNGTarFile = Join-Path $OutputDirectory "lttng_trace.tgz"
        $CLOG2TEXT = Join-Path $RootDir "artifacts/tools/clog/clog2text_lttng"
        $SideCar = Join-Path $RootDir "src/manifest/clog.sidecar"
        $BableTraceFile = Join-Path $OutputDirectory "decoded_babeltrace.txt"
        $ClogOutputDecodeFile = Join-Path $OutputDirectory "clog_decode.txt"

        if (!(Test-Path $LTTNGRawDirectory)) {
            Write-Host "ERROR : Output Directory $LTTNGRawDirectory must exist"
            exit 1
        }

        if (!(Test-Path $OutputDirectory)) {
            New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
        }

        Write-Host "tar/gzip LTTNG log files from $LTTNGRawDirectory into $LTTNGTarFile"
        tar -cvzf $LTTNGTarFile $LTTNGRawDirectory

        Write-Host "Decoding LTTNG into BabelTrace format ($WorkingDirectory/decoded_babeltrace.txt)"
        babeltrace --names all $LTTNGRawDirectory/* > $BableTraceFile

        Write-Host "Decoding Babeltrace into human text using CLOG"
        $Command = "$CLOG2TEXT -i $BableTraceFile -s $SideCar -o $ClogOutputDecodeFile"
        Write-Host $Command
        Invoke-Expression $Command

        Write-Host "Deleting LTTNG Directory (the contents are now stored in the tgz file)"
        Remove-Item -Path $LTTNGTempDirectory -Recurse -Force
    }
}


# Start log collection.
function Log-Stream {
    if ($IsWindows) {
        Write-Host "Not supported on Windows"
    } else {
        lttng -q destroy
        lttng -q create msquicLive --live
        lttng -q enable-event --userspace CLOG_*
        lttng -q start
        lttng -q list
        babeltrace -i lttng-live net://localhost


        $CLOG2TEXT = Join-Path $RootDir "artifacts/tools/clog/clog2text_lttng"
        $SideCar = Join-Path $RootDir "src/manifest/clog.sidecar"

        Write-Host "***************************************************************"
        Write-Host ""
        Write-Host ""
        Write-Host "   Starting live decode of traces"
        Write-Host ""
        Write-Host "   Please start your tests - your events should be decoded in realtime"
        $Command = "babeltrace --names all -i lttng-live net://localhost/host/$env:NAME/msquicLive | $CLOG2TEXT -s $SideCar"
        Invoke-Expression $Command
    }
}


# Decode Log from file
function Log-Decode {
    if ($IsWindows) {
        Write-Host "Not supported on Windows"
    } else {
        Write-Host $LogFile

        $DecompressedLogs = Join-Path $WorkingDirectory "DecompressedLogs"
        $ClogOutputDecodeFile = Join-Path $WorkingDirectory "clog_decode.txt"
        $SideCar = Join-Path $RootDir "src/manifest/clog.sidecar"
        $BableTraceFile = Join-Path $WorkingDirectory "decoded_babeltrace.txt"
        $CLOG2TEXT = Join-Path $RootDir "artifacts/tools/clog/clog2text_lttng"

        mkdir $WorkingDirectory
        mkdir $DecompressedLogs

        Write-Host "Decompressing $Logfile into $DecompressedLogs"
        tar xvfz $Logfile -C $DecompressedLogs

        Write-Host "Decoding LTTNG into BabelTrace format ($BableTraceFile)"
        babeltrace --names all $DecompressedLogs/* > $BableTraceFile

        Write-Host "Decoding Babeltrace into human text using CLOG"
        $Command = "$CLOG2TEXT -i $BableTraceFile -s $SideCar -o $ClogOutputDecodeFile"
        Write-Host $Command
        Invoke-Expression $Command
    }
}
##############################################################
#                     Main Execution                         #
##############################################################

if ($Start)  {
    if($LogProfile -eq "Stream") {
        Log-Stream
    } else {
        Log-Start
    }
}

if ($Cancel) { Log-Cancel }
if ($Stop)   { Log-Stop }
if ($DecodeTrace) {Log-Decode }