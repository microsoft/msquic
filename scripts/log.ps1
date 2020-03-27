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
        Write-Host "lttng-destroy"
        lttng destroy | Write-Host
        lttng | Write-Host
        lttng version | Write-Host

        $LogProfile = "QuicLTTNG"

        Write-Host "making QUICLogs directory ./QUICLogs/$LogProfile"
        pushd ~
        mkdir ./QUICLogs | Out-Null
        mkdir ./QUICLogs/$LogProfile | Out-Null
        pushd ./QUICLogs | Out-Null

        Write-Host "------------" 
        Write-Host "Creating LTTNG Profile $LogProfile into ./$LogProfile"
        $Command = "lttng create $LogProfile -o=$LogProfile | Write-Host"
        Write-Host $Command
        Invoke-Expression $Command

        popd
        Write-Host "------------" 
        
        Write-Host "Enabling all CLOG traces"
        lttng enable-event --userspace CLOG_*

        Write-Host "Starting LTTNG"
        lttng start | Write-Host
        lttng list | Write-Host
        popd
    }
}

# Cancels log collection, discarding any logs.
function Log-Cancel {
    if ($IsWindows) {
        wpr.exe -cancel -instancename $InstanceName
    } else {
        lttng destroy
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

        $LogPath = Join-Path $OutputDirectory "quic.log"
        # $BabelLogPath = Join-Path $OutputDirectory "babel.log"
        $LTTNGLog = Join-Path $OutputDirectory "lttng_trace.tgz"
        Write-Host "Formating traces into $LogPath"


        Write-Host "tar/gzip LTTNG log files into ~/QUICLogs/$LogProfile"
        tar -cvzf $LTTNGLog ~/QUICLogs/$LogProfile

        # mkdir $OutputDirectory | Out-Null
        # Write-Host "Writing BabelTrace logs to $BabelLogPath"
        # $Command = "time babeltrace --names all ~/QUICLogs/$LogProfile/* > $BabelLogPath"
        # Write-Host "Command :$Command"
        # Invoke-Expression $Command

        # tail -n 1000 $BabelLogPath | Write-Host       

        Write-Host "Finished Creating LTTNG Log"
        ls -l $OutputDirectory
    }
}


# Start log collection.
function Log-Stream {
    if ($IsWindows) {
       Write-Host "Not supported on Windows"
    } else {
        lttng destroy
        Write-Host "------------"   
        lttng destroy
        lttng create msquicLive --live
        lttng enable-event --userspace CLOG_*
        lttng start
        lttng list
        babeltrace -i lttng-live net://localhost
        
        babeltrace --names all -i lttng-live net://localhost/host/$env:NAME/msquicLive | ../artifacts/tools/clog/clog2text_lttng -s ../src/manifest/clog.sidecar
    }
}


# Decode Log from file
function Log-Decode {
    if ($IsWindows) {
       Write-Host "Not supported on Windows"
    } else {
        Write-Host $LogFile

        $DecompressedLogs = Join-Path $WorkingDirectory "DecompressedLogs"

        mkdir $WorkingDirectory
        mkdir $DecompressedLogs
        tar xvfz $Logfile -C $DecompressedLogs

        babeltrace --names all /home/chris/fooboobaz/DecompressedLogs/* | ../artifacts/tools/clog/clog2text_lttng -s ../src/manifest/clog.sidecar > $WorkingDirectory/clog_decode.txt
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

Write-Host "Finished and exiting"