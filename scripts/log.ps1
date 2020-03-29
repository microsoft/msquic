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
        lttng destroy | Out-Null
     
        $LogProfile = "QuicLTTNG"

        #find $HOME | Write-Host

        $OutputDirectoryRoot = Join-Path $HOME "QUICLogs"
        $LTTNGRawDirectory = Join-Path $OutputDirectoryRoot "LTTNGRaw"

        Write-Host "making QUICLogs directory ./QUICLogs/$LogProfile"       

        if (!(Test-Path $LTTNGRawDirectory)) { 
            New-Item -Path $LTTNGRawDirectory -ItemType Directory -Force | Out-Null 
        } else {
            Write-Host "ERROR : Output Directory $LTTNGRawDirectory must not exist"
            exit 1        
        }       

                 
        Write-Host "------------" 
        Write-Host "Creating LTTNG Profile $LogProfile into $LTTNGRawDirectory"
        $Command = "lttng create $LogProfile -o=$LTTNGRawDirectory | Write-Host"
        Write-Host $Command
        Invoke-Expression $Command

     
        Write-Host "------------" 
        
        Write-Host "Enabling all CLOG traces"
        lttng enable-event --userspace CLOG_*

        Write-Host "Starting LTTNG"
        lttng start | Write-Host
        lttng list | Write-Host
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

        #find $HOME | Write-Host

        $OutputDirectoryRoot = Join-Path $HOME "QUICLogs"
        $LTTNGRawDirectory = Join-Path $OutputDirectoryRoot "LTTNGRaw"

        if (!(Test-Path $LTTNGRawDirectory)) {            
            Write-Host "ERROR : Output Directory $LTTNGRawDirectory must exist"
            exit 1        
        }       

        $LTTNGLog = Join-Path $OutputDirectory "lttng_trace.tgz"

        
        Write-Host "tar/gzip LTTNG log files from $LTTNGRawDirectory into $LTTNGLog"
        tar -cvzf $LTTNGLog $LTTNGRawDirectory

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

        Write-Host "Decompressing $Logfile into $DecompressedLogs"
        tar xvfz $Logfile -C $DecompressedLogs

        Write-Host "Decoding LTTNG into BabelTrace format ($DecompressedLogs/decoded_babeltrace.txt)"
        babeltrace --names all $DecompressedLogs/* > $WorkingDirectory/decoded_babeltrace.txt

        Write-Host "Decoding Babeltrace into human text using CLOG"
        ../artifacts/tools/clog/clog2text_lttng -i $WorkingDirectory/decoded_babeltrace.txt -s ../src/manifest/clog.sidecar -o $WorkingDirectory/clog_decode.txt
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