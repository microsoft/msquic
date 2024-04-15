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

.PARAMETER PerfRun
    Use perf command to wrap exe

.PARAMETER Command
    Command to be wrapped by PerfRun

.PARAMETER Iteration
    Current test iteration from client

.PARAMETER PerfGraph
    Use perf command to generate flamegraph

.PARAMETER NumIterations
    The number of test iterations from client

.PARAMETER Output
    The output file name or directory for the logs.

.PARAMETER RawLogOnly
    Does not convert the output logs to text. Only keeps raw files.

.PARAMETER InstanceName
    A unique name for the logging instance.

.PARAMETER ProfileInScriptDirectory
    Flag for if the MsQuic wprp file is in the same directory as the script.

.PARAMETER Remote
    Flag for if the logging is for Local/Remote

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
    [ValidateSet("Basic.Light", "Datapath.Light", "Datapath.Verbose", "Stacks.Light", "Stacks.Verbose", "RPS.Light", "RPS.Verbose", "Performance.Light", "Basic.Verbose", "Performance.Light", "Performance.Verbose", "Full.Light", "Full.Verbose", "SpinQuic.Light", "SpinQuicWarnings.Light")]
    [string]$Profile = "Full.Light",

    [Parameter(Mandatory = $false, ParameterSetName='Cancel')]
    [switch]$Cancel = $false,

    [Parameter(Mandatory = $false, ParameterSetName='Stop')]
    [switch]$Stop = $false,

    [Parameter(Mandatory = $false, ParameterSetName='PerfRun')]
    [switch]$PerfRun = $false,

    [Parameter(Mandatory = $false, ParameterSetName='PerfRun')]
    [string]$Command = "",

    [Parameter(Mandatory = $false, ParameterSetName='PerfRun')]
    [int]$Iteration = 1,

    [Parameter(Mandatory = $false, ParameterSetName='PerfGraph')]
    [switch]$PerfGraph = $false,

    [Parameter(Mandatory = $false, ParameterSetName='PerfGraph')]
    [int]$NumIterations = 1,

    [Parameter(Mandatory = $true, ParameterSetName='Stop')]
    [Parameter(Mandatory = $true, ParameterSetName='PerfGraph')]
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
    [switch]$ProfileInScriptDirectory = $false,

    [Parameter(Mandatory = $false)]
    [string]$InstanceName = "msquic",

    [Parameter(Mandatory = $false)]
    [switch]$Remote = $false
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
$TempLTTngDir = $null
$TempPerfDir = $null
if ($IsLinux) {
    $InstanceName = $InstanceName.Replace(".", "_")
    $TempDir = Join-Path $HOME "QUICLogs"
    $TempLTTngDir = Join-Path $TempDir $InstanceName
    $TempPerfDir = Join-Path $TempDir "Perf"
    try { lttng version | Out-Null }
    catch {
        Write-Host "Installing lttng"
        sudo apt-add-repository ppa:lttng/stable-2.13
        sudo apt-get update
        sudo apt-get install -y lttng-tools
        sudo apt-get install -y liblttng-ust-dev
    }
    perf version 2>&1 | Out-Null
    if (!$?) {
        Write-Debug "Installing perf"
        sudo apt-get install -y linux-tools-$(uname -r)
        sudo wget https://raw.githubusercontent.com/brendangregg/FlameGraph/master/stackcollapse-perf.pl -O /usr/bin/stackcollapse-perf.pl
        sudo chmod +x /usr/bin/stackcollapse-perf.pl
        sudo wget https://raw.githubusercontent.com/brendangregg/FlameGraph/master/flamegraph.pl -O /usr/bin/flamegraph.pl
        sudo chmod +x /usr/bin/flamegraph.pl
    }
}

function Perf-Run {
    if (!$IsLinux) {
        throw "perf command wrapper is only for Linux"
    } else {
        New-Item -Path $TempPerfDir -ItemType Directory -Force
        $CommandSplit = $Command.Split(" ")
        $OutFile = "server.perf.data"
        if (!$Remote) {
            $OutFile = "client_$Iteration.perf.data"
        }
        $BasePath = Split-Path $CommandSplit[0] -Parent
        # FIXME: When to run Remote case and command bellow generates stderr, server side stop its operation
        #        e.g. - `-F max`'s warning
        #             - `perf`'s graceful stop generates two lines of stderr. the first line stops the operation (no essential effect)
        # FIXME: Small frequency for now. Higher (e.g. max) freq (with -a) generates big data which causes host machine to be overloaded,
        #        cause timeout and/or WPA becomes too slow to load/convert trace
        # FIXME: Make WPA to load trace which is collected without -a option. this is PerfView design.
        #        https://github.com/microsoft/perfview/issues/1793
        # FIXME: Run only single `perf` in case of using -a option for Loopback test as it collects trace from entire system
        #
        # WARN: If all test cases runs, timeout need to be more than 90 min with Freq of 99.
        #       Especially HPS/RPS tests are heavy
        # WARN: Must not redirect output to Out-Debug and Out-Null as client watches server's stdout
        $Freq = 399
        sudo LD_LIBRARY_PATH=$BasePath perf record -F $Freq -g -o $(Join-Path $TempPerfDir $OutFile) $CommandSplit[0] $CommandSplit[1..$($CommandSplit.count-1)]
    }
}

function Perf-Cancel {
    if (!$IsLinux) {
        throw "perf command wapper is only for Linux"
    } else {
        sudo pkill perf
        try { Remove-Item -Path $TempPerfDir -Recurse -Force | Out-Null } catch { }
    }
}

function Perf-Graph {
    if (!$IsLinux) {
        throw "perf command wapper is only for Linux"
    } else {
        New-Item -ItemType Directory $OutputPath -Force | Out-Null
        if ($Remote) {
            $InputPath = $(Join-Path $TempPerfDir "server.perf.data")
            sudo -E perf script -i $InputPath > $(Join-Path $OutputPath "server.perf.data.txt")
            cat $(Join-Path $OutputPath "server.perf.data.txt") | stackcollapse-perf.pl | flamegraph.pl > $(Join-Path $OutputPath "server.svg")
            Remove-Item -Path $InputPath -Force | Out-Null
        } else {
            1..$NumIterations | ForEach {
                Start-Job -ScriptBlock {
                    $FileName = "client_$using:_.perf.data"
                    $InputPath = $(Join-Path $using:TempPerfDir $FileName)
                    sudo -E perf script -i $InputPath > $(Join-Path $using:OutputPath ($FileName.Split(".")[0] + ".perf.data.txt"))
                    cat $(Join-Path $using:OutputPath ($FileName.Split(".")[0] + ".perf.data.txt")) | stackcollapse-perf.pl | flamegraph.pl > $(Join-Path $using:OutputPath ($FileName.Split(".")[0] + ".svg"))
                    Remove-Item -Path $InputPath -Force | Out-Null
                }
            } | Wait-Job | Receive-Job -ErrorAction Continue
        }
        if (@(Get-ChildItem $TempPerfDir).count -eq 0) {
            Remove-Item -Path $TempPerfDir -Recurse -Force | Out-Null
        }
    }
}

# Start log collection.
function Log-Start {
    if ($IsWindows) {
        wpr.exe -start "$($WprpFile)!$($Profile)" -filemode -instancename $InstanceName 2>&1
    } elseif ($IsMacOS) {
    } else {
        if (Test-Path $TempLTTngDir) {
            Write-Error "LTTng session ($InstanceName) already running! ($TempLTTngDir)"
        }

        try {
            if ($Stream) {
                lttng -q create msquiclive --live
            } else {
                New-Item -Path $TempLTTngDir -ItemType Directory -Force | Out-Null
                $Command = "lttng create $InstanceName -o=$TempLTTngDir"
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
        try { wpr.exe -cancel -instancename $InstanceName 2>&1 } catch { }
    } elseif ($IsMacOS) {
    } else {
        if (!(Test-Path $TempLTTngDir)) {
            Write-Debug "LTTng session ($InstanceName) not currently running"
        } else {
            try { Invoke-Expression "lttng destroy -n $InstanceName" | Write-Debug } catch { }
            try { Remove-Item -Path $TempLTTngDir -Recurse -Force | Out-Null } catch { }
            Write-Debug "Destroyed LTTng session ($InstanceName) and deleted $TempLTTngDir"
        }
        Perf-Cancel
    }
    $global:LASTEXITCODE = 0
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

        if (!(Test-Path $TempLTTngDir)) {
            Write-Error "LTTng session ($InstanceName) not currently running!"
        }

        Invoke-Expression "lttng stop $InstanceName" | Write-Debug

        $LTTNGTarFile = $OutputPath + ".tgz"
        $BableTraceFile = $OutputPath + ".babel.txt"

        Write-Host "tar/gzip LTTng log files: $LTTNGTarFile"
        tar -cvzf $LTTNGTarFile -P $TempLTTngDir | Write-Debug

        if (!$RawLogOnly) {
            Write-Debug "Decoding LTTng into BabelTrace format ($BableTraceFile)"
            babeltrace --names all $TempLTTngDir/* > $BableTraceFile
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
        Remove-Item -Path $TempLTTngDir -Recurse -Force | Out-Null
        Write-Debug "Destroyed LTTng session ($InstanceName) and deleted $TempLTTngDir"
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
if ($PerfRun) { Perf-Run }
if ($PerfGraph) { Perf-Graph }
