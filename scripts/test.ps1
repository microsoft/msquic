<#

.SYNOPSIS
This script runs the MsQuic tests.

.PARAMETER Config
    Specifies the build configuration to test.

.PARAMETER Arch
    The CPU architecture to test.

.PARAMETER Tls
    The TLS library test.

.PARAMETER ExtraArtifactDir
    Add an extra classifier to the artifact directory to allow publishing alternate builds of same base library

.PARAMETER Kernel
    Runs the Windows kernel mode tests.

.PARAMETER Filter
    A filter to include test cases from the list to execute. Multiple filters
    are separated by :. Negative filters are prefixed with -.

.PARAMETER ListTestCases
    Lists all the test cases.

.PARAMETER IsolationMode
    Controls the isolation mode when running each test case.

.PARAMETER KeepOutputOnSuccess
    Don't discard console output or logs on success.

.PARAMETER GenerateXmlResults
    Generates an xml Test report for the run.

.PARAMETER Debugger
    Attaches the debugger to each test case run.

.PARAMETER InitialBreak
    Debugger starts broken into the process to allow setting breakpoints, etc.

.PARAMETER BreakOnFailure
    Triggers a break point on a test failure.

.PARAMETER LogProfile
    The name of the profile to use for log collection.

.PARAMETER CompressOutput
    Compresses the output files generated for failed test cases.

.PARAMETER NoProgress
    Disables the progress bar.

.Parameter EnableAppVerifier
    Enables all basic Application Verifier checks on test binaries.

.Parameter CodeCoverage
    Collect code coverage for this test run. Incompatible with -Kernel and -Debugger.

.Parameter Clang
    Indicates the build was done with Clang. When combined with -CodeCoverage, uses llvm-cov gcov for coverage collection.

.Parameter AZP
    Runs in Azure Pipelines mode.

.Parameter ErrorsAsWarnings
    Treats all errors as warnings.

.Parameter DuoNic
    Uses DuoNic instead of loopback (DuoNic must already be installed via 'prepare-machine.ps1 -InstallDuoNic').

.Parameter NumIterations
    Number of times to run this particular command. Catches tricky edge cases due to random nature of networks.

.EXAMPLE
    test.ps1

.EXAMPLE
    test.ps1 -ListTestCases

.EXAMPLE
    test.ps1 -ListTestCases -Filter ParameterValidation*

.EXAMPLE
    test.ps1 -Filter ParameterValidation*

.EXAMPLE
    test.ps1 -LogProfile Full.Light

.EXAMPLE
    test.ps1 -LogProfile Full.Verbose -Compress

.EXAMPLE
    test.ps1 -Filter ParameterValidation* -NumIterations 10
#>

#Requires -Version 7.2

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$Arch = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "quictls", "openssl")]
    [string]$Tls = "",

    [Parameter(Mandatory = $false)]
    [switch]$Kernel = $false,

    [Parameter(Mandatory = $false)]
    [string]$Filter = "",

    [Parameter(Mandatory = $false)]
    [switch]$ListTestCases = $false,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Batch", "Isolated")]
    [string]$IsolationMode = "Isolated",

    [Parameter(Mandatory = $false)]
    [switch]$KeepOutputOnSuccess = $false,

    [Parameter(Mandatory = $false)]
    [switch]$GenerateXmlResults = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Debugger = $false,

    [Parameter(Mandatory = $false)]
    [switch]$InitialBreak = $false,

    [Parameter(Mandatory = $false)]
    [switch]$BreakOnFailure = $false,

    [Parameter(Mandatory = $false)]
    [ValidateSet("None", "Basic.Light", "Datapath.Light", "Datapath.Verbose", "Stacks.Light", "Stacks.Verbose", "RPS.Light", "RPS.Verbose", "Performance.Light", "Basic.Verbose", "Performance.Light", "Performance.Verbose", "Full.Light", "Full.Verbose", "SpinQuic.Light", "SpinQuicWarnings.Light")]
    [string]$LogProfile = "None",

    [Parameter(Mandatory = $false)]
    [switch]$CompressOutput = $false,

    [Parameter(Mandatory = $false)]
    [switch]$NoProgress = $false,

    [Parameter(Mandatory = $false)]
    [switch]$EnableAppVerifier = $false,

    [Parameter(Mandatory = $false)]
    [switch]$EnableSystemVerifier = $false,

    [Parameter(Mandatory = $false)]
    [switch]$CodeCoverage = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Clang = $false,

    [Parameter(Mandatory = $false)]
    [string]$ExtraArtifactDir = "",

    [Parameter(Mandatory = $false)]
    [switch]$AZP = $false,

    [Parameter(Mandatory = $false)]
    [switch]$GHA = $false,

    [Parameter(Mandatory = $false)]
    [switch]$SkipUnitTests = $false,

    [Parameter(Mandatory = $false)]
    [switch]$ErrorsAsWarnings = $false,

    [Parameter(Mandatory = $false)]
    [switch]$DuoNic = $false,

    [Parameter(Mandatory = $false)]
    [switch]$UseXdp = $false,

    [Parameter(Mandatory = $false)]
    [switch]$UseQtip = $false,

    [Parameter(Mandatory = $false)]
    [string]$OsRunner = "",

    [Parameter(Mandatory = $false)]
    [int]$NumIterations = 1
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

function Test-Administrator
{
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ($IsWindows -and !(Test-Administrator)) {
    Write-Warning "We recommend running this test as administrator. Crash dumps will not work"
}

# Validate the the kernel switch.
if ($Kernel -and !$IsWindows) {
    Write-Error "-Kernel switch only supported on Windows";
}

# Validate the code coverage switch.
if ($CodeCoverage) {
    if ($Kernel) {
        Write-Error "-CodeCoverage is not supported for kernel mode tests";
    }
    if ($Debugger) {
        Write-Error "-CodeCoverage switch is not supported with debugging";
    }
    if ($IsWindows -and !(Test-Path "C:\Program Files\OpenCppCoverage\OpenCppCoverage.exe")) {
            Write-Error "Code coverage tools are not installed";
    } elseif ($IsLinux -and !(Get-Command gcovr -ErrorAction SilentlyContinue)) {
        Write-Error "Code coverage tools for linux (gcovr) are not installed (missing 'gcovr')."
    } 
}

$BuildConfig = & (Join-Path $PSScriptRoot get-buildconfig.ps1) -Tls $Tls -Arch $Arch -ExtraArtifactDir $ExtraArtifactDir -Config $Config

$Tls = $BuildConfig.Tls
$Arch = $BuildConfig.Arch
$RootArtifactDir = $BuildConfig.ArtifactsDir

if ($UseXdp) {
    # Helper for XDP usage
    $DuoNic = $true
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Coverage destination directory.
$CoverageDir = Join-Path $RootDir "artifacts" "coverage"

if ($CodeCoverage) {
    # Clear old coverage data
    if (Test-Path $CoverageDir) {
        Remove-Item -Path (Join-Path $CoverageDir '*.cov') -Force
        Remove-Item -Path (Join-Path $RootDir '*.gcda') -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Path to the run-gtest Powershell script.
$RunTest = Join-Path $RootDir "scripts/run-gtest.ps1"

if ("" -ne $ExtraArtifactDir -and $Kernel) {
    Write-Error "Kernel not supported with extra artifact dir"
}

# Path to the msquictest executable.
$MsQuicTest = $null
$MsQuicCoreTest = $null
$MsQuicPlatTest = $null
$KernelPath = $null;
if ($IsWindows) {
    $MsQuicTest = Join-Path $RootArtifactDir  "msquictest.exe"
    $MsQuicCoreTest = Join-Path $RootArtifactDir "msquiccoretest.exe"
    $MsQuicPlatTest = Join-Path $RootArtifactDir "msquicplatformtest.exe"
    $KernelPath = Join-Path $RootDir "\artifacts\bin\winkernel\$($Arch)_$($Config)_$($Tls)"
}  elseif ($IsLinux -or $IsMacOS) {
    $MsQuicTest = Join-Path $RootArtifactDir "msquictest"
    $MsQuicCoreTest = Join-Path $RootArtifactDir "msquiccoretest"
    $MsQuicPlatTest = Join-Path $RootArtifactDir "msquicplatformtest"
} else {
    Write-Error "Unsupported platform type!"
}

# Make sure the build is present.
if (!(Test-Path $MsQuicTest)) {
    Write-Error "Build does not exist!`n `nRun the following to generate it:`n `n    $(Join-Path $RootDir "scripts" "build.ps1") -Config $Config -Arch $Arch -Tls $Tls`n"
}
if ($Kernel) {
    if (!(Test-Path (Join-Path $KernelPath "msquictestpriv.sys"))) {
        Write-Error "Kernel binaries do not exist!"
    }
}

$PfxFile = Join-Path $RootArtifactDir "selfsignedservercert.pfx"
if (!(Test-Path $PfxFile)) {
    $MyPath = Split-Path -Path $PSCommandPath -Parent
    $ScriptPath = Join-Path $MyPath install-test-certificates.ps1

    &$ScriptPath -OutputFile $PfxFile
}

# Build up all the arguments to pass to the Powershell script.
$TestArguments =  "-IsolationMode $IsolationMode -PfxPath $PfxFile"

if ($DuoNic) {
    $TestArguments += " -DuoNic"
}
if ($Kernel) {
    $TestArguments += " -Kernel $KernelPath"
}
if ("" -ne $Filter) {
    $TestArguments += " -Filter $Filter"
}
if ($ListTestCases) {
    $TestArguments += " -ListTestCases"
}
if ($KeepOutputOnSuccess) {
    $TestArguments += " -KeepOutputOnSuccess"
}
if ($GenerateXmlResults) {
    $TestArguments += " -GenerateXmlResults"
}
if ($Debugger) {
    $TestArguments += " -Debugger"
}
if ($InitialBreak) {
    $TestArguments += " -InitialBreak"
}
if ($BreakOnFailure) {
    $TestArguments += " -BreakOnFailure"
}
if ("None" -ne $LogProfile) {
    $TestArguments += " -LogProfile $LogProfile"
}
if ($CompressOutput) {
    $TestArguments += " -CompressOutput"
}
if ($NoProgress) {
    $TestArguments += " -NoProgress"
}
if ($EnableAppVerifier) {
    $TestArguments += " -EnableAppVerifier"
}
if ($EnableSystemVerifier) {
    $TestArguments += " -EnableSystemVerifier"
}
if ($CodeCoverage) {
    $TestArguments += " -CodeCoverage"
}
if ($AZP) {
    $TestArguments += " -AZP"
}
if ($GHA) {
    $TestArguments += " -GHA"
}
if ($ErrorsAsWarnings) {
    $TestArguments += " -ErrorsAsWarnings"
}
if ("" -ne $OsRunner) {
    $TestArguments += " -OsRunner $OsRunner"
}
if ($UseQtip) {
    $TestArguments += " -UseQtip"
}

if (![string]::IsNullOrWhiteSpace($ExtraArtifactDir)) {
    $TestArguments += " -ExtraArtifactDir $ExtraArtifactDir"
}

$TestPaths = @()
if (!$Kernel -and !$SkipUnitTests) {
    $TestPaths += $MsQuicPlatTest
    $TestPaths += $MsQuicCoreTest
}
$TestPaths += $MsQuicTest

for ($iteration = 1; $iteration -le $NumIterations; $iteration++) {
    if ($NumIterations -gt 1) {
        Write-Host "------- Iteration $iteration -------"
    }
    # Run the script.
    foreach ($TestPath in $TestPaths) {
        if ($IsLinux -and $UseXdp) {
            $NOFILE = Invoke-Expression "bash -c 'ulimit -n'"
            $DiagDir = Join-Path $RootDir "artifacts" "xdp_diagnostics"
            New-Item -ItemType Directory -Path $DiagDir -Force | Out-Null
            $DiagFile = Join-Path $DiagDir "resource_monitor.log"
            $BinaryName = Split-Path $TestPath -Leaf

            # Helper: post a diagnostic comment to the PR via GitHub API.
            function Post-XdpDiag($Title, $Body) {
                if (-not $env:GITHUB_TOKEN -or -not $env:GITHUB_REPOSITORY) {
                    Write-Host ">>> [XDP Diag] Missing GITHUB_TOKEN or GITHUB_REPOSITORY"
                    return
                }
                if (-not ($env:GITHUB_REF -match 'refs/pull/(\d+)')) {
                    Write-Host ">>> [XDP Diag] Not a PR (REF=$($env:GITHUB_REF))"
                    return
                }
                $PrNum = $Matches[1]
                $Full = "### XDP Diag: $Title`n$Body"
                $TmpFile = Join-Path $DiagDir "comment.json"
                @{ body = $Full } | ConvertTo-Json -Depth 2 | Set-Content -Path $TmpFile
                $result = bash -c "curl -sS -w '%{http_code}' -X POST -H 'Authorization: Bearer $($env:GITHUB_TOKEN)' -H 'Content-Type: application/json' -d @$TmpFile 'https://api.github.com/repos/$($env:GITHUB_REPOSITORY)/issues/$PrNum/comments' -o /dev/null 2>&1"
                Write-Host ">>> [XDP Diag] Post '$Title' to PR #$PrNum -> HTTP $result"
            }

            # Post pre-flight diagnostics BEFORE the test binary starts
            $PreDiag = bash -c "echo 'mem:'; free -h | head -2; echo 'disk:'; df -h / | tail -1; echo 'load:'; cat /proc/loadavg; echo 'cores:'; nproc; echo 'kernel:'; uname -r"
            Post-XdpDiag "Starting $BinaryName" "``````n$($PreDiag -join "`n")`n``````"

            # Start background resource monitor that writes to a log file
            $MonitorScript = Join-Path $DiagDir "monitor.sh"
            @'
#!/bin/bash
while true; do
    echo "[$(date +%H:%M:%S)] mem=$(free -m | awk 'NR==2{print $3"/"$2"MB"}') disk=$(df -h / | awk 'NR==2{print $3"/"$2}') load=$(cut -d' ' -f1-3 /proc/loadavg)" >> "$1"
    sleep 30
done
'@ | Set-Content -Path $MonitorScript -NoNewline
            bash -c "chmod +x $MonitorScript"
            $MonitorPid = $null
            try {
                $MonitorPid = (Start-Process -FilePath "bash" -ArgumentList $MonitorScript, $DiagFile -PassThru -NoNewWindow).Id
            } catch {
                Write-Host "Warning: Could not start resource monitor: $_"
            }

            # Start background heartbeat only for msquictest (where the crash
            # happens). Posts PR comments every 60 seconds so we capture the
            # system state just before the runner crash.
            $HeartbeatPid = $null
            if ($BinaryName -eq "msquictest") {
            $HeartbeatScript = Join-Path $DiagDir "heartbeat.sh"
            @"
#!/bin/bash
BINARY_NAME="$BinaryName"
DIAG_DIR="$DiagDir"
DIAG_FILE="$DiagFile"
"@ | Set-Content -Path $HeartbeatScript -NoNewline
            @'

COUNTER=0
while true; do
    COUNTER=$((COUNTER + 1))
    # Collect system state
    MEM=$(free -h | head -2)
    DISK=$(df -h / | tail -1)
    LOAD=$(cat /proc/loadavg)
    # Broad dmesg check: kernel oops, BUG, OOM, XDP, segfault, panic, hung_task, slab
    DMESG=$(sudo dmesg -T --since '2 minutes ago' 2>/dev/null | grep -iE 'oom|kill|xdp|bpf|segfault|oops|BUG|panic|Call Trace|RIP:|WARNING|hung_task|page allocation|slab|out of memory' | tail -20)
    if [ -z "$DMESG" ]; then
        DMESG="(no relevant kernel messages)"
    fi
    # Get last 5 lines of resource monitor
    MONITOR_TAIL=""
    if [ -f "$DIAG_FILE" ]; then
        MONITOR_TAIL=$(tail -5 "$DIAG_FILE")
    fi
    # Get process tree for test processes (top 10 by memory)
    PROCS=$(ps aux --sort=-%mem | head -10)
    # Check kernel memory (slab + page cache details)
    KMEM=$(cat /proc/meminfo | grep -E 'Slab|SReclaimable|SUnreclaim|Committed_AS|VmallocUsed|AnonPages|Mapped|PageTables')
    # Build the comment body
    BODY="### XDP Heartbeat #${COUNTER}: ${BINARY_NAME} (+${COUNTER} min)
\`\`\`
mem:
${MEM}
kernel mem:
${KMEM}
disk:
${DISK}
load:
${LOAD}
dmesg (last 2 min):
${DMESG}
top processes by memory:
${PROCS}
resource monitor:
${MONITOR_TAIL}
\`\`\`"
    # Post to PR if possible
    if [ -n "$GITHUB_TOKEN" ] && [ -n "$GITHUB_REPOSITORY" ] && [ -n "$GITHUB_REF" ]; then
        PR_NUM=$(echo "$GITHUB_REF" | grep -oP 'refs/pull/\K\d+')
        if [ -n "$PR_NUM" ]; then
            TMPFILE="${DIAG_DIR}/heartbeat_comment.json"
            python3 -c "import json,sys; print(json.dumps({'body': sys.stdin.read()}))" <<< "$BODY" > "$TMPFILE"
            curl -sS -w '%{http_code}' -X POST \
                -H "Authorization: Bearer $GITHUB_TOKEN" \
                -H "Content-Type: application/json" \
                -d @"$TMPFILE" \
                "https://api.github.com/repos/$GITHUB_REPOSITORY/issues/$PR_NUM/comments" \
                -o /dev/null 2>&1
        fi
    fi
    sleep 60  # heartbeat every 60 seconds
done
'@ | Add-Content -Path $HeartbeatScript -NoNewline
            bash -c "chmod +x $HeartbeatScript"
            try {
                $HeartbeatPid = (Start-Process -FilePath "bash" -ArgumentList $HeartbeatScript -PassThru -NoNewWindow).Id
                Write-Host ">>> [XDP Diag] Heartbeat monitor started (PID=$HeartbeatPid) for $BinaryName"
            } catch {
                Write-Host "Warning: Could not start heartbeat monitor: $_"
            }
            } # end if msquictest

            Write-Host ">>> [XDP Diag] Before ${BinaryName}:"
            bash -c "free -h; echo '---'; df -h / /tmp; echo '---'; cat /proc/loadavg"
            # Disable core dumps entirely via hard limit. Use timeout as
            # a safety net.
            Invoke-Expression ('/usr/bin/sudo bash -c "ulimit -n $NOFILE && ulimit -Hc 0 && timeout --signal=KILL --foreground 6000 pwsh $RunTest -Path $TestPath $TestArguments"')
            $TestExitCode = $LASTEXITCODE

            # Post post-test diagnostics
            $PostDiag = bash -c "echo 'mem:'; free -h | head -2; echo 'disk:'; df -h / | tail -1; echo 'load:'; cat /proc/loadavg; echo 'dmesg:'; sudo dmesg -T --since '2 hours ago' 2>/dev/null | grep -iE 'oom|kill|xdp|bpf|segfault|oops|BUG|panic|Call Trace|RIP:|WARNING|hung_task|page allocation|slab|out of memory' | tail -20 || echo 'none'"
            $MonitorLog = if (Test-Path $DiagFile) { Get-Content $DiagFile -Raw } else { "no data" }
            Post-XdpDiag "Finished $BinaryName (exit=$TestExitCode)" "``````n$($PostDiag -join "`n")`n``````n`nResource monitor:`n``````n$MonitorLog`n``````"

            Write-Host ">>> [XDP Diag] After ${BinaryName} (exit=$TestExitCode):"
            $PostDiag | ForEach-Object { Write-Host $_ }

            # Stop the background monitors
            if ($MonitorPid) {
                Stop-Process -Id $MonitorPid -ErrorAction SilentlyContinue
            }
            if ($HeartbeatPid) {
                Stop-Process -Id $HeartbeatPid -ErrorAction SilentlyContinue
            }
        } else {
            Invoke-Expression ($RunTest + " -Path $TestPath " + $TestArguments)
        }
    }
}

if ($CodeCoverage) {
    # Merge code coverage results
    if ($IsWindows) {
        $CoverageMergeParams = ""

        foreach ($file in $(Get-ChildItem -Path $CoverageDir -Filter '*.cov')) {
            $CoverageMergeParams += " --input_coverage $(Join-Path $CoverageDir $file.Name)"
        }

        if ($CoverageMergeParams -ne "") {
            $CoverageMergeParams +=  " --export_type cobertura:$(Join-Path $CoverageDir "msquiccoverage.xml")"

            $CoverageExe = 'C:\"Program Files"\OpenCppCoverage\OpenCppCoverage.exe'
            Invoke-Expression ($CoverageExe + $CoverageMergeParams) | Out-Null
        } else {
            Write-Warning "No coverage results to merge!"
        }
    } elseif ($IsLinux) {
        # Use gcovr to generate coverage report from .gcda files
        $CoverageOutput = Join-Path $CoverageDir "msquiccoverage.xml"
        $BuildDir       = Join-Path $RootDir "build"

        # Build filter and exclude expressions
        $coreFilter     = Join-Path $RootDir 'src/core'
        $platformFilter = Join-Path $RootDir 'src/platform'
        $testExclude    = '(?i).*/.*test.*(/.*)?$'

        $GcovrParams = ""

        if ($Clang) {
            $GcovrParams += ' --gcov-executable "llvm-cov gcov"'
        }

        $GcovrParams += " -r `"$RootDir`""
        $GcovrParams += " --filter `"$coreFilter`""
        $GcovrParams += " --filter `"$platformFilter`""
        $GcovrParams += " --exclude `"$testExclude`""
        $GcovrParams += " --cobertura `"$CoverageOutput`""
        $GcovrParams += " `"$BuildDir`""

        Invoke-Expression ("gcovr" + $GcovrParams) | Out-Null

        if (Test-Path $CoverageOutput) {
            Write-Host "Coverage report generated at $CoverageOutput"
        } else {
            Write-Warning "Coverage generation was not successful"
        }
    }
}
