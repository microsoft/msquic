<#

.SYNOPSIS
This script runs a google test executable and collects logs or dumps
as necessary.

.PARAMETER Path
    The path to the test executable.

.PARAMETER Kernel
    Runs for Windows kernel mode, given the path for binaries.

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
    Attaches the debugger to the process.

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
    Enables all basic Application Verifier checks on the test binary.

.Parameter EnableTcpipVerifier
    Enables TCPIP verifier in user mode tests.

.Parameter CodeCoverage
    Collects code coverage for this test run. Incompatible with -Debugger.

.Parameter AZP
    Runs in Azure Pipelines mode.

.Parameter ErrorsAsWarnings
    Treats all errors as warnings.

.PARAMETER DuoNic
    Uses DuoNic instead of loopback.

#>

param (
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [Parameter(Mandatory = $false)]
    [string]$Kernel = "",

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
    [ValidateSet("None", "Basic.Light", "Basic.Verbose", "Full.Light", "Full.Verbose")]
    [string]$LogProfile = "None",

    [Parameter(Mandatory = $false)]
    [switch]$CompressOutput = $false,

    [Parameter(Mandatory = $false)]
    [switch]$NoProgress = $false,

    [Parameter(Mandatory = $false)]
    [switch]$EnableAppVerifier = $false,

    [Parameter(Mandatory = $false)]
    [switch]$EnableTcpipVerifier = $false,

    [Parameter(Mandatory = $false)]
    [switch]$CodeCoverage = $false,

    [Parameter(Mandatory = $false)]
    [String]$PfxPath = "",

    [Parameter(Mandatory = $false)]
    [switch]$AZP = $false,

    [Parameter(Mandatory = $false)]
    [switch]$ErrorsAsWarnings = $false,

    [Parameter(Mandatory = $false)]
    [string]$ExtraArtifactDir = "",

    [Parameter(Mandatory = $false)]
    [switch]$DuoNic = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

function Test-Administrator
{
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

function Log($msg) {
    Write-Host "[$(Get-Date)] $msg"
}

function LogWrn($msg) {
    if ($AZP -and !$ErrorsAsWarnings) {
        Write-Host "##vso[task.LogIssue type=warning;][$(Get-Date)] $msg"
    } else {
        Write-Warning "[$(Get-Date)] $msg"
    }
}

function LogErr($msg) {
    if ($AZP -and !$ErrorsAsWarnings) {
        Write-Host "##vso[task.LogIssue type=error;][$(Get-Date)] $msg"
    } else {
        Write-Warning "[$(Get-Date)] $msg"
    }
}

# Make sure the test executable is present.
if (!(Test-Path $Path)) {
    Write-Error "$($Path) does not exist!"
}

# Validate the the kernel switch.
if ($Kernel -ne "" -and !$IsWindows) {
    Write-Error "-Kernel switch only supported on Windows";
}

# Validate the code coverage switch
if ($CodeCoverage) {
    if (!$IsWindows) {
        Write-Error "-CodeCoverage switch only supported on Windows";
    }
    if ($Debugger) {
        Write-Error "-CodeCoverage switch is not supported with debugging";
    }
    if ($Kernel -ne "") {
        Write-Error "-CodeCoverage is not supported for kernel mode tests";
    }
    if (!(Test-Path "C:\Program Files\OpenCppCoverage\OpenCppCoverage.exe")) {
        Write-Error "Code coverage tools are not installed";
    }
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Script for controlling loggings.
$LogScript = Join-Path $RootDir "scripts" "log.ps1"

# Executable name.
$TestExeName = Split-Path $Path -Leaf
$CoverageName = "$(Split-Path $Path -LeafBase).cov"

$ExeLogFolder = $TestExeName
if (![string]::IsNullOrWhiteSpace($ExtraArtifactDir)) {
    $ExeLogFolder += "_$ExtraArtifactDir"
}

# Folder for log files.
$LogDir = Join-Path $RootDir "artifacts" "logs" $ExeLogFolder (Get-Date -UFormat "%m.%d.%Y.%T").Replace(':','.')
New-Item -Path $LogDir -ItemType Directory -Force | Out-Null

# Folder for coverage files
$CoverageDir = $null
if ($CodeCoverage) {
    $CoverageDir = Join-Path $RootDir "artifacts" "coverage"
    New-Item -Path $CoverageDir -ItemType Directory -Force | Out-Null
}

# The file path of the final XML results.
$FinalResultsPath = "$($LogDir)-results.xml"

# Base XML results data.
$XmlResults = [xml]@"
<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="0" failures="0" disabled="0" errors="0" time="0" timestamp="date" name="AllTests">
</testsuites>
"@
$XmlResults.testsuites.timestamp = Get-Date -UFormat "%Y-%m-%dT%T"

# XML for creating new (failure) result data.
$FailXmlText = @"
<?xml version="1.0" encoding="UTF-8"?>
<testsuites tests="1" failures="1" disabled="0" errors="0" time="0" name="AllTests">
  <testsuite name="TestSuiteName" tests="1" failures="1" disabled="0" errors="0" timestamp="date" time="0" >
    <testcase name="TestCaseName" status="run" result="completed" time="0" timestamp="date" classname="TestSuiteName">
      <failure message="Application Crashed" type=""><![CDATA[Application Crashed]]></failure>
    </testcase>
  </testsuite>
</testsuites>
"@

# Global state for tracking if any crashes occurred.
$global:CrashedProcessCount = 0

# Path to the WER registry key used for collecting dumps.
$WerDumpRegPath = "HKLM:\Software\Microsoft\Windows\Windows Error Reporting\LocalDumps\$TestExeName"

# Helper script to build up a combined XML file for all test cases. This
# function just appends the given test case's xml output to the existing xml
# file. If not present (because of a crash) it generates one instead and appends
# it.
function Add-XmlResults($TestCase) {
    $TestHasResults = Test-Path $TestCase.ResultsPath
    $TestSuiteName = $TestCase.Name.Split(".")[0]
    $TestCaseName = $TestCase.Name.Split(".")[1]

    $NewXmlResults = $null
    if ($TestHasResults) {
        # Get the results from the test output.
        $NewXmlResults = [xml](Get-Content $TestCase.ResultsPath)
        Remove-Item $TestCase.ResultsPath -Force | Out-Null
    } else {
        # Generate our own results xml.
        $NewXmlText = $FailXmlText.Replace("TestSuiteName", $TestSuiteName)
        $NewXmlText = $NewXmlText.Replace("TestCaseName", $TestCaseName)
        $NewXmlText = $NewXmlText.Replace("date", $TestCase.Timestamp)
        $NewXmlResults = [xml]($NewXmlText)
    }

    $IsFailure = $NewXmlResults.testsuites.failures -eq 1
    $Time = $NewXmlResults.testsuites.testsuite.testcase.time -as [Decimal]

    $Node = $null
    if ($XmlResults.testsuites.tests -ne 0) {
        # Look for a matching test suite that might already exist.
        $Node = $XmlResults.testsuites.testsuite | Where-Object { $_.Name -eq $TestSuiteName }
    }
    if ($null -ne $Node) {
        # Already has a matching test suite. Add the test case to it.
        $Node.tests = ($Node.tests -as [Int]) + 1
        if ($IsFailure) {
            $Node.failures = ($Node.failures -as [Int]) + 1
        }
        $Node.time = ($Node.time -as [Decimal]) + $Time
        $NewNode = $XmlResults.ImportNode($NewXmlResults.testsuites.testsuite.testcase, $true)
        $Node.AppendChild($NewNode) | Out-Null
    } else {
        # First instance of this test suite. Add the test suite.
        $NewNode = $XmlResults.ImportNode($NewXmlResults.testsuites.testsuite, $true)
        $XmlResults.testsuites.AppendChild($NewNode) | Out-Null
    }

    # Update the top level test and failure counts.
    $XmlResults.testsuites.tests = ($XmlResults.testsuites.tests -as [Int]) + 1
    if ($IsFailure) {
        $XmlResults.testsuites.failures = ($XmlResults.testsuites.failures -as [Int]) + 1
    }
    $XmlResults.testsuites.time = ($XmlResults.testsuites.time -as [Decimal]) + $Time
}

# Asynchronously starts the test executable with the given arguments.
function Start-TestExecutable([String]$Arguments, [String]$OutputDir) {
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    if ($IsWindows) {
        if ($Debugger) {
            $pinfo.FileName = "windbg"
            if ($InitialBreak) {
                $pinfo.Arguments = "-G $($Path) $($Arguments)"
            } else {
                $pinfo.Arguments = "-g -G $($Path) $($Arguments)"
            }
        } elseif ($CodeCoverage) {
            $CoverageOutput = Join-Path $OutputDir $CoverageName
            $pinfo.FileName = "C:\Program Files\OpenCppCoverage\OpenCppCoverage.exe"
            $pinfo.Arguments = "--modules=$(Split-Path $Path -Parent) --cover_children --sources src\core --excluded_sources unittest --working_dir $($OutputDir) --export_type binary:$($CoverageOutput) -- $($Path) $($Arguments)"
            $pinfo.WorkingDirectory = $OutputDir
        } else {
            $pinfo.FileName = $Path
            $pinfo.Arguments = $Arguments
            if (Test-Administrator) {
                # Enable WER dump collection.
                New-ItemProperty -Path $WerDumpRegPath -Name DumpType -PropertyType DWord -Value 2 -Force | Out-Null
                New-ItemProperty -Path $WerDumpRegPath -Name DumpFolder -PropertyType ExpandString -Value $OutputDir -Force | Out-Null
            }
        }
    } else {
        if ($Debugger) {
            $pinfo.FileName = "gdb"
            if ($InitialBreak) {
                $pinfo.Arguments = "--args $($Path) $($Arguments)"
            } else {
                $pinfo.Arguments = "-ex=r --args $($Path) $($Arguments)"
            }
        } else {
            $pinfo.FileName = "bash"
            $pinfo.Arguments = "-c `"ulimit -c unlimited && LSAN_OPTIONS=report_objects=1 ASAN_OPTIONS=disable_coredump=0:abort_on_error=1 UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 $($Path) $($Arguments) && echo Done`""
            $pinfo.WorkingDirectory = $OutputDir
        }
    }
    if (!$Debugger) {
        $pinfo.RedirectStandardOutput = $true
        $pinfo.RedirectStandardError = $true
    }
    $pinfo.UseShellExecute = $false
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p
}

# Asynchronously starts a single msquictest test case running.
function Start-TestCase([String]$Name) {

    $InstanceName = $Name.Replace("/", "_")
    $LocalLogDir = Join-Path $LogDir $InstanceName
    mkdir $LocalLogDir | Out-Null

    if ($LogProfile -ne "None") {
        # Start the logs
        & $LogScript -Start -Profile $LogProfile | Out-Null
    }

    # Build up the argument list.
    $ResultsPath = Join-Path $LocalLogDir "results.xml"
    $Arguments = "--gtest_catch_exceptions=0 --gtest_filter=$($Name) --gtest_output=xml:$($ResultsPath)"
    if ($BreakOnFailure) {
        $Arguments += " --gtest_break_on_failure"
    }
    if ($Kernel -ne "") {
        $Arguments += " --kernelPriv"
    }
    if ($DuoNic) {
        $Arguments += " --duoNic"
    }
    if ($PfxPath -ne "") {
        $Arguments += " -PfxPath:$PfxPath"
    }

    # Start the test process and return some information about the test case.
    [pscustomobject]@{
        Name = $Name
        InstanceName = $InstanceName
        LogDir = $LocalLogDir
        Timestamp = (Get-Date -UFormat "%Y-%m-%dT%T")
        ResultsPath = $ResultsPath
        Process = (Start-TestExecutable $Arguments $LocalLogDir)
    }
}

# Asynchronously start all the msquictest test cases running.
function Start-AllTestCases {

    $Name = "all"
    $InstanceName = $Name

    if ($LogProfile -ne "None") {
        # Start the logs
        & $LogScript -Start -Profile $LogProfile | Out-Null
    }

    # Build up the argument list.
    $Arguments = "--gtest_catch_exceptions=0 --gtest_output=xml:$($FinalResultsPath)"
    if ($Filter -ne "") {
        $Arguments += " --gtest_filter=$($Filter)"
    }
    if ($BreakOnFailure) {
        $Arguments += " --gtest_break_on_failure"
    }
    if ($Kernel -ne "") {
        $Arguments += " --kernelPriv"
    }
    if ($DuoNic) {
        $Arguments += " --duoNic"
    }
    if ($PfxPath -ne "") {
        $Arguments += " -PfxPath:$PfxPath"
    }
    # Start the test process and return some information about the test case.
    [pscustomobject]@{
        Name = $Name
        InstanceName = $InstanceName
        LogDir = $LogDir
        Timestamp = (Get-Date -UFormat "%Y-%m-%dT%T")
        ResultsPath = $FinalResultsPath
        Process = (Start-TestExecutable $Arguments $LogDir)
    }
}

# Uses CDB.exe to print the crashing callstack in the dump file.
function PrintDumpCallStack($DumpFile) {
    $env:_NT_SYMBOL_PATH = Split-Path $Path
    try {
        if ($env:BUILD_BUILDNUMBER -ne $null) {
            $env:PATH += ";c:\Program Files (x86)\Windows Kits\10\Debuggers\x64"
        }
        $Output = cdb.exe -z $File -c "kn;q" | Join-String -Separator "`n"
        $Output = ($Output | Select-String -Pattern " # Child-SP(?s).*quit:").Matches[0].Groups[0].Value
        Write-Host "=================================================================================="
        Write-Host " $(Split-Path $DumpFile -Leaf)"
        Write-Host "=================================================================================="
        $Output -replace "quit:", "=================================================================================="
        $Output | Out-File "$DumpFile.txt"
    } catch {
        # Silently fail
    }
}

function PrintLldbCoreCallStack($CoreFile) {
    try {
        $Output = lldb $Path -c $CoreFile -b -o "`"bt all`""
        Write-Host "=================================================================================="
        Write-Host " $(Split-Path $CoreFile -Leaf)"
        Write-Host "=================================================================================="
        # Find line containing Current thread
        $Found = $false
        $LastThreadStart = 0
        for ($i = 0; $i -lt $Output.Length; $i++) {
            if ($Output[$i] -like "*stop reason =*") {
                if ($Found) {
                    break
                }
                $LastThreadStart = $i
            }
            if ($Output[$i] -like "*quic_bugcheck*") {
                $Found = $true
                for ($j = $LastThreadStart; $j -lt $i; $j++) {
                    $Output[$j]
                }
            }
            if ($Found) {
                $Output[$i]
            }
        }
        if (!$Found) {
            $Output | Join-String -Separator "`n"
        }
        $Output | Join-String -Separator "`n" | Out-File "$CoreFile.txt"
    } catch {
        # Silently Fail
    }
}

function PrintGdbCoreCallStack($CoreFile) {
    try {
        $Output = gdb $Path $CoreFile -batch -ex "`"bt`"" -ex "`"quit`""
        Write-Host "=================================================================================="
        Write-Host " $(Split-Path $CoreFile -Leaf)"
        Write-Host "=================================================================================="
        # Find line containing Current thread
        $Found = $false
        for ($i = 0; $i -lt $Output.Length; $i++) {
            if ($Output[$i] -like "*Current thread*") {
                $Found = $true
            }
            if ($Found) {
                $Output[$i]
            }
        }
        if (!$Found) {
            $Output | Join-String -Separator "`n"
        }
        $Output | Join-String -Separator "`n" | Out-File "$CoreFile.txt"
    } catch {
        # Silently Fail
    }
}

# Waits for the executable to finish and processes the results.
function Wait-TestCase($TestCase) {
    $ProcessCrashed = $false
    $AnyTestFailed = $false
    $StdOut = $null
    $StdOutTxt = $null
    $StdError = $null
    $StdErrorTxt = $null
    $IsReadingStreams = $false

    try {
        if (!$Debugger) {
            $IsReadingStreams = $true
            $StdOut = $TestCase.Process.StandardOutput.ReadToEndAsync()
            $StdError = $TestCase.Process.StandardError.ReadToEndAsync()
        }
        $TestCase.Process.WaitForExit()
        if ($TestCase.Process.ExitCode -ne 0) {
            Log "Process had nonzero exit code: $($TestCase.Process.ExitCode)"
            $ProcessCrashed = $true
        }
        if ($IsReadingStreams) {
            [System.Threading.Tasks.Task]::WaitAll(@($StdOut, $StdError))
            $StdOutTxt = $StdOut.Result
            $StdErrorTxt = $StdError.Result

            if (!$IsWindows -and !$ProcessCrashed) {
                $ProcessCrashed = $StdErrorTxt.Contains("Aborted")
            }
            $AnyTestFailed = $StdOutTxt.Contains("[  FAILED  ]")
            if (!(Test-Path $TestCase.ResultsPath) -and !$ProcessCrashed) {
                LogWrn "No test results generated! Treating as crash!"
                $ProcessCrashed = $true
            }
        }
        $DumpFiles = (Get-ChildItem $TestCase.LogDir) | Where-Object { $_.Extension -eq ".dmp" }
        if ($DumpFiles) {
            LogWrn "Dump file(s) generated"
            foreach ($File in $DumpFiles) {
                PrintDumpCallStack($File)
            }
            $ProcessCrashed = $true
        }
        $CoreFiles = (Get-ChildItem $TestCase.LogDir) | Where-Object { $_.Extension -eq ".core" }
        if ($CoreFiles) {
            LogWrn "Core file(s) generated"
            foreach ($File in $CoreFiles) {
                if ($IsMacOS) {
                    PrintLldbCoreCallStack $File
                } else {
                    PrintGdbCoreCallStack $File
                }
            }
            $ProcessCrashed = $true
        }
    } catch {
        LogWrn "Treating exception as crash!"
        $ProcessCrashed = $true
        throw
    } finally {
        # Add the current test case results.
        if ($IsolationMode -ne "Batch") {
            try { Add-XmlResults $TestCase } catch { }
        }

        if ($CodeCoverage) {
            $NewCoverage = Join-Path $TestCase.LogDir $Coveragename
            if ($IsolationMode -eq "Isolated") {
                # Merge coverage with previous runs
                $PreviousCoverage = Join-Path $CoverageDir $CoverageName
                if (!(Test-Path $PreviousCoverage)) {
                    # No previous coverage data, just copy
                    Copy-Item $NewCoverage $CoverageDir
                } else {
                    # Merge new coverage data with existing coverage data
                    # On a developer machine, this will always merge coverage until the dev deletes old coverage.
                    $TempMergedCoverage = Join-Path $CoverageDir "mergetemp.cov"
                    $CoverageExe = 'C:\"Program Files"\OpenCppCoverage\OpenCppCoverage.exe'
                    $CoverageMergeParams = " --input_coverage $($PreviousCoverage) --input_coverage $($NewCoverage) --export_type binary:$($TempMergedCoverage)"
                    Invoke-Expression ($CoverageExe + $CoverageMergeParams) | Out-Null
                    Move-Item $TempMergedCoverage $PreviousCoverage -Force
                }
            } else {
                # Copy the coverage to destination
                Copy-Item $NewCoverage $CoverageDir -Force
                # Copy coverage log
                $LogName = "LastCoverageResults-$(Split-Path $Path -LeafBase).log"
                Copy-Item (Join-Path $TestCase.LogDir "LastCoverageResults.log") (Join-Path $CoverageDir $LogName) -Force
            }
        }

        if ($ProcessCrashed) {
            $global:CrashedProcessCount++
        }

        if ($IsolationMode -eq "Batch") {
            if ($StdOutTxt) { Write-Host $StdOutTxt }
            if ($StdErrorTxt) { Write-Host $StdErrorTxt }
        } else {
            if ($AnyTestFailed -or $ProcessCrashed) {
                LogErr "$($TestCase.Name) failed:"
                if ($StdOutTxt) { Write-Host $StdOutTxt }
                if ($StdErrorTxt) { Write-Host $StdErrorTxt }
            } else {
                Log "$($TestCase.Name) succeeded"
            }
        }

        if ($KeepOutputOnSuccess -or $ProcessCrashed -or $AnyTestFailed) {

            if ($LogProfile -ne "None") {
                & $LogScript -Stop -OutputPath (Join-Path $TestCase.LogDir "quic")
            }

            if ($StdOutTxt) {
                $StdOutTxt > (Join-Path $TestCase.LogDir "stdout.txt")
            }

            if ($StdErrorTxt) {
                $StdErrorTxt > (Join-Path $TestCase.LogDir "stderr.txt")
            }

            if ($CompressOutput) {
                # Zip the output.
                CompressOutput-Archive -Path "$($TestCase.LogDir)\*" -DestinationPath "$($TestCase.LogDir).zip" | Out-Null
                Remove-Item $TestCase.LogDir -Recurse -Force | Out-Null
            }

        } else {
            if ($LogProfile -ne "None") {
                & $LogScript -Cancel | Out-Null
            }
            Remove-Item $TestCase.LogDir -Recurse -Force | Out-Null
        }
    }
}

# Runs the test executable to query all available test cases, parses the console
# output and returns a list of test case names.
function GetTestCases {
    $Arguments = " --gtest_list_tests"
    if ($Filter -ne "") {
        $Arguments = " --gtest_filter=$Filter --gtest_list_tests"
    }
    $stdout = Invoke-Expression ($Path + $Arguments)

    $Tests = New-Object System.Collections.ArrayList
    if ($null -ne $stdout) {
        $Lines = ($stdout.Split([Environment]::NewLine)) | Where-Object { $_.Length -ne 0 }
        $CurTestGroup = $null
        for ($i = 0; $i -lt $Lines.Length; $i++) {
            if (!($Lines[$i].StartsWith(" "))) {
                $CurTestGroup = $Lines[$i]
            } else {
                $Tests.Add($CurTestGroup + $Lines[$i].Split("#")[0].Trim()) | Out-Null
            }
        }
    }
    $Tests.ToArray()
}

function Get-WindowsKitTool {
    param (
        [string]$Arch = "x86",
        [Parameter(Mandatory = $true)]
        [string]$Tool
    )

    $KitBinRoot = "C:\Program Files (x86)\Windows Kits\10\bin"
    if (!(Test-Path $KitBinRoot)) {
        Write-Error "Windows Kit Binary Folder not Found"
        return ""
    }

    $FoundToolPath = $null
    $FoundToolVersion = "0"

    $Subfolders = Get-ChildItem -Path $KitBinRoot -Directory
    foreach ($Subfolder in $Subfolders) {
        $ToolPath = Join-Path $Subfolder "$Arch\$Tool"
        if (Test-Path $ToolPath) {
            $KitVersion = $Subfolder.Name

            if ($KitVersion -gt $FoundToolVersion) {
                $FoundToolVersion = $KitVersion
                $FoundToolPath = $ToolPath
            }
        }
    }

    if ($null -ne $FoundToolPath) {
        return $FoundToolPath
    }
    Write-Error "Failed to find tool"
    return $null
}

##############################################################
#                     Main Execution                         #
##############################################################

# Query all the test cases.
$TestCases = GetTestCases
if ($null -eq $TestCases) {
    Log "$Path (Skipped)"
    exit
}

$TestCount = ($TestCases -as [String[]]).Length

Log "$Path ($TestCount test case(s))"

if ($ListTestCases) {
    # List the tst cases.
    $TestCases
    exit
}

# Cancel any outstanding logs that might be leftover.
& $LogScript -Cancel | Out-Null

# Initialize WER dump registry key if necessary.
if ($IsWindows -and !(Test-Path $WerDumpRegPath) -and (Test-Administrator)) {
    New-Item -Path $WerDumpRegPath -Force | Out-Null
}

# Initialize application verifier (Windows only).
if ($IsWindows -and $EnableAppVerifier) {
    where.exe appverif.exe
    if ($LastExitCode -eq 0) {
        appverif.exe /verify $Path
    } else {
        Write-Warning "Application Verifier not installed!"
        $EnableAppVerifier = $false;
    }
}

# Install the kernel mode drivers.
if ($Kernel -ne "") {
    if ($null -ne (Get-Service -Name "msquicpriv" -ErrorAction Ignore)) {
        try {
            net.exe stop msquicpriv /y | Out-Null
        }
        catch {}
        sc.exe delete msquicpriv /y | Out-Null
    }
    if ($null -ne (Get-Service -Name "msquictestpriv" -ErrorAction Ignore)) {
        try {
            net.exe stop msquictestpriv /y | Out-Null
        }
        catch {}
        sc.exe delete msquictestpriv /y | Out-Null
    }
    Copy-Item (Join-Path $Kernel "msquictestpriv.sys") (Split-Path $Path -Parent)
    Copy-Item (Join-Path $Kernel "msquicpriv.sys") (Split-Path $Path -Parent)

    $SignTool = Get-WindowsKitTool -Tool "signtool.exe"

    if (Test-Path c:\CodeSign.pfx) {
        & $SignTool sign /f C:\CodeSign.pfx -p "placeholder" /fd SHA256 /tr http://timestamp.digicert.com /td SHA256  (Join-Path (Split-Path $Path -Parent) "msquicpriv.sys")
        & $SignTool sign /f C:\CodeSign.pfx -p "placeholder" /fd SHA256 /tr http://timestamp.digicert.com /td SHA256  (Join-Path (Split-Path $Path -Parent) "msquictestpriv.sys")
    }
    sc.exe create "msquicpriv" type= kernel binpath= (Join-Path (Split-Path $Path -Parent) "msquicpriv.sys") start= demand | Out-Null
    if ($LastExitCode) {
        Log ("sc.exe " + $LastExitCode)
    }
    verifier.exe /volatile /adddriver msquicpriv.sys msquictestpriv.sys /flags 0x9BB
    if ($LastExitCode) {
        Log ("verifier.exe " + $LastExitCode)
    }
    net.exe start msquicpriv
    if ($LastExitCode) {
        Log ("net.exe " + $LastExitCode)
    }
}

if ($IsWindows -and ($EnableTcpipVerifier -or $Kernel)) {
    verifier.exe /volatile /adddriver afd.sys netio.sys tcpip.sys /flags 0x9BB
    if ($LastExitCode) {
        Log ("verifier.exe " + $LastExitCode)
    }
}

try {
    if ($IsolationMode -eq "Batch") {
        # Run the the test process once for all tests.
        Wait-TestCase (Start-AllTestCases)
    } else {
        # Run the test cases individually.
        for ($i = 0; $i -lt $TestCount; $i++) {
            Wait-TestCase (Start-TestCase ($TestCases -as [String[]])[$i])
            if (!$NoProgress) {
                Write-Progress -Activity "Running tests" -Status "Progress:" -PercentComplete ($i/$TestCount*100)
            }
        }
    }
} catch {
    Log "Exception Thrown"
    Log $_
    Get-Error
    $_ | Format-List *
} finally {
    if ($LogProfile -ne "None") {
        & $LogScript -Cancel | Out-Null
    }

    if ($IsWindows) {
        # Cleanup the WER registry.
        if (Test-Administrator) {
            Remove-Item -Path $WerDumpRegPath -Force | Out-Null
        }
        # Turn off App Verifier
        if ($EnableAppVerifier) {
            appverif.exe -disable * -for $Path
        }
    }

    if ($IsolationMode -eq "Batch") {
        if (Test-Path $FinalResultsPath) {
            $XmlResults = [xml](Get-Content $FinalResultsPath)
            if (!$GenerateXmlResults) {
                # Delete the XML results file since it's not needed.
                Remove-Item $FinalResultsPath -Force | Out-Null
            }
        } else {
            # No results file means the tests crashed most likely.
            $NewXmlText = $FailXmlText.Replace("TestSuiteName", "all")
            $NewXmlText = $NewXmlText.Replace("TestCaseName", "all")
            $NewXmlText = $NewXmlText.Replace("date", $XmlResults.testsuites.timestamp)
            $XmlResults = [xml]($NewXmlText)
            if ($GenerateXmlResults) {
                # Save the xml results.
                $XmlResults.Save($FinalResultsPath) | Out-Null
            }
        }
    } else {
        if ($GenerateXmlResults) {
            # Save the xml results.
            $XmlResults.Save($FinalResultsPath) | Out-Null
        }
    }

    $TestCount = $XmlResults.testsuites.tests -as [Int]
    $TestsFailed = $XmlResults.testsuites.failures -as [Int]

    # Uninstall the kernel mode test driver and revert the msquic driver.
    if ($Kernel -ne "") {
        net.exe stop msquicpriv /y | Out-Null
        sc.exe delete msquictestpriv | Out-Null
        sc.exe delete msquicpriv | Out-Null
        verifier.exe /volatile /removedriver msquicpriv.sys msquictestpriv.sys
        verifier.exe /volatile /flags 0x0
    }

    if ($IsWindows -and ($EnableTcpipVerifier -or $Kernel)) {
        verifier.exe /volatile /removedriver afd.sys netio.sys tcpip.sys
        verifier.exe /volatile /flags 0x0
    }

    # Print out the results.
    Log "$($TestCount) test(s) run."
    if ($KeepOutputOnSuccess -or ($TestsFailed -ne 0) -or ($global:CrashedProcessCount -ne 0)) {
        Log "Output can be found in $($LogDir)"
        if ($ErrorsAsWarnings) {
            Write-Warning "$($TestsFailed) test(s) failed."
            Write-Warning "$($TestsFailed) test(s) failed, $($global:CrashedProcessCount) test(s) crashed."
        } else {
            Write-Error "$($TestsFailed) test(s) failed, $($global:CrashedProcessCount) test(s) crashed."
            $LastExitCode = 1
        }
    } elseif ($AZP -and $TestCount -eq 0) {
        Write-Error "Failed to run any tests."
    } else {
        if (Test-Path $LogDir) {
            Remove-Item $LogDir -Recurse -Force | Out-Null
        }
    }
}
