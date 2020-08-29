<#

.SYNOPSIS
This script runs a google test executable and collects and logs or process dumps
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

.PARAMETER ExecutionMode
    Controls the execution mode when running each test case.

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

.Parameter CodeCoverage
    Collects code coverage for this test run. Incompatible with -Debugger.

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
    [ValidateSet("Serial", "Parallel")]
    [string]$ExecutionMode = "Serial",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Batch", "Isolated")]
    [string]$IsolationMode = "Batch",

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
    [switch]$CodeCoverage = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

function Log($msg) {
    Write-Host "[$(Get-Date)] $msg"
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

# Folder for log files.
$LogDir = Join-Path $RootDir "artifacts" "logs" $TestExeName (Get-Date -UFormat "%m.%d.%Y.%T").Replace(':','.')
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
$AnyProcessCrashes = $false

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
            # Enable WER dump collection.
            New-ItemProperty -Path $WerDumpRegPath -Name DumpType -PropertyType DWord -Value 2 -Force | Out-Null
            New-ItemProperty -Path $WerDumpRegPath -Name DumpFolder -PropertyType ExpandString -Value $OutputDir -Force | Out-Null
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
            $pinfo.Arguments = "-c `"ulimit -c unlimited && $($Path) $($Arguments) && echo Done`""
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
        $Arguments += " --kernel --privateLibrary"
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
        $Arguments += " --kernel --privateLibrary"
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
    } catch {
        # Silently fail
    }
}

# Waits for the executable to finish and processes the results.
function Wait-TestCase($TestCase) {
    $stdout = $null
    $stderr = $null
    $ProcessCrashed = $false
    $AnyTestFailed = $false

    try {
        if (!$Debugger) {
            $stdout = $TestCase.Process.StandardOutput.ReadToEnd()
            $stderr = $TestCase.Process.StandardError.ReadToEnd()
            if (!$isWindows) {
                $ProcessCrashed = $stderr.Contains("Aborted")
            }
            $AnyTestFailed = $stdout.Contains("[  FAILED  ]")
            if (!(Test-Path $TestCase.ResultsPath) -and !$ProcessCrashed) {
                Log "No test results generated! Treating as crash!"
                $ProcessCrashed = $true
            }
        }
        $TestCase.Process.WaitForExit()
        if ($TestCase.Process.ExitCode -ne 0) {
            Log "Process had nonzero exit code: $($TestCase.Process.ExitCode)"
            $ProcessCrashed = $true
        }
        $DumpFiles = (Get-ChildItem $TestCase.LogDir) | Where-Object { $_.Extension -eq ".dmp" }
        if ($DumpFiles) {
            Log "Dump file(s) generated"
            foreach ($File in $DumpFiles) {
                PrintDumpCallStack($File)
            }
            $ProcessCrashed = $true
        }
    } catch {
        Log "Treating exception as crash!"
        $ProcessCrashed = $true
        throw
    } finally {
        # Add the current test case results.
        if ($IsolationMode -ne "Batch") {
            Add-XmlResults $TestCase
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
            $AnyProcessCrashes = $true;
        }

        if ($IsolationMode -eq "Batch") {
            if ($stdout) { Write-Host $stdout }
            if ($stderr) { Write-Host $stderr }
        } else {
            if ($AnyTestFailed -or $ProcessCrashed) {
                Log "$($TestCase.Name) failed:"
                if ($stdout) { Write-Host $stdout }
                if ($stderr) { Write-Host $stderr }
            } else {
                Log "$($TestCase.Name) succeeded"
            }
        }

        if ($KeepOutputOnSuccess -or $ProcessCrashed -or $AnyTestFailed) {

            if ($LogProfile -ne "None") {
                & $LogScript -Stop -OutputDirectory $TestCase.LogDir
            }

            if ($stdout) {
                $stdout > (Join-Path $TestCase.LogDir "stdout.txt")
            }

            if ($stderr) {
                $stderr > (Join-Path $TestCase.LogDir "stderr.txt")
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

# Debugger doesn't work for parallel right now.
if ($Debugger -and $ExecutionMode -eq "Parallel") {
    Log "Warning: Disabling parallel execution for debugger runs!"
    $ExecutionMode = "IsolatedSerial"
}

# Parallel execution doesn't work well. Warn.
if ($ExecutionMode -eq "Parallel") {
    Log "Warning: Parallel execution doesn't work very well"
}

# Initialize WER dump registry key if necessary.
if ($IsWindows -and !(Test-Path $WerDumpRegPath)) {
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
    sc.exe create "msquicpriv" type= kernel binpath= (Join-Path (Split-Path $Path -Parent) "msquicpriv.sys") start= demand | Out-Null
    verifier.exe /volatile /adddriver afd.sys msquicpriv.sys msquictestpriv.sys netio.sys tcpip.sys /flags 0x9BB
    net.exe start msquicpriv
}

try {
    if ($IsolationMode -eq "Batch") {
        # Batch/Parallel is an unsupported combination.
        if ($ExecutionMode -eq "Parallel") {
            Log "Warning: Disabling parallel execution for batch runs!"
            $ExecutionMode = "IsolatedSerial"
        }

        # Run the the test process once for all tests.
        Wait-TestCase (Start-AllTestCases)

    } else {
        if ($ExecutionMode -eq "Serial") {
            # Run the test cases serially.
            for ($i = 0; $i -lt $TestCount; $i++) {
                Wait-TestCase (Start-TestCase ($TestCases -as [String[]])[$i])
                if (!$NoProgress) {
                    Write-Progress -Activity "Running tests" -Status "Progress:" -PercentComplete ($i/$TestCount*100)
                }
            }

        } else {
            # Log collection doesn't work for parallel right now.
            if ($LogProfile -ne "None") {
                Log "Warning: Disabling log collection for parallel runs!"
                $LogProfile = "None"
            }

            # Starting the test cases all in parallel.
            $Runs = New-Object System.Collections.ArrayList
            for ($i = 0; $i -lt $TestCount; $i++) {
                $Runs.Add((Start-TestCase ($TestCases -as [String[]]))) | Out-Null
                if (!$NoProgress) {
                    Write-Progress -Activity "Starting tests" -Status "Progress:" -PercentComplete ($i/$TestCount*100)
                }
                Start-Sleep -Milliseconds 1
            }

            # Wait for the test cases to complete.
            Log "Waiting for all test cases to complete..."
            for ($i = 0; $i -lt $Runs.Count; $i++) {
                Wait-TestCase $Runs[$i]
                if (!$NoProgress) {
                    Write-Progress -Activity "Finishing tests" -Status "Progress:" -PercentComplete ($i/$TestCount*100)
                }
            }
        }
    }
} finally {
    if ($LogProfile -ne "None") {
        & $LogScript -Cancel | Out-Null
    }

    if ($isWindows) {
        # Cleanup the WER registry.
        Remove-Item -Path $WerDumpRegPath -Force | Out-Null
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

    # Print out the results.
    Log "$($TestCount) test(s) run. $($TestsFailed) test(s) failed."
    if ($KeepOutputOnSuccess -or ($TestsFailed -ne 0) -or $AnyProcessCrashes) {
        Log "Output can be found in $($LogDir)"
    } else {
        if (Test-Path $LogDir) {
            Remove-Item $LogDir -Recurse -Force | Out-Null
        }
    }
    Write-Host ""

    # Uninstall the kernel mode test driver and revert the msquic driver.
    if ($Kernel -ne "") {
        net.exe stop msquicpriv /y | Out-Null
        sc.exe delete msquictestpriv | Out-Null
        sc.exe delete msquicpriv | Out-Null
        verifier.exe /volatile /removedriver afd.sys msquicpriv.sys msquictestpriv.sys netio.sys tcpip.sys
        verifier.exe /volatile /flags 0x0
    }
}
