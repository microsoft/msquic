<#

.SYNOPSIS
This script runs a google test executable and collects and logs or process dumps
as necessary.

.PARAMETER Path
    The path to the test executable.

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

.PARAMETER ConvertLogs
    Convert any collected logs to text. Only works when LogProfile is set.

.PARAMETER CompressOutput
    Compresses the output files generated for failed test cases.

.PARAMETER NoProgress
    Disables the progress bar.

#>

param (
    [Parameter(Mandatory = $true)]
    [string]$Path,

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
    [switch]$ConvertLogs = $false,

    [Parameter(Mandatory = $false)]
    [switch]$CompressOutput = $false,

    [Parameter(Mandatory = $false)]
    [switch]$NoProgress = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

function Log($msg) {
    Write-Host "[$(Get-Date)] $msg"
}

# Make sure the test executable is present.
if (!(Test-Path $Path)) {
    Write-Error "[$(Get-Date)] $($Path) does not exist!"
}

# Root directory of the project.
$RootDir = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent

# Script for controlling loggings.
$LogScript = Join-Path $RootDir "scripts" "log.ps1"

# Executable name.
$TestExeName = Split-Path $Path -Leaf

# Folder for log files.
$LogDir = Join-Path $RootDir "artifacts" "logs" $TestExeName (Get-Date -UFormat "%m.%d.%Y.%T").Replace(':','.')
New-Item -Path $LogDir -ItemType Directory -Force | Out-Null

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
        } else {
            $pinfo.FileName = $RootDir + "\bld\windows\procdump\procdump64.exe"
            $pinfo.Arguments = "-ma -e -b -l -accepteula -x $($OutputDir) $($Path) $($Arguments)"
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
        & $LogScript -Start -LogProfile $LogProfile -InstanceName $InstanceName | Out-Null
    }

    # Build up the argument list.
    $ResultsPath = Join-Path $LocalLogDir "results.xml"
    $Arguments = "--gtest_catch_exceptions=0 --gtest_filter=$($Name) --gtest_output=xml:$($ResultsPath)"
    if ($BreakOnFailure) {
        $Arguments = $Arguments + " --gtest_break_on_failure"
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
        & $LogScript -Start -LogProfile $LogProfile -InstanceName $InstanceName | Out-Null
    }

    # Build up the argument list.
    $Arguments = "--gtest_catch_exceptions=0 --gtest_output=xml:$($FinalResultsPath)"
    if ($Filter -ne "") {
        $Arguments = $Arguments + " --gtest_filter=$($Filter)"
    }
    if ($BreakOnFailure) {
        $Arguments = $Arguments + " --gtest_break_on_failure"
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
            if ($isWindows) {
                $ProcessCrashed = $stdout.Contains("Dump 1 complete")
            } else {
                $ProcessCrashed = $stderr.Contains("Aborted")
            }
            $AnyTestFailed = $stdout.Contains("[  FAILED  ]")
            if (!(Test-Path $TestCase.ResultsPath) -and !$ProcessCrashed) {
                Log "No test results generated! Treating as crash!"
                $ProcessCrashed = $true
            }
        }
        $TestCase.Process.WaitForExit()
    } catch {
        Log "Treating exception as crash!"
        $ProcessCrashed = $true
        throw
    } finally {
        # Add the current test case results.
        if ($IsolationMode -ne "Batch") {
            Add-XmlResults $TestCase
        }

        if ($ProcessCrashed) {
            $AnyProcessCrashes = $true;
        }

        if ($IsolationMode -eq "Batch") {
            if ($null -ne $stdout -and "" -ne $stdout) {
                Write-Host $stdout
            }
            if ($null -ne $stderr -and "" -ne $stderr) {
                Write-Host $stderr
            }
        } else {
            if ($AnyTestFailed -or $ProcessCrashed) {
                Log "$($TestCase.Name) failed"
            } else {
                Log "$($TestCase.Name) succeeded"
            }
        }

        if ($KeepOutputOnSuccess -or $ProcessCrashed -or $AnyTestFailed) {

            if ($LogProfile -ne "None") {
                if ($ConvertLogs) {
                    & $LogScript -Stop -OutputDirectory $TestCase.LogDir -InstanceName $TestCase.InstanceName -ConvertToText
                } else {
                    & $LogScript -Stop -OutputDirectory $TestCase.LogDir -InstanceName $TestCase.InstanceName | Out-Null
                }
            }

            if ($null -ne $stdout -and "" -ne $stdout) {
                $stdout > (Join-Path $TestCase.LogDir "stdout.txt")
            }

            if ($null -ne $stderr -and "" -ne $stderr) {
                $stderr > (Join-Path $TestCase.LogDir "stderr.txt")
            }

            if ($CompressOutput) {
                # Zip the output.
                CompressOutput-Archive -Path "$($TestCase.LogDir)\*" -DestinationPath "$($TestCase.LogDir).zip" | Out-Null
                Remove-Item $TestCase.LogDir -Recurse -Force | Out-Null
            }

        } else {
            if ($LogProfile -ne "None") {
                & $LogScript -Cancel -InstanceName $TestCase.InstanceName | Out-Null
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
    Log "No test cases found."
    exit
}

$TestCount = ($TestCases -as [String[]]).Length

if ($ListTestCases) {
    # List the tst cases.
    $TestCases
    exit
}

# Log collection doesn't work for parallel right now.
if ($Debugger -and $ExecutionMode -eq "Parallel") {
    Log "Warning: Disabling parallel execution for debugger runs!"
    $ExecutionMode = "IsolatedSerial"
}

try {
    if ($IsolationMode -eq "Batch") {
        # Batch/Parallel is an unsupported combination.
        if ($ExecutionMode -eq "Parallel") {
            Log "Warning: Disabling parallel execution for batch runs!"
            $ExecutionMode = "IsolatedSerial"
        }

        # Run the the test process once for all tests.
        Log "Executing $TestCount test(s) in batch..."
        Wait-TestCase (Start-AllTestCases)

    } else {
        if ($ExecutionMode -eq "Serial") {
            # Run the test cases serially.
            Log "Executing $TestCount test(s) in series..."
            for ($i = 0; $i -lt $TestCases.Length; $i++) {
                Wait-TestCase (Start-TestCase $TestCases[$i])
                if (!$NoProgress) {
                    Write-Progress -Activity "Running tests" -Status "Progress:" -PercentComplete ($i/$TestCases.Length*100)
                }
            }

        } else {
            # Log collection doesn't work for parallel right now.
            if ($LogProfile -ne "None") {
                Log "Warning: Disabling log collection for parallel runs!"
                $LogProfile = "None"
            }

            # Starting the test cases all in parallel.
            Log "Starting $TestCount test(s) in parallel..."
            $Runs = New-Object System.Collections.ArrayList
            for ($i = 0; $i -lt $TestCases.Length; $i++) {
                $Runs.Add((Start-TestCase $TestCases[$i])) | Out-Null
                if (!$NoProgress) {
                    Write-Progress -Activity "Starting tests" -Status "Progress:" -PercentComplete ($i/$TestCases.Length*100)
                }
                Start-Sleep -Milliseconds 1
            }

            # Wait for the test cases to complete.
            Log "Waiting for test cases to complete..."
            for ($i = 0; $i -lt $Runs.Count; $i++) {
                Wait-TestCase $Runs[$i]
                if (!$NoProgress) {
                    Write-Progress -Activity "Finishing tests" -Status "Progress:" -PercentComplete ($i/$TestCases.Length*100)
                }
            }
        }
    }
} finally {
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
}
