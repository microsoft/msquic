<#

.SYNOPSIS
This script provides helpers for running executing the MsQuic tests.

.PARAMETER Config
    Specifies the build configuration to test.

.PARAMETER ListTestCases
    Lists all the test cases.

.PARAMETER Parallel
    Runs the test cases in parallel instead of serially. Log collection not currently supported.

.PARAMETER Compress
    Compresses the output files generated for failed test cases.

.PARAMETER LogProfile
    The name of the profile to use for log collection.

.PARAMETER Filter
    A filter to include test cases from the list to execute.

.PARAMETER NegativeFilter
    A filter to remove test cases from the list to execute.

.PARAMETER Debugger
    Attaches the debugger to each test case run.

.EXAMPLE
    test.ps1

.EXAMPLE
    test.ps1 -ListTestCases

.EXAMPLE
    test.ps1 -ListTestCases -Filter ParameterValidation*

.EXAMPLE
    test.ps1 -Filter ParameterValidation*

.EXAMPLE
    test.ps1 -LogProfile Full.Basic

.EXAMPLE
    test.ps1 -Parallel -NegativeFilter *Send*

.EXAMPLE
    test.ps1 -LogProfile Full.Verbose -Compress

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [switch]$ListTestCases = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Parallel = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Compress = $false,

    [Parameter(Mandatory = $false)]
    [ValidateSet("None", "Basic.Light", "Basic.Verbose", "Full.Light", "Full.Verbose")]
    [string]$LogProfile = "None",

    [Parameter(Mandatory = $false)]
    [string]$Filter = "",

    [Parameter(Mandatory = $false)]
    [string]$NegativeFilter = "",

    [Parameter(Mandatory = $false)]
    [switch]$Debugger = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Current directory.
$CurrentDir = (Get-Item -Path ".\").FullName

# Path for the test program.
$MsQuicTest = $CurrentDir + "\artifacts\windows\bin\$($Config)\msquictest.exe"
if (!$IsWindows) {
    $MsQuicTest = $CurrentDir + "/artifacts/linux/bin/msquictest"
}

# Path for the procdump executable.
$ProcDumpExe = $CurrentDir + "\bld\windows\procdump\procdump64.exe"

# Folder for log files.
$LogBaseDir = Join-Path (Join-Path $CurrentDir "artifacts") "logs"
$LogDir = Join-Path $LogBaseDir (Get-Date -UFormat "%m.%d.%Y.%T").Replace(':','.')

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
        $NewXmlText =  $FailXmlText.Replace("TestSuiteName", $TestSuiteName)
        $NewXmlText =  $NewXmlText.Replace("TestCaseName", $TestCaseName)
        $NewXmlText =  $NewXmlText.Replace("date", $TestCase.Timestamp)
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

function Log($msg) {
    Write-Host "[$(Get-Date)] $msg"
}

# Starts msquictext with the given arguments, asynchronously.
function Start-MsQuicTest([String]$Arguments, [String]$OutputDir) {
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    if ($IsWindows) {
        if ($Debugger) {
            $pinfo.FileName = "windbg"
            $pinfo.Arguments = "-g -G $($MsQuicTest) $($Arguments)"
        } else {
            $pinfo.FileName = $ProcDumpExe
            $pinfo.Arguments = "-ma -e -b -l -accepteula -x $($OutputDir) $($MsQuicTest) $($Arguments)"
        }
    } else {
        if ($Debugger) {
            $pinfo.FileName = "gdb"
            $pinfo.Arguments = "--args $MsQuicTest $Arguments"
        } else {
            $pinfo.FileName = $MsQuicTest
            $pinfo.Arguments = $Arguments
            $pinfo.WorkingDirectory = $OutputDir
        }
    }
    if (!$Debugger) {
        $pinfo.RedirectStandardOutput = $true
    }
    $pinfo.UseShellExecute = $false
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p
}

# Executes msquictest to query all available test cases, parses the console
# output and returns a list of test case names.
function GetTestCases {
    $stdout = & $MsQuicTest "--gtest_list_tests"
    $Lines = ($stdout.Split([Environment]::NewLine)) | Where-Object { $_.Length -ne 0 }
    $CurTestGroup = $null
    $Tests = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $Lines.Length; $i++) {
        if (!($Lines[$i].StartsWith(" "))) {
            $CurTestGroup = $Lines[$i]
        } else {
            $Tests.Add($CurTestGroup + $Lines[$i].Split("#")[0].Trim()) | Out-Null
        }
    }
    $Tests.ToArray()
}

# Starts a single msquictest test case running.
function StartTestCase([String]$Name) {

    $InstanceName = $Name.Replace("/", "_")
    $LocalLogDir = Join-Path $LogDir $InstanceName
    mkdir $LocalLogDir | Out-Null

    if ($LogProfile -ne "None") {
        # Start the logs
        .\log.ps1 -Start -LogProfile $LogProfile -InstanceName $InstanceName | Out-Null
    }

    $ResultsPath = Join-Path $LocalLogDir "results.xml"
    $Arguments = "--gtest_break_on_failure --gtest_filter=$($Name) --gtest_output=xml:$($ResultsPath)"

    # Start the test process and return some information about the test case.
    [pscustomobject]@{
        Name = $Name
        InstanceName = $InstanceName
        LogDir = $LocalLogDir
        Timestamp = (Get-Date -UFormat "%Y-%m-%dT%T")
        ResultsPath = $ResultsPath
        Process = (Start-MsQuicTest $Arguments $LocalLogDir)
    }
}

# Waits for and finishes up the test case.
function FinishTestCase($TestCase) {
    $stdout = $null
    if (!$Debugger) {
        $stdout = $TestCase.Process.StandardOutput.ReadToEnd()
    }
    $TestCase.Process.WaitForExit()

    # Add the current test case results.
    Add-XmlResults $TestCase

    if ($Debugger -or $stdout.Contains("[  PASSED  ] 1 test")) {
        if ($LogProfile -ne "None") {
            # Don't keep logs on success.
            .\log.ps1 -Cancel -InstanceName $TestCase.InstanceName | Out-Null
        }
        Remove-Item $TestCase.LogDir -Recurse -Force | Out-Null
    } else {
        if ($LogProfile -ne "None") {
            # Keep logs on failure.
            .\log.ps1 -Stop -OutputDirectory $TestCase.LogDir -InstanceName $TestCase.InstanceName | Out-Null
        }

        $stdout > (Join-Path $TestCase.LogDir "console.txt")

        if ($Compress) {
            # Zip the output.
            Compress-Archive -Path "$($TestCase.LogDir)\*" -DestinationPath "$($TestCase.LogDir).zip" | Out-Null
            Remove-Item $TestCase.LogDir -Recurse -Force | Out-Null
        }
    }
}

# Runs a test case synchronously.
function RunTestCase([String]$Name) {
    FinishTestCase (StartTestCase $Name)
}

##############################################################
#                     Main Execution                         #
##############################################################

# Make sure the executable is present for the current configuration.
if (!(Test-Path $MsQuicTest)) { Write-Error "$($MsQuicTest) does not exist!" }
if (!(Test-Path $ProcDumpExe)) { Write-Error "$($ProcDumpExe) does not exist!" }

# Query all the test cases.
$TestCases = GetTestCases

# Apply any filtering.
if ($Filter -ne "") {
    $TestCases = ($TestCases | Where-Object { $_ -Like $Filter }) -as [String[]]
}
if ($NegativeFilter -ne "") {
    $TestCases = ($TestCases | Where-Object { !($_ -Like $NegativeFilter) }) -as [String[]]
}
if ($null -eq $TestCases) {
    Log "No test cases found."
    exit
}

if ($ListTestCases) {
    # List the tst cases.
    $TestCases
    exit
}

# Set up the base directory.
if (!(Test-Path $LogBaseDir)) { mkdir $LogBaseDir | Out-Null }
mkdir $LogDir | Out-Null

# Log collection doesn't work for parallel right now.
if ($Debugger -and $Parallel) {
    Log "Warning: Disabling parallel for debugger runs!"
    $Parallel = $false
}

try {
    if ($Parallel -eq $false) {
        # Run the test cases serially.
        Log "Executing $($TestCases.Length) tests in series..."
        for ($i = 0; $i -lt $TestCases.Length; $i++) {
            RunTestCase $TestCases[$i]
            Write-Progress -Activity "Running tests" -Status "Progress:" -PercentComplete ($i/$TestCases.Length*100)
        }

    } else {
        # Log collection doesn't work for parallel right now.
        if ($LogProfile -ne "None") {
            Log "Warning: Disabling log collection for parallel runs!"
            $LogProfile = "None"
        }

        # Starting the test cases all in parallel.
        Log "Starting $($TestCases.Length) tests in parallel..."
        $Runs = New-Object System.Collections.ArrayList
        for ($i = 0; $i -lt $TestCases.Length; $i++) {
            $Runs.Add((StartTestCase $TestCases[$i])) | Out-Null
            Write-Progress -Activity "Starting tests" -Status "Progress:" -PercentComplete ($i/$TestCases.Length*100)
            Start-Sleep -Milliseconds 1
        }

        # Wait for the test cases to complete.
        Log "Waiting for test cases to complete..."
        for ($i = 0; $i -lt $Runs.Count; $i++) {
            FinishTestCase $Runs[$i]
            Write-Progress -Activity "Finishing tests" -Status "Progress:" -PercentComplete ($i/$TestCases.Length*100)
        }
    }
} finally {
    # Save the xml results.
    $XmlResults.Save("$($LogDir).xml") | Out-Null

    $TestCount = $XmlResults.testsuites.tests -as [Int]
    $TestsFailed = $XmlResults.testsuites.failures -as [Int]

    # Print out the results.
    Log "$($TestCount) test(s) run. $($TestsFailed) test(s) failed."
    if ($TestsFailed -ne 0) {
        Log "Logs can be found in $($LogDir)"
    } else {
        Remove-Item $LogDir -Recurse -Force | Out-Null
    }
}
