<#

.SYNOPSIS
This script provides helpers for running executing the MsQuic tests.

.PARAMETER Config
    Specifies the build configuration to test.

.PARAMETER ListTestCases
    Lists all the test cases.

.PARAMETER Serial
    Runs the test cases serially instead of in parallel. Required for log collection.

.PARAMETER Compress
    Compresses the output files generated for failed test cases.

.PARAMETER LogProfile
    The name of the profile to use for log collection.

.PARAMETER Filter
    A filter to include test cases from the list to execute.

.PARAMETER NegativeFilter
    A filter to remove test cases from the list to execute.

.EXAMPLE
    test.ps1

.EXAMPLE
    test.ps1 -ListTestCases

.EXAMPLE
    test.ps1 -ListTestCases -Filter ParameterValidation*

.EXAMPLE
    test.ps1 -Filter ParameterValidation*

.EXAMPLE
    test.ps1 -Serial - LogProfile Full.Basic

.EXAMPLE
    test.ps1 -Compress

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [switch]$ListTestCases = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Serial = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Compress = $false,

    [Parameter(Mandatory = $false)]
    [ValidateSet("None", "Basic.Light", "Basic.Verbose", "Full.Light", "Full.Verbose")]
    [string]$LogProfile = "None",

    [Parameter(Mandatory = $false)]
    [string]$Filter = "",

    [Parameter(Mandatory = $false)]
    [string]$NegativeFilter = ""
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Helper to determine if we're running on Windows.
#$IsWindows = $Env:OS -eq "Windows_NT"

# Current directory.
$CurrentDir = (Get-Item -Path ".\").FullName

# Path for the test program.
$MsQuicTest = $CurrentDir + "\artifacts\bin\$($Config)\msquictest.exe"
if (!$IsWindows) {
    $MsQuicTest = $CurrentDir + "/artifacts/bin/msquictest"
}

# Path for the procdump executable.
$ProcDumpExe = $CurrentDir + "\bld\procdump\procdump.exe"

# Folder for log files.
$LogBaseDir = Join-Path (Join-Path $CurrentDir "artifacts") "logs"
$LogDir = Join-Path $LogBaseDir (Get-Date -UFormat "%m.%d.%Y.%T").Replace(':','.')

# List of all the test results.
$PassedTests = New-Object System.Collections.ArrayList
$FailedTests = New-Object System.Collections.ArrayList

function Log($msg) {
    Write-Host "[$(Get-Date)] $msg"
}

# Installs procdump if not already. Windows specific.
function Install-ProcDump {
    if (!(Test-Path bld)) { mkdir bld | Out-Null }
    if (!(Test-Path .\bld\procdump)) {
        Log "Installing procdump..."
        # Download the zip file.
        Invoke-WebRequest -Uri https://download.sysinternals.com/files/Procdump.zip -OutFile bld\procdump.zip
        # Extract the zip file.
        Expand-Archive -Path bld\procdump.zip .\bld\procdump
        # Delete the zip file.
        Remove-Item -Path bld\procdump.zip
    }
}

# Executes msquictext with the given arguments.
function Start-MsQuicTest([String]$Arguments, [String]$InstanceName = "") {
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    if ($IsWindows -and $InstanceName -ne "") {
        $pinfo.FileName = $ProcDumpExe
        $pinfo.Arguments = "-ma -e -b -l -accepteula -x $($LogDir)\$($InstanceName) $($MsQuicTest) $($Arguments)"
    } else {
        $pinfo.FileName = $MsQuicTest
        $pinfo.Arguments = $Arguments
    }
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p
}

# Executes msquictest to query all available test cases, parses the console
# output and returns a list of test case names.
function GetTestCases {
    $p = Start-MsQuicTest "--gtest_list_tests"
    $stdout = $p.StandardOutput.ReadToEnd()
    $p.WaitForExit()
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

    $InstanceName = $Name.Replace("/", "_").Replace(".", "_")
    $LocalLogDir = Join-Path $LogDir $InstanceName
    mkdir $LocalLogDir | Out-Null

    if ($LogProfile -ne "None") {
        # Start the logs
        .\log.ps1 -Start -LogProfile $LogProfile -InstanceName $InstanceName | Out-Null
    }

    # Run the test and parse the output to determine if it was success.
    $ResultsPath = Join-Path $LocalLogDir "results.xml"
    $p = Start-MsQuicTest "--gtest_filter=$($Name) --gtest_output=xml:$($ResultsPath)" $InstanceName
    
    [pscustomobject]@{
        Name = $Name
        p = $p
    }
}

# Waits for and finishes up the test case.
function FinishTestCase($p) {

    $InstanceName = $p.Name.Replace("/", "_").Replace(".", "_")
    $LocalLogDir = Join-Path $LogDir $InstanceName

    $stdout = $p.p.StandardOutput.ReadToEnd()
    $p.p.WaitForExit()
    $Success = $stdout.Contains("[  PASSED  ] 1 test")

    if ($Success) {
        if ($LogProfile -ne "None") {
            # Don't keep logs on success.
            .\log.ps1 -Cancel -InstanceName $InstanceName | Out-Null
        }
        $PassedTests.Add($p.Name) | Out-Null
        Remove-Item $LocalLogDir -Recurse -Force | Out-Null
    } else {
        if ($LogProfile -ne "None") {
            # Keep logs on failure.
            .\log.ps1 -Stop -Output "$($LocalLogDir)\quic.etl" -InstanceName $InstanceName | Out-Null
        }
        $stdout > (Join-Path $LocalLogDir "console.txt")
        $FailedTests.Add($p.Name) | Out-Null

        if ($Compress) {
            # Zip the output.
            Compress-Archive -Path "$($LocalLogDir)\*" -DestinationPath "$($LocalLogDir).zip" | Out-Null
            Remove-Item $LocalLogDir -Recurse -Force | Out-Null
        }
    }
}

# Runs a test case synchronously.
function RunTestCase([String]$Name) {
    FinishTestCase (StartTestCase $Name)
}

######################
#   Main Execution   #
######################

# Make sure the executable is present for the current configuration.
if (!(Test-Path $MsQuicTest)) { Write-Error "$($MsQuicTest) does not exist!" }

# Query all the test cases.
$TestCases = GetTestCases

# Apply any filtering.
if ($Filter -ne "") {
    $TestCases = ($TestCases | Where-Object { $_ -Like $Filter }) -as [String[]]
}
if ($NegativeFilter -ne "") {
    $TestCases = ($TestCases | Where-Object { !($_ -Like $NegativeFilter) }) -as [String[]]
}

if ($ListTestCases) {
    # List the tst cases.
    $TestCases
    exit
}

if ($IsWindows) {
    # Make sure procdump is installed.
    Install-ProcDump
}

# Set up the base directory.
if (!(Test-Path $LogBaseDir)) { mkdir $LogBaseDir }
mkdir $LogDir | Out-Null

if ($Serial -ne $false) {
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

# Print out the results.
Log "$($PassedTests.Count) test(s) passed."
if ($FailedTests.Count -ne 0) {
    Log "$($FailedTests.Count) test(s) failed:"
    for ($i = 0; $i -lt $FailedTests.Count; $i++) {
        Log "  $($FailedTests[$i])"
    }
    Log "Logs can be found in $($LogDir)"
} else {
    Remove-Item $LogDir | Out-Null
}
