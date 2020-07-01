<#

.SYNOPSIS
This script runs performance tests locally for a period of time.

.PARAMETER Config
    Specifies the build configuration to use.

.PARAMETER TestsFile
    Explcitly specifes a test file to run

.PARAMETER Remote
    The remote to connect to. Must have ssh remoting enabled, and public key auth. username@ip

.PARAMETER SkipDeploy
    Set flag to skip deploying test files

.PARAMETER Publish
    Publishes the results to the artifacts directory.

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [string]$TestsFile = "",

    [Parameter(Mandatory = $false)]
    [string]$Remote = "",

    [Parameter(Mandatory = $false)]
    [string]$WinRMUser = "",

    [Parameter(Mandatory = $false)]
    [switch]$SkipDeploy = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Publish = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

Get-PSSession | Remove-PSSession

$LocalPlatform = $null
if ($IsWindows) {
    $LocalPlatform = "windows"
} else {
    $LocalPlatform = "linux"
}


if ($TestsFile -eq "") {
    $TestsFile = Join-Path $PSScriptRoot "RemoteTests.json"
}

# -ComputerName

if ($Remote -eq "") {
    if ($WinRMUser -ne "") {
        $session = New-PSSession -ComputerName quic-server -Credential $WinRMUser -ConfigurationName PowerShell.7
    } else {
        $session = New-PSSession -ComputerName quic-server -ConfigurationName PowerShell.7
    }
} else {
    $session = New-PSSession -HostName "$Remote"
}

$RemoteAddress = $session.ComputerName

if ($null -eq $session) {
    exit
}

Write-Host "Connected to: $RemoteAddress"

$OutputDir = Join-Path $RootDir "artifacts/PerfDataResults"
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null


$RemotePlatform = Invoke-Command -Session $session -ScriptBlock { 
    if ($IsWindows) {
        return "windows"
    } else {
        return "linux"
    }
}

# Join path in script to ensure right platform separator
$RemoteDirectory = Invoke-Command -Session $session -ScriptBlock { Join-Path (Get-Location) "Tests" }

$LocalDirectory = Join-Path $RootDir "artifacts"

function WaitFor-Remote-Ready {
    param ($Job, $Matcher)
    $StopWatch =  [system.diagnostics.stopwatch]::StartNew()
    while ($true) {
        $CurrentResults = Receive-Job -Job $Job -Keep
        if (![string]::IsNullOrWhiteSpace($CurrentResults)) {
            $DidMatch = $CurrentResults -match $Matcher
            if ($DidMatch) {
                return $true
            }
        }
        Start-Sleep -Seconds 0.1 | Out-Null
        if ($StopWatch.ElapsedMilliseconds -gt 10000) {
            return $false
        }
    }
}

function WaitFor-Remote {
    param ($Job)
    Wait-Job -Job $Job -Timeout 10 | Out-Null
    $RetVal = Receive-Job -Job $Job
    return $RetVal -join "`n"
}

function Copy-Artifacts {
    param([string]$From, [string]$To)
    try {
        Invoke-Command $session -ScriptBlock {Remove-Item -Path "$Using:To/*" -Recurse -Force }
    } catch {
        # Ignore failure
    }
    # TODO Figure out how to filter this
    Copy-Item -Path "$From\*" -Destination $To -ToSession $session  -Recurse
}

class ExecutableSpec {
    [string]$Platform;
    [string]$Tls;
    [string]$Arch;
    [string]$Exe;
    [string]$Arguments;
}

class TestDefinition {
    [string]$TestName;
    [ExecutableSpec]$Remote;
    [ExecutableSpec]$Local;
    [int]$Iterations;
    [string]$RemoteReadyMatcher;
    [string]$ResultsMatcher;

    [string]ToString() {
        return ("{0}_{1}_{2}_{3}_{4}_{5}_{6}" -f $this.TestName, 
                                         $this.Local.Platform, 
                                         $this.Local.Tls,
                                         $this.Local.Arch,
                                         $this.Remote.Platform,
                                         $this.Remote.Tls,
                                         $this.Remote.Arch
                                         )
    }

    [string]ToStringWithoutName() {
        return ("{0}_{1}_{2}_{3}_{4}_{5}" -f $this.Local.Platform, 
                                         $this.Local.Tls,
                                         $this.Local.Arch,
                                         $this.Remote.Platform,
                                         $this.Remote.Tls,
                                         $this.Remote.Arch
                                         )
    }
}

class TestPublishResult {
    [string]$PlatformName
    [string]$TestName
    [string]$CommitHash
    [double[]]$IndividualRunResults
}

$currentLoc = Get-Location
Set-Location -Path $RootDir
$env:GIT_REDIRECT_STDERR = '2>&1'
$CurrentCommitHash = $null
try {
    $CurrentCommitHash = git rev-parse HEAD
} catch {
    Write-Debug "Failed to get commit hash from git"
}
Set-Location -Path $currentLoc


function GetExe-Name {
    param($PathRoot, $Platform, $IsRemote, $TestPlat)
    $ExeName = $TestPlat.Exe
    if ($Platform -eq "windows") {
        $ExeName += ".exe"
    }

    $ConfigStr = "$($TestPlat.Arch)_$($Config)_$($TestPlat.Tls)"

    if ($IsRemote) {
        return Invoke-Command -Session $session -ScriptBlock { Join-Path $Using:PathRoot $Using:Platform $Using:ConfigStr $Using:ExeName  }
    } else {
        return Join-Path $PathRoot $Platform $ConfigStr $ExeName
    }
}

function Parse-Test-Results($Results, $Matcher) {
    try {
        # Unused variable on purpose
        $Results -match $Matcher | Out-Null
        return $Matches[1]
    } catch {
        Write-Host "Error Processing Results:`n`n$Results"
        throw
    }
}

function Get-Latest-Test-Results($Platform, $Test) {
    $Uri = "https://msquicperformanceresults.azurewebsites.net/performance/$Platform/$Test"
    Write-Debug "Requesting: $Uri"
    $LatestResult = Invoke-RestMethod -Uri $Uri
    Write-Debug "Result: $LatestResult"
    return $LatestResult
}

function Median-Test-Results($FullResults) {
    $sorted = $FullResults | Sort-Object
    return $sorted[[int](($sorted.Length - 1) / 2)]
}

function RunRemote-Exe {
    param($Exe, $RunArgs)

    # Command to run chmod if necessary, and get base path
    $BasePath = Invoke-Command -Session $session -ScriptBlock {
        if (!$IsWindows) {
            chmod +x $Using:Exe
            return Split-Path $Using:Exe -Parent
        }
        return $null
    }

    return Invoke-Command -Session $session -ScriptBlock {
        if ($null -ne $Using:BasePath) {
            $env:LD_LIBRARY_PATH = $Using:BasePath
        }
        
        & $Using:Exe ($Using:RunArgs).Split(" ")
    } -AsJob
}

function RunLocal-Exe {
    param ($Exe, $RunArgs)

    if (!$IsWindows) {
        $BasePath = Split-Path $Exe -Parent
        $env:LD_LIBRARY_PATH = $BasePath
        chmod +x $Exe | Out-Null
    }
    return (Invoke-Expression "$Exe $RunArgs") -join "`n"
}

function Run-Test {
    param($Test)

    Write-Host "Running Test $Test"

    $RemoteExe = GetExe-Name -PathRoot $RemoteDirectory -Platform $RemotePlatform -IsRemote $true -TestPlat $Test.Remote
    $LocalExe = GetExe-Name -PathRoot $LocalDirectory -Platform $LocalPlatform -IsRemote $false -TestPlat $Test.Local

    # Check both Exes
    $RemoteExeExists = Invoke-Command -Session $session -ScriptBlock { Test-Path $Using:RemoteExe }
    $LocalExeExists = Test-Path $LocalExe

    if (!$RemoteExeExists -or !$LocalExeExists) {
        Write-Host "Failed to Run $Test because of missing exe"
        if (!$RemoteExeExists) {
            Write-Host "Missing Remote Exe $RemoteExe"
        }
        if (!$LocalExeExists) {
            Write-Host "Missing Local Exe $LocalExe"
        }
        return
    }

    $LocalArguments = $Test.Local.Arguments.Replace('$RemoteAddress', $RemoteAddress)

    $RemoteJob = RunRemote-Exe -Exe $RemoteExe -RunArgs $Test.Remote.Arguments

    $ReadyToStart = WaitFor-Remote-Ready -Job $RemoteJob 

    if (!$ReadyToStart) {
        Write-Host "Test Remote for $Test failed to start"
        Stop-Job -Job $Job
        return
    }

    $AllRunsResults = @()

    1..$Test.Iterations | ForEach-Object {
        $LocalResults = RunLocal-Exe -Exe $LocalExe -RunArgs $LocalArguments 

        $LocalParsedResults = Parse-Test-Results -Results $LocalResults -Matcher $Test.ResultsMatcher

        
        $AllRunsResults += $LocalParsedResults

        Write-Host "Run $($_): $LocalParsedResults kbps"
        $LocalResults | Write-Debug
    }

    $RemoteResults = WaitFor-Remote -Job $RemoteJob

    $Platform = $Test.ToStringWithoutName()

    # Print current and latest master results to console.
    $MedianCurrentResult = Median-Test-Results -FullResults $AllRunsResults
    $fullLastResult = Get-Latest-Test-Results -Platform $Platform -Test $Test.TestName
    if ($fullLastResult -ne "") {
        $MedianLastResult = Median-Test-Results -FullResults $fullLastResult.individualRunResults
        $PercentDiff = 100 * (($MedianCurrentResult - $MedianLastResult) / $MedianLastResult)
        $PercentDiffStr = $PercentDiff.ToString("#.##")
        if ($PercentDiff -ge 0) {
            $PercentDiffStr = "+$PercentDiffStr"
        }
        Write-Host "Median: $MedianCurrentResult kbps ($PercentDiffStr%)"
        Write-Host "Master: $MedianLastResult kbps"
    } else {
        Write-Host "Median: $MedianCurrentResult kbps"
    }
    Write-Debug $RemoteResults.ToString()

    if ($Publish -and ($CurrentCommitHash -ne $null)) {
        Write-Host "Saving results.json out for publishing."
        $Results = [TestPublishResult]::new()
        $Results.CommitHash = $CurrentCommitHash.Substring(0, 7)
        $Results.PlatformName = $Platform
        $Results.TestName = $Test.TestName
        $Results.IndividualRunResults = $allRunsResults

        $ResultFile = Join-Path $OutputDir "results_$Test.json"
        $Results | ConvertTo-Json | Out-File $ResultFile
    } elseif ($Publish -and ($CurrentCommitHash -eq $null)) {
        Write-Debug "Failed to publish because of missing commit hash"
    }
}

function Check-Test {
    param($Test)
    return ($Test.Local.Platform -eq $LocalPlatform) -and ($Test.Remote.Platform -eq $RemotePlatform)
}

try {
    $Tests = [TestDefinition[]](Get-Content -Path $TestsFile | ConvertFrom-Json)

    if (!$SkipDeploy) {
        Copy-Artifacts -From $LocalDirectory -To $RemoteDirectory
    }

    foreach ($Test in $Tests) {
        if (Check-Test -Test $Test) {
            Run-Test -Test $Test
        } else {
            Write-Host "Skipping $Test"
        }
    }
} finally {
    Remove-PSSession -Session $session 
}
