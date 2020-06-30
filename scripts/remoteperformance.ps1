<#

.SYNOPSIS
This script runs performance tests locally for a period of time.

.PARAMETER Config
    Specifies the build configuration to use.

.PARAMETER Arch
    The CPU architecture to use.

.PARAMETER Tls
    The TLS library use.

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$Arch = "x64",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl", "stub", "mitls")]
    [string]$Tls = "stub",

    [Parameter(Mandatory = $false)]
    [string]$TestsFile = ""
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Default TLS based on current platform.
if ("" -eq $Tls) {
    if ($IsWindows) {
        $Tls = "schannel"
    } else {
        $Tls = "openssl"
    }
}

if ($TestsFile -eq "") {
    $TestsFile = Join-Path $PSScriptRoot "RemoteTests-Windows.json"
}

$OsPlat = "Linux"
if ($IsWindows) {
    $OsPlat = "Windows"
}
$Platform = "$($OsPlat)_$($Arch)_$($Tls)"


$ArtifactsFolder = $null
$RemoteDirectory = $null
if ($IsWindows) {
    $ArtifactsFolder = "artifacts\windows\$($Arch)_$($Config)_$($Tls)"
    $RemoteDirectory = "C:\Test"
} else {
    $ArtifactsFolder = "artifacts/linux/$($Arch)_$($Config)_$($Tls)"
    $RemoteDirectory = "/user/test/test"
    
}
$LocalDirectory = Join-Path $RootDir $ArtifactsFolder

$RemoteIp = "172.21.202.141"

$session = New-PSSession -HostName $RemoteIp -UserName "User"

if ($null -eq $session) {
    exit
}

function Start-Remote {
    param($ScriptBlock)
    $job =  Invoke-Command -Session $session -ScriptBlock $ScriptBlock -AsJob
    return $job
}

function WaitFor-Remote-Ready {
    param ($Job, $Matcher)
    while ($true) {
        $CurrentResults = Receive-Job -Job $Job -Keep
        if (![string]::IsNullOrWhiteSpace($CurrentResults)) {
            Write-Host $CurrentResults
            break;
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
    Copy-Item -Path "$From\*" -Destination $To -ToSession $session  -Recurse
}

function Run-Foreground-Executable($File, $Arguments) {
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $File
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $Arguments
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p.WaitForExit()
    return $p.StandardOutput.ReadToEnd()
}

class ExecutableSpec {
    [string]$Platform;
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
}

$Tests = [TestDefinition[]](Get-Content -Path $TestsFile | ConvertFrom-Json)

function GetExe-Name {
    param($PathRoot, $ExeName)
    if ($IsWindows) {
        $ExeName += ".exe"
    }
    return Join-Path $PathRoot $ExeName
}

function Parse-Test-Results($Results, $Matcher) {
    try {
        # Unused variable on purpose
        $m = $Results -match $Matcher
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

function Run-Test {
    param($Test)

    $RemoteExe = GetExe-Name -PathRoot $RemoteDirectory -ExeName $Test.Remote.Exe
    $LocalExe = GetExe-Name -PathRoot $LocalDirectory -ExeName $Test.Local.Exe

    $LocalArguments = $Test.Local.Arguments.Replace('$RemoteTarget', $RemoteIp)

    $RemoteCommand = "$RemoteExe " + $Test.Remote.Arguments

    $RemoteScript = { Invoke-Expression $Using:RemoteCommand }

    $RemoteJob = Start-Remote -ScriptBlock $RemoteScript

    Start-Sleep 3

    #WaitFor-Remote-Ready -Job $RemoteJob

    $AllRunsResults = @()

    1..$Test.Iterations | ForEach-Object {
        $LocalResults = Run-Foreground-Executable -File $LocalExe -Arguments $LocalArguments

        $LocalParsedResults = Parse-Test-Results -Results $LocalResults -Matcher $Test.ResultsMatcher

        
        $AllRunsResults += $LocalParsedResults

        Write-Host "Run $($_): $LocalParsedResults kbps"
        $LocalResults | Write-Debug
    }

    

    $RemoteResults = WaitFor-Remote -Job $RemoteJob

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
}

try {
    Copy-Artifacts -From $LocalDirectory -To $RemoteDirectory

    foreach ($Test in $Tests) {
        Run-Test -Test $Test
    }
} finally {
    Remove-PSSession -Session $session 
}
