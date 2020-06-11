<#

.SYNOPSIS
This script runs performance tests locally for a period of time.

.PARAMETER Config
    Specifies the build configuration to use.

.PARAMETER Arch
    The CPU architecture to use.

.PARAMETER Tls
    The TLS library use.

.PARAMETER WriteResults
    Write results 

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
    [string]$Tls = "",

    [Parameter(Mandatory = $false)]
    [switch]$WriteResults = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Default TLS based on current platform.
if ("" -eq $Tls) {
    if ($IsWindows) {
        $Tls = "schannel"
    } else {
        $Tls = "openssl"
    }
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Path to the spinquic exectuable.
$PingClient = $null
if ($IsWindows) {
    $PingClient = Join-Path $RootDir "\artifacts\windows\$($Arch)_$($Config)_$($Tls)\quicping.exe"
} else {
    $PingClient = Join-Path $RootDir "/artifacts/linux/$($Arch)_$($Config)_$($Tls)/quicping"
}

# Make sure the build is present.
if (!(Test-Path $PingClient)) {
    Write-Error "Build does not exist!`n `nRun the following to generate it:`n `n    $(Join-Path $RootDir "scripts" "build.ps1") -Config $Config -Arch $Arch -Tls $Tls`n"
}

function Start-Background-Executable($File, $Arguments) {
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = $File
    $pinfo.RedirectStandardOutput = $true
    $pinfo.RedirectStandardInput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $Arguments
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    return $p
}

function Stop-Background-Executable($Process) {
    $Process.StandardInput.WriteLine("")
    $Process.StandardInput.Flush()
    $Process.WaitForExit()
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

$GitPath = Join-Path $RootDir "artifacts/PerfDataGit"

function Clone-Data-Repo() {
    # Redirect stderr to stdout for git.
    $env:GIT_REDIRECT_STDERR = '2>&1'
    git clone https://github.com/microsoft/msquic $GitPath
    $currentLoc = Get-Location
    Set-Location -Path $GitPath
    git clean -d -x -f
    git reset --hard
    git checkout data/performance
    git pull
    Set-Location -Path $currentLoc
}

function Get-Last-Result($Path) {
    $FullLatestResult = Get-Item -Path $Path | Get-Content -Tail 1
    $SplitLatestResult =  $FullLatestResult -split ','
    $LatestResult = $SplitLatestResult[$SplitLatestResult.Length - 1].Trim()
    return $LatestResult
}

function Parse-Loopback-Results($Results) {
    #Unused variable on purpose
    $m = $Results -match "Total rate.*\(TX.*bytes @ (.*) kbps \|"
    return $Matches[1]
}

function Run-Loopback-Test() {
    Write-Host "Running Loopback Test"
    $proc = Start-Background-Executable -File $PingClient -Arguments "-listen:* -selfsign:1 -peer_uni:1"
    Start-Sleep 4

    $allRunsResults = @()

    1..10 | ForEach-Object {
        $runResult = Run-Foreground-Executable -File $PingClient -Arguments "-target:localhost -uni:1 -length:100000000"
        $parsedRunResult = Parse-Loopback-Results -Results $runResult
        $allRunsResults += $parsedRunResult
        Write-Host "Client $_ Finished"
    }

    Stop-Background-Executable -Process $proc

    $sum = 0
    $allRunsResults | ForEach-Object { $sum += $_ }
    $average = $sum / $allRunsResults.Length

    $combinedResults = ""
    $allRunsResults | ForEach-Object { $combinedResults += "$_, " }

    $osPath = "linux"
    if ($IsWindows) {
        $osPath = "windows"
    }

    $ResultsFolderRoot = "$osPath/loopback"
    $ResultsFileName = "/results.csv"
    $ResultsFileNamePath = "$ResultsFolderRoot/$ResultsFileName"
    $LastResultsPath = Join-Path $GitPath $ResultsFileNamePath
    $LastResult = Get-Last-Result -Path $LastResultsPath

    if ($WriteResults) {
        # Redirect stderr to stdout for git.
        $env:GIT_REDIRECT_STDERR = '2>&1'
        $time = [DateTime]::UtcNow.ToString("u")
        $currentLoc = Get-Location
        Set-Location -Path $RootDir
        $fullHash = git rev-parse HEAD
        $hash = $fullHash.Substring(0, 7)

        $newResult = "$time, $hash, $allRunsResults $average"

        $NewFilePath = Join-Path $RootDir "artifacts/PerfDataResults/$ResultsFolderRoot"
        $NewFileLocation = Join-Path $NewFilePath $ResultsFileName
        New-Item $NewFilePath -ItemType Directory -Force
        Copy-Item $LastResultsPath -Destination $NewFileLocation -Force

        Add-Content -Path $NewFileLocation -Value $newResult
        Set-Location -Path $currentLoc
    }

    Write-Host "Current Run: $average kbps"
    Write-Host "Last Master Run: $LastResult kbps"
    Write-Host "All Results: $allRunsResults"
}


Clone-Data-Repo


Run-Loopback-Test
