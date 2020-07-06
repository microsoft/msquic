<#

.SYNOPSIS
This script runs performance tests locally for a period of time.

.PARAMETER Config
    Specifies the build configuration to use.

.PARAMETER LocalArch
    Specifies what the local arch is

.PARAMETER RemoteArch
    Specifies what the remote arch is

.PARAMETER LocalTls
    Specifies what local TLS provider to use

.PARAMETER RemoteTls
    Specifies what remote TLS provider to use

.PARAMETER TestsFile
    Explcitly specifes a test file to run

.PARAMETER Remote
    The remote to connect to. Must have ssh remoting enabled, and public key auth. username@ip

.PARAMETER Local
    Use the local system as the remote

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
    [string]$LocalArch = "x64",

    [Parameter(Mandatory = $false)]
    [string]$LocalTls = "stub",

    [Parameter(Mandatory = $false)]
    [string]$RemoteArch = "x64",
    
    [Parameter(Mandatory = $false)]
    [string]$RemoteTls = "stub",

    [Parameter(Mandatory = $false)]
    [string]$WinRMUser = "",

    [Parameter(Mandatory = $false)]
    [switch]$SkipDeploy = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Publish = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Local = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

# Remove any previous remote PowerShell sessions
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

Import-Module (Join-Path $PSScriptRoot 'performance-helper.psm1') -Force

SetGlobals  -Local $Local `
            -LocalTls $LocalTls `
            -LocalArch $LocalArch `
            -RemoteTls $RemoteTls `
            -RemoteArch $RemoteArch `
            -Config $Config

if ($Local) {
    $RemoteAddress = "localhost"
    $session = $null
    $LocalAddress = "127.0.0.1"
} else {
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
        Write-Error "Failed to create remote session"
        exit
    }

    $LocalAddress = ComputeLocalAddress -RemoteAddress $RemoteAddress

    Write-Host "Connected to: $RemoteAddress"
    Write-Host "Local IP Connection $LocalAddress" 
}

$OutputDir = Join-Path $RootDir "artifacts/PerfDataResults"
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

$RemotePlatform = Invoke-TestCommand -Session $session -ScriptBlock { 
    if ($IsWindows) {
        return "windows"
    } else {
        return "linux"
    }
}

# Join path in script to ensure right platform separator
$RemoteDirectory = Invoke-TestCommand -Session $session -ScriptBlock {
    Join-Path (Get-Location) "Tests" 
}

$LocalDirectory = Join-Path $RootDir "artifacts"

if ($Local) {
    $RemoteDirectory = $LocalDirectory
}

$CurrentCommitHash = Get-GitHash -RepoDir $RootDir

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

function LocalSetup {
    $RetObj = New-Object -TypeName psobject
    $RetObj | Add-Member -MemberType NoteProperty -Name apipaInterfaces -Value $null
    try {
        if ($IsWindows) {
            $apipaAddr = Get-NetIPAddress 169.254.*
            if ($null -ne $apipaAddr) {
                # Disable all the APIPA interfaces for URO perf.
                Write-Debug "Temporarily disabling APIPA interfaces"
                $RetObj.apipaInterfaces = (Get-NetAdapter -InterfaceIndex $apipaAddr.InterfaceIndex) | where {$_.AdminStatus -eq "Up"}
                $RetObj.apipaInterfaces | Disable-NetAdapter -Confirm:$false
            }
        }
    } catch {
        $RetObj.apipaInterfaces = $null
    }

    return $RetObj
}

function LocalTeardown {
    param ($LocalCache)
    if ($null -ne $LocalCache.apipaInterfaces) {
        # Re-enable the interfaces we disabled earlier.
        Write-Debug "Re-enabling APIPA interfaces"
        $LocalCache.apipaInterfaces | Enable-NetAdapter
    }
}

function Run-Test {
    param ($Test)

    Write-Host "Running Test $Test"

    $RemoteExe = Get-ExeName -PathRoot $RemoteDirectory -Platform $RemotePlatform -IsRemote $true -TestPlat $Test.Remote
    $LocalExe = Get-ExeName -PathRoot $LocalDirectory -Platform $LocalPlatform -IsRemote $false -TestPlat $Test.Local

    # Check both Exes
    $RemoteExeExists = Invoke-TestCommand -Session $session -ScriptBlock {
        param ($RemoteExe)
        Test-Path $RemoteExe
    } -ArgumentList $RemoteExe

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

    $LocalArguments = $Test.Local.Arguments.GetArguments().Replace('$RemoteAddress', $RemoteAddress)
    $LocalArguments = $LocalArguments.Replace('$LocalAddress', $LocalAddress)

    $CertThumbprint = Invoke-TestCommand -Session $session -ScriptBlock { 
        return $env:QUICCERT 
    }

    $RemoteArguments = $Test.Remote.Arguments.GetArguments().Replace('$Thumbprint', $CertThumbprint)

    $RemoteJob = RunRemote-Exe -Exe $RemoteExe -RunArgs $RemoteArguments

    $ReadyToStart = Wait-ForRemoteReady -Job $RemoteJob 

    if (!$ReadyToStart) {
        Write-Host "Test Remote for $Test failed to start"
        Stop-Job -Job $RemoteJob
        return
    }

    $AllRunsResults = @()

    try {
        1..$Test.Iterations | ForEach-Object {
            $LocalResults = RunLocal-Exe -Exe $LocalExe -RunArgs $LocalArguments 

            $LocalParsedResults = Parse-Test-Results -Results $LocalResults -Matcher $Test.ResultsMatcher

            
            $AllRunsResults += $LocalParsedResults

            Write-Host "Run $($_): $LocalParsedResults kbps"
            $LocalResults | Write-Debug
        }
    } finally {
        $RemoteResults = Wait-ForRemote -Job $RemoteJob
        Write-Debug $RemoteResults.ToString()
    }

    $Platform = $Test.ToTestPlatformString()

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

$LocalDataCache = LocalSetup

try {
    $Tests = Get-Tests $TestsFile

    $TestsValid = Validate-Tests -Test $Tests

    if (!$TestsValid) {
        Write-Host "Tests are not valid"
        exit
    }

    if (!$SkipDeploy -and !$Local) {
        Copy-Artifacts -From $LocalDirectory -To $RemoteDirectory
    }

    foreach ($Test in $Tests) {
        if (Check-Test -Test $Test -RemotePlatform $RemotePlatform -LocalPlatform $LocalPlatform) {
            Run-Test -Test $Test
        } else {
            Write-Host "Skipping $Test"
        }
    }
} finally {
    if ($null -ne $session) {
        Remove-PSSession -Session $session 
    }
    LocalTeardown($LocalDataCache)
}
