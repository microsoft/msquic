<#

.SYNOPSIS
This script runs performance tests locally for a period of time.

.PARAMETER Config
    Specifies the build configuration to use.

# TODO Add LocalTls and RemoteTls flags

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

function HostToNetworkOrder {
    param($Address)
    $Bytes = $Address.GetAddressBytes()
    [Array]::Reverse($Bytes) | Out-Null
    return [System.BitConverter]::ToUInt32($Bytes, 0)
}

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
        exit
    }

    $PossibleRemoteIPs = [System.Net.Dns]::GetHostAddresses($RemoteAddress) | Select-Object -Property IPAddressToString

    $PossibleLocalIPs = Get-NetIPAddress -AddressFamily IPv4 | Select-Object -Property IPv4Address, PrefixLength

    $MatchedIPs = @()

    $PossibleLocalIPs | ForEach-Object {

        [IPAddress]$LocalIpAddr = $_.IPv4Address

        $ToMaskLocalAddress = HostToNetworkOrder($LocalIpAddr)

        $Mask = (1ul -shl $_.PrefixLength) - 1
        $Mask = $Mask -shl (32 - $_.PrefixLength)
        $LocalSubnet = $ToMaskLocalAddress -band $Mask

        $PossibleRemoteIPs | ForEach-Object {
            [ipaddress]$RemoteIpAddr = $_.IPAddressToString
            $ToMaskRemoteAddress = HostToNetworkOrder($RemoteIpAddr)
            $RemoteMasked = $ToMaskRemoteAddress -band $Mask

            if ($RemoteMasked -eq $LocalSubnet) {
                $MatchedIPs += $LocalIpAddr.IPAddressToString
            }
        }
    }

    if ($MatchedIPs.Length -ne 1) {
        Write-Host "Failed to parse local address. Using first address"
    }
    $LocalAddress = $MatchedIPs[0]

    Write-Host "Connected to: $RemoteAddress"
    Write-Host "Local IP Connection $LocalAddress" 
}

function Invoke-Test-Command {
    param (
        $Session,
        $ScriptBlock,
        [Object[]]$ArgumentList = @(),
        [switch]$AsJob = $false
    )

    if ($Local) {
        if ($AsJob) {
            return Start-Job -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
        }
        return Invoke-Command -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    } else {
        if ($AsJob) {
            return Invoke-Command -Session $Session -ScriptBlock $ScriptBlock -AsJob -ArgumentList $ArgumentList
        }
        return Invoke-Command -Session $Session -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList
    }
    
}

$OutputDir = Join-Path $RootDir "artifacts/PerfDataResults"
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null


$RemotePlatform = Invoke-Test-Command -Session $session -ScriptBlock { 
    if ($IsWindows) {
        return "windows"
    } else {
        return "linux"
    }
}

# Join path in script to ensure right platform separator
$RemoteDirectory = Invoke-Test-Command -Session $session -ScriptBlock { Join-Path (Get-Location) "Tests" }

$LocalDirectory = Join-Path $RootDir "artifacts"

if ($Local) {
    $RemoteDirectory = $LocalDirectory
}

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
        Invoke-Test-Command $session -ScriptBlock { param($To) Remove-Item -Path "$To/*" -Recurse -Force } -ArgumentList $To
    } catch {
        # Ignore failure
    }
    # TODO Figure out how to filter this
    Copy-Item -Path "$From\*" -Destination $To -ToSession $session  -Recurse
}

class ExecutableSpec {
    [string]$Platform;
    [string[]]$Tls;
    [string[]]$Arch;
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
        return ("{0}_{1}_{2}" -f $this.TestName, 
                                         $this.Local.Platform, 
                                         $this.Remote.Platform
                                         )
    }

    [string]ToTestPlatformString() {
        return ("{0}_{1}_{2}_{3}_{4}_{5}" -f $this.Local.Platform, 
                                         $global:LocalTls,
                                         $global:LocalArch,
                                         $this.Remote.Platform,
                                         $global:RemoteTls,
                                         $global:RemoteArch
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

    

    if ($IsRemote) {
        $ConfigStr = "$($RemoteArch)_$($Config)_$($RemoteTls)"
        return Invoke-Test-Command -Session $session -ScriptBlock { param($PathRoot, $Platform, $ConfigStr, $ExeName) Join-Path $PathRoot $Platform $ConfigStr $ExeName  } -ArgumentList $PathRoot, $Platform, $ConfigStr, $ExeName
    } else {
        $ConfigStr = "$($LocalArch)_$($Config)_$($LocalTls)"
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
    $BasePath = Invoke-Test-Command -Session $session -ScriptBlock {
        param ($Exe)
        if (!$IsWindows) {
            chmod +x $Exe
            return Split-Path $Exe -Parent
        }
        return $null
    } -ArgumentList $Exe

    Write-Debug "Running Remote: $Exe $RunArgs" | Out-Null

    return Invoke-Test-Command -Session $session -ScriptBlock {
        param($Exe, $RunArgs, $BasePath)
        if ($null -ne $BasePath) {
            $env:LD_LIBRARY_PATH = $BasePath
        }
        
        & $Exe ($RunArgs).Split(" ")
    } -AsJob -ArgumentList $Exe, $RunArgs, $BasePath
}

function RunLocal-Exe {
    param ($Exe, $RunArgs)

    if (!$IsWindows) {
        $BasePath = Split-Path $Exe -Parent
        $env:LD_LIBRARY_PATH = $BasePath
        chmod +x $Exe | Out-Null
    }
    $FullCommand = "$Exe $RunArgs"
    Write-Debug "Running Locally: $FullCommand"
    return (Invoke-Expression $FullCommand) -join "`n"
}

function Run-Test {
    param($Test)

    Write-Host "Running Test $Test"

    $RemoteExe = GetExe-Name -PathRoot $RemoteDirectory -Platform $RemotePlatform -IsRemote $true -TestPlat $Test.Remote
    $LocalExe = GetExe-Name -PathRoot $LocalDirectory -Platform $LocalPlatform -IsRemote $false -TestPlat $Test.Local

    # Check both Exes
    $RemoteExeExists = Invoke-Test-Command -Session $session -ScriptBlock { param($RemoteExe) Test-Path $RemoteExe } -ArgumentList $RemoteExe
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
    $LocalArguments = $LocalArguments.Replace('$LocalAddress', $LocalAddress)

    $CertThumbprint = Invoke-Test-Command -Session $session -ScriptBlock { return $env:QUICCERT }

    $RemoteArguments = $Test.Remote.Arguments.Replace('$Thumbprint', $CertThumbprint)

    $RemoteJob = RunRemote-Exe -Exe $RemoteExe -RunArgs $RemoteArguments

    $ReadyToStart = WaitFor-Remote-Ready -Job $RemoteJob 

    if (!$ReadyToStart) {
        Write-Host "Test Remote for $Test failed to start"
        #Stop-Job -Job $RemoteJob
        #return
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
        $RemoteResults = WaitFor-Remote -Job $RemoteJob
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

function Check-Test {
    param([TestDefinition]$Test)
    $PlatformCorrect = ($Test.Local.Platform -eq $LocalPlatform) -and ($Test.Remote.Platform -eq $RemotePlatform)
    if (!$PlatformCorrect) {
        return $false
    }
    if (!$Test.Local.Tls.Contains($LocalTls)) {
        return $false
    }
    if (!$Test.Remote.Tls.Contains($RemoteTls)) {
        return $false
    }
    return $true
}

try {
    $Tests = [TestDefinition[]](Get-Content -Path $TestsFile | ConvertFrom-Json)

    if (!$SkipDeploy -and !$Local) {
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
    if ($null -ne $session) {
        Remove-PSSession -Session $session 
    }
}
