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

.PARAMETER Record
    Records ETW traces

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
    [string]$ComputerName = "quic-server",

    [Parameter(Mandatory = $false)]
    [string]$WinRMUser = "",

    [Parameter(Mandatory = $false)]
    [switch]$SkipDeploy = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Publish = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Local = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Record = $false
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

Set-Globals -Local $Local `
            -LocalTls $LocalTls `
            -LocalArch $LocalArch `
            -RemoteTls $RemoteTls `
            -RemoteArch $RemoteArch `
            -Config $Config `
            -Publish $Publish `
            -Record $Record

if ($Local) {
    $RemoteAddress = "localhost"
    $Session = $null
    $LocalAddress = "127.0.0.1"
} else {
    if ($Remote -eq "") {
        if ($WinRMUser -ne "") {
            $Session = New-PSSession -ComputerName $ComputerName -Credential $WinRMUser -ConfigurationName PowerShell.7
        } else {
            $Session = New-PSSession -ComputerName $ComputerName -ConfigurationName PowerShell.7
        }
    } else {
        $Session = New-PSSession -HostName "$Remote"
    }

    $RemoteAddress = $Session.ComputerName

    if ($null -eq $Session) {
        Write-Error "Failed to create remote session"
        exit
    }

    $LocalAddress = Get-LocalAddress -RemoteAddress $RemoteAddress

    Write-Output "Connected to: $RemoteAddress"
    Write-Output "Local IP Connection $LocalAddress"
}

Set-Session -Session $Session

$OutputDir = Join-Path $RootDir "artifacts/PerfDataResults"
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

$RemotePlatform = Invoke-TestCommand -Session $Session -ScriptBlock {
    if ($IsWindows) {
        return "windows"
    } else {
        return "linux"
    }
}

# Join path in script to ensure right platform separator
$RemoteDirectory = Invoke-TestCommand -Session $Session -ScriptBlock {
    Join-Path (Get-Location) "Tests"
}

$LocalDirectory = Join-Path $RootDir "artifacts"

if ($Local) {
    $RemoteDirectory = $LocalDirectory
}

$CurrentCommitHash = Get-GitHash -RepoDir $RootDir

function LocalSetup {
    $RetObj = New-Object -TypeName psobject
    $RetObj | Add-Member -MemberType NoteProperty -Name apipaInterfaces -Value $null
    try {
        if ($IsWindows) {
            $apipaAddr = Get-NetIPAddress 169.254.*
            if ($null -ne $apipaAddr) {
                # Disable all the APIPA interfaces for URO perf.
                Write-Debug "Temporarily disabling APIPA interfaces"
                $RetObj.apipaInterfaces = (Get-NetAdapter -InterfaceIndex $apipaAddr.InterfaceIndex) | Where-Object {$_.AdminStatus -eq "Up"}
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

function Invoke-Test {
    param ($Test)

    Write-Output "Running Test $Test"

    $RemoteExe = Get-ExeName -PathRoot $RemoteDirectory -Platform $RemotePlatform -IsRemote $true -TestPlat $Test.Remote
    $LocalExe = Get-ExeName -PathRoot $LocalDirectory -Platform $LocalPlatform -IsRemote $false -TestPlat $Test.Local

    # Check both Exes
    $RemoteExeExists = Invoke-TestCommand -Session $Session -ScriptBlock {
        param ($RemoteExe)
        Test-Path $RemoteExe
    } -ArgumentList $RemoteExe

    $LocalExeExists = Test-Path $LocalExe

    if (!$RemoteExeExists -or !$LocalExeExists) {
        Write-Output "Failed to Run $Test because of missing exe"
        if (!$RemoteExeExists) {
            Write-Output "Missing Remote Exe $RemoteExe"
        }
        if (!$LocalExeExists) {
            Write-Output "Missing Local Exe $LocalExe"
        }
        return
    }

    $LocalArguments = $Test.Local.Arguments.GetArguments().Replace('$RemoteAddress', $RemoteAddress)
    $LocalArguments = $LocalArguments.Replace('$LocalAddress', $LocalAddress)

    $CertThumbprint = Invoke-TestCommand -Session $Session -ScriptBlock {
        return $env:QUICCERT
    }

    $RemoteArguments = $Test.Remote.Arguments.GetArguments().Replace('$Thumbprint', $CertThumbprint)

    $RemoteJob = Invoke-RemoteExe -Exe $RemoteExe -RunArgs $RemoteArguments

    $ReadyToStart = Wait-ForRemoteReady -Job $RemoteJob

    if (!$ReadyToStart) {
        Write-Output "Test Remote for $Test failed to start"
        Stop-Job -Job $RemoteJob
        return
    }

    $AllRunsResults = @()

    try {
        1..$Test.Iterations | ForEach-Object {
            $LocalResults = Invoke-LocalExe -Exe $LocalExe -RunArgs $LocalArguments

            $LocalParsedResults = Get-TestResult -Results $LocalResults -Matcher $Test.ResultsMatcher


            $AllRunsResults += $LocalParsedResults

            Write-Output "Run $($_): $LocalParsedResults kbps"
            $LocalResults | Write-Debug
        }
    } finally {
        $RemoteResults = Wait-ForRemote -Job $RemoteJob
        Write-Debug $RemoteResults.ToString()
    }

    if ($Record) {
        Get-RemoteFile -From ($RemoteExe + ".remote.etw") -To (Join-Path $OutputDir $Test.ToString() + ".etw")
    }

    Publish-TestResults -Test $Test `
                        -AllRunsResults $AllRunsResults `
                        -CurrentCommitHash $CurrentCommitHash `
                        -OutputDir $OutputDir
}

$LocalDataCache = LocalSetup

try {
    $Tests = Get-Tests $TestsFile

    if ($null -eq $Tests) {
        Write-Output "Tests are not valid"
        exit
    }

    if (!$SkipDeploy -and !$Local) {
        Copy-Artifacts -From $LocalDirectory -To $RemoteDirectory
    }

    foreach ($Test in $Tests) {
        if (Test-CanRunTest -Test $Test -RemotePlatform $RemotePlatform -LocalPlatform $LocalPlatform) {
            Invoke-Test -Test $Test
        } else {
            Write-Output "Skipping $Test"
        }
    }
} finally {
    if ($null -ne $Session) {
        Remove-PSSession -Session $Session
    }
    LocalTeardown($LocalDataCache)
}
