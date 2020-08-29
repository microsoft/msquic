<#

.SYNOPSIS
This script runs performance tests locally for a period of time.

.PARAMETER Config
    Specifies the build configuration to use.

.PARAMETER LocalArch
    Specifies what the local arch is

.PARAMETER RemoteArch
    Specifies what the remote arch is

.PARAMETER Kernel
    Run the remote in kernel mode

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

.PARAMETER PGO
    Uses pgomgr to merge the resulting .pgc files back to the .pgd.

.PARAMETER SkipDeploy
    Set flag to skip deploying test files

.PARAMETER Publish
    Publishes the results to the artifacts directory.

.PARAMETER RecordStack
    Records ETW stack traces

.PARAMETER Timeout
    Timeout in seconds for each individual client test invocation.

.PARAMETER RecordQUIC
    Record QUIC specific trace events

.PARAMETER TestToRun
    Run a specific test name

#>

param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Release",

    [Parameter(Mandatory = $false)]
    [string]$TestsFile = "",

    [Parameter(Mandatory = $false)]
    [string]$Remote = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$LocalArch = "x64",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl", "stub", "mitls")]
    [string]$LocalTls = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$RemoteArch = "x64",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl", "stub", "mitls")]
    [string]$RemoteTls = "",

    [Parameter(Mandatory = $false)]
    [string]$ComputerName = "quic-server",

    [Parameter(Mandatory = $false)]
    [string]$WinRMUser = "",

    [Parameter(Mandatory = $false)]
    [switch]$Kernel = $false,

    [Parameter(Mandatory = $false)]
    [switch]$SkipDeploy = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Publish = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Local = $false,

    [Parameter(Mandatory = $false)]
    [switch]$RecordStack = $false,

    [Parameter(Mandatory = $false)]
    [switch]$PGO = $false,

    [Parameter(Mandatory = $false)]
    [int]$Timeout = 120,

    [Parameter(Mandatory = $false)]
    [switch]$RecordQUIC = $false,

    [Parameter(Mandatory = $false)]
    [string]$TestToRun = ""
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Validate the the kernel switch.
if ($Kernel -and !$IsWindows) {
    Write-Error "-Kernel switch only supported on Windows"
}

if ($Kernel -and $PGO) {
    Write-Error "PGO is currently not supported in kernel mode"
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

$Record = $RecordStack -or $RecordQUIC

# Remove any previous remote PowerShell sessions
Get-PSSession | Remove-PSSession

$LocalPlatform = $null
if ($IsWindows) {
    $LocalPlatform = "windows"
} else {
    $LocalPlatform = "linux"
}

# Set Tls
if (($LocalTls -eq "") -and ($RemoteTls -eq "")) {
    if ($IsWindows) {
        $LocalTls = "schannel"
        $RemoteTls = $LocalTls
    } else {
        $LocalTls = "openssl"
        $RemoteTls = $LocalTls
    }
} elseif (($LocalTls -ne "") -xor ($RemoteTls -ne "")) {
    Write-Error "Both TLS arguments must be set if a manual setting is done"
}

if (!$IsWindows) {
    if ($PGO) {
        Write-Error "'-PGO' is not supported on this platform!"
    }
    if ($Record) {
        Write-Error "'-Record' is not supported on this platform!"
    }
}


if ($TestsFile -eq "") {
    $TestsFile = Join-Path $PSScriptRoot "RemoteTests.json"
}

Import-Module (Join-Path $PSScriptRoot 'performance-helper.psm1') -Force

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

Set-ScriptVariables -Local $Local `
                    -LocalTls $LocalTls `
                    -LocalArch $LocalArch `
                    -RemoteTls $RemoteTls `
                    -RemoteArch $RemoteArch `
                    -Config $Config `
                    -Publish $Publish `
                    -Record $Record `
                    -RecordQUIC $RecordQUIC `
                    -RemoteAddress $RemoteAddress `
                    -Session $Session `
                    -Kernel $Kernel

$RemotePlatform = Invoke-TestCommand -Session $Session -ScriptBlock {
    if ($IsWindows) {
        return "windows"
    } else {
        return "linux"
    }
}

$OutputDir = Join-Path $RootDir "artifacts/PerfDataResults/$RemotePlatform/$($RemoteArch)_$($Config)_$($RemoteTls)"
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

# Join path in script to ensure right platform separator
$RemoteDirectory = Invoke-TestCommand -Session $Session -ScriptBlock {
    Join-Path (Get-Location) "Tests"
}

$LocalDirectory = Join-Path $RootDir "artifacts/bin"

if ($Local) {
    $RemoteDirectory = $LocalDirectory
}

$CurrentCommitHash = Get-GitHash -RepoDir $RootDir

if ($PGO -and $Local) {
    # PGO needs the server and client executing out of separate directories.
    $RemoteDirectoryOld = $RemoteDirectory
    $RemoteDirectory = "$($RemoteDirectoryOld)_server"
    try {
        Remove-Item -Path "$RemoteDirectory/*" -Recurse -Force
    } catch {
        # Ignore failure, which occurs when directory does not exist
    }
    New-Item -Path $RemoteDirectory -ItemType Directory -Force | Out-Null
    Copy-Item "$RemoteDirectoryOld\*" $RemoteDirectory -Recurse
}

function LocalSetup {
    $RetObj = New-Object -TypeName psobject
    $RetObj | Add-Member -MemberType NoteProperty -Name apipaInterfaces -Value $null
    try {
        if ($IsWindows -and $Local) {
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

$RemoteExePath = Get-ExePath -PathRoot $RemoteDirectory -Platform $RemotePlatform -IsRemote $true
$LocalExePath = Get-ExePath -PathRoot $LocalDirectory -Platform $LocalPlatform -IsRemote $false

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
        if (!$RemoteExeExists) {
            Write-Output "Missing Remote Exe $RemoteExe"
        }
        if (!$LocalExeExists) {
            Write-Output "Missing Local Exe $LocalExe"
        }
        Write-Error "Failed to Run $Test because of missing exe"
    }

    $LocalArguments = $Test.Local.Arguments.Replace('$RemoteAddress', $RemoteAddress)
    $LocalArguments = $LocalArguments.Replace('$LocalAddress', $LocalAddress)

    $CertThumbprint = Invoke-TestCommand -Session $Session -ScriptBlock {
        return $env:QUICCERT
    }

    $RemoteArguments = $Test.Remote.Arguments.Replace('$Thumbprint', $CertThumbprint)

    Write-Debug "Running Remote: $RemoteExe Args: $RemoteArguments"

    # Starting the server
    $RemoteJob = Invoke-RemoteExe -Exe $RemoteExe -RunArgs $RemoteArguments
    $ReadyToStart = Wait-ForRemoteReady -Job $RemoteJob -Matcher $Test.RemoteReadyMatcher

    if (!$ReadyToStart) {
        Stop-Job -Job $RemoteJob
        Write-Error "Test Remote for $Test failed to start"
    }

    $AllRunsResults = @()

    Start-Tracing -Exe $LocalExe

    try {
        1..$Test.Iterations | ForEach-Object {
            Write-Debug "Running Local: $LocalExe Args: $LocalArguments"
            $LocalResults = Invoke-LocalExe -Exe $LocalExe -RunArgs $LocalArguments -Timeout $Timeout
            $LocalParsedResults = Get-TestResult -Results $LocalResults -Matcher $Test.ResultsMatcher
            $AllRunsResults += $LocalParsedResults
            if ($PGO) {
                # Merge client PGO Counts
                Merge-PGOCounts -Path $LocalExePath
            }

            Write-Output "Run $($_): $LocalParsedResults $($Test.Units)"
            $LocalResults | Write-Debug
        }
    } finally {
        $RemoteResults = Wait-ForRemote -Job $RemoteJob
        Write-Debug $RemoteResults.ToString()
    }

    Stop-Tracing -Exe $LocalExe

    if ($Record) {
        if ($Local) {
            Get-RemoteFile -From ($RemoteExe + ".remote.etl") -To (Join-Path $OutputDir ($Test.ToString() + ".combined.etl"))
        } else {
            Get-RemoteFile -From ($RemoteExe + ".remote.etl") -To (Join-Path $OutputDir ($Test.ToString() + ".server.etl"))
            Copy-Item -Path ($LocalExe + ".local.etl") -Destination (Join-Path $OutputDir ($Test.ToString() + ".client.etl"))
        }
    }

    if ($PGO) {
        # Merge server PGO Counts
        Get-RemoteFile -From (Join-Path $RemoteExePath *.pgc) -To $LocalExePath
        Remove-RemoteFile -Path (Join-Path $RemoteExePath *.pgc)
        Merge-PGOCounts -Path $LocalExePath
    }

    Publish-TestResults -Test $Test `
                        -AllRunsResults $AllRunsResults `
                        -CurrentCommitHash $CurrentCommitHash `
                        -OutputDir $OutputDir
}

$LocalDataCache = LocalSetup

if ($Record -and $IsWindows) {
    try {
        wpr.exe -cancel 2> $null
    } catch {
    }
    Invoke-TestCommand -Session $Session -ScriptBlock {
        try {
            wpr.exe -cancel 2> $null
        } catch {
        }
    }
}

try {
    $Tests = Get-Tests $TestsFile

    if ($null -eq $Tests) {
        Write-Error "Tests are not valid"
    }

    # Find All Remote processes, and kill them
    if (!$Local) {
        foreach ($Test in $Tests) {
            $ExeName = $Test.Remote.Exe
            Invoke-TestCommand -Session $Session -ScriptBlock {
                param ($ExeName)
                try {
                    Stop-Process -Name $ExeName -Force
                } catch {
                }
            } -ArgumentList $ExeName
        }

    }

    if (!$SkipDeploy -and !$Local) {
        Copy-Artifacts -From $LocalDirectory -To $RemoteDirectory
    }

    foreach ($Test in $Tests) {
        if ($TestToRun -ne "" -and $Test.TestName -ne $TestToRun) {
            continue
        }
        if (Test-CanRunTest -Test $Test -RemotePlatform $RemotePlatform -LocalPlatform $LocalPlatform) {
            Invoke-Test -Test $Test
        } else {
            Write-Output "Skipping $Test"
        }
    }

    if ($PGO) {
        Write-Host "Saving msquic.pgd out for publishing."
        Copy-Item "$LocalExePath\msquic.pgd" $OutputDir
    }

} finally {
    if ($null -ne $Session) {
        Remove-PSSession -Session $Session
    }
    LocalTeardown($LocalDataCache)
}
