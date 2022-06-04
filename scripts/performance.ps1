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

.PARAMETER FailOnRegression
    Fail tests on perf regression (Currently only throughput up)

.PARAMETER Protocol
    Which Protocol to use (QUIC or TCP)

#>

Using module .\performance-helper.psm1

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
    [ValidateSet("schannel", "openssl")]
    [string]$LocalTls = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64")]
    [string]$RemoteArch = "x64",

    [Parameter(Mandatory = $false)]
    [string]$ExtraArtifactDir = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl")]
    [string]$RemoteTls = "",

    [Parameter(Mandatory = $false)]
    [string]$ComputerName = "quic-server",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic.Light", "Datapath.Light", "Datapath.Verbose", "Stacks.Light", "RPS.Light", "Performance.Light", "Basic.Verbose", "Performance.Light", "Performance.Verbose", "Full.Light", "Full.Verbose", "SpinQuic.Light", "None")]
    [string]$LogProfile = "None",

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
    [switch]$PGO = $false,

    [Parameter(Mandatory = $false)]
    [switch]$SharedEC = $false,

    [Parameter(Mandatory = $false)]
    [switch]$XDP = $false,

    [Parameter(Mandatory = $false)]
    [int]$Timeout = 120,

    [Parameter(Mandatory = $false)]
    [string]$TestToRun = "",

    [Parameter(Mandatory = $false)]
    [boolean]$FailOnRegression = $false,

    [Parameter(Mandatory = $false)]
    [string]$ForceBranchName = $null,

    [Parameter(Mandatory = $false)]
    [ValidateSet("QUIC", "TCPTLS")]
    [string]$Protocol = "QUIC",

    [Parameter(Mandatory = $false)]
    [int]$ForceIterations = 0
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Validate the the switches.
if ($Kernel) {
    if (!$IsWindows) {
        Write-Error "'-Kernel' is not supported on this platform"
    }
    if ($PGO) {
        Write-Error "'-PGO' is not supported in kernel mode!"
    }
    if ($SharedEC) {
        Write-Error "'-SharedEC' is not supported in kernel mode!"
    }
    if ($XDP) {
        Write-Error "'-XDP' is not supported in kernel mode!"
    }
}
if (!$IsWindows) {
    if ($PGO) {
        Write-Error "'-PGO' is not supported on this platform!"
    }
    if ($XDP) {
        Write-Error "'-XDP' is not supported on this platform!"
    }
}

if (!$IsWindows -and [string]::IsNullOrWhiteSpace($Remote)) {
    $Remote = "quic-server"
}

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

$Record = "None" -ne $LogProfile

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

$TestFileName = ($Protocol -eq "QUIC") ? "RemoteTests.json" : "TcpTests.json"

if ($TestsFile -eq "") {
    $TestsFile = Join-Path $PSScriptRoot $TestFileName
} elseif (-not (Test-Path $TestsFile)) {
    $TestsFile = Join-Path $PSScriptRoot $TestsFile
}

if (-not (Test-Path $TestsFile)) {
    Write-Error "Test file to run not found"
}

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
                    -SharedEC $SharedEC `
                    -XDP $XDP `
                    -Config $Config `
                    -Publish $Publish `
                    -Record $Record `
                    -LogProfile $LogProfile `
                    -RemoteAddress $RemoteAddress `
                    -Session $Session `
                    -Kernel $Kernel `
                    -FailOnRegression $FailOnRegression

$RemotePlatform = Invoke-TestCommand -Session $Session -ScriptBlock {
    if ($IsWindows) {
        return "windows"
    } else {
        return "linux"
    }
}

$OutputDir = Join-Path $RootDir "artifacts/PerfDataResults/$RemotePlatform/$($RemoteArch)_$($Config)_$($RemoteTls)"
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null

$DebugFileName = $Local ? "DebugLogLocal.txt" : "DebugLog.txt"
if ($Kernel) {
    $DebugFileName = "Kernel$DebugFileName"
}
$DebugLogFile = Join-Path $OutputDir $DebugFileName
"" | Out-File $DebugLogFile

Set-DebugLogFile -DebugLogFile $DebugLogFile

$OsBuildNumber = [System.Environment]::OSVersion.Version.Build
Write-LogAndDebug "Running on $OsBuildNumber"

$LocalDirectory = Join-Path $RootDir "artifacts/bin"
$RemoteDirectorySMB = $null

# Copy manifest and log script to local directory
Copy-Item -Path (Join-Path $RootDir scripts log.ps1) -Destination $LocalDirectory
Copy-Item -Path (Join-Path $RootDir scripts xdp-devkit.json) -Destination $LocalDirectory
Copy-Item -Path (Join-Path $RootDir scripts prepare-machine.ps1) -Destination $LocalDirectory
Copy-Item -Path (Join-Path $RootDir scripts xdp-devkit.json) -Destination $LocalDirectory
Copy-Item -Path (Join-Path $RootDir src manifest MsQuic.wprp) -Destination $LocalDirectory

if ($Local) {
    $RemoteDirectory = $LocalDirectory
} else {
    # See if remote SMB path exists
    if (Test-Path "\\$ComputerName\Tests") {
        $RemoteDirectorySMB = "\\$ComputerName\Tests"
        $RemoteDirectory = Invoke-TestCommand -Session $Session -ScriptBlock {
            (Get-SmbShare -Name Tests).Path
        }
    } else {
        # Join path in script to ensure right platform separator
        $RemoteDirectory = Invoke-TestCommand -Session $Session -ScriptBlock {
            Join-Path (Get-Location) "Tests"
        }
    }
}

$CurrentCommitHash = Get-GitHash -RepoDir $RootDir
$CurrentCommitDate = Get-CommitDate -RepoDir $RootDir

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
                Write-LogAndDebug "Temporarily disabling APIPA interfaces"
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
        Write-LogAndDebug "Re-enabling APIPA interfaces"
        $LocalCache.apipaInterfaces | Enable-NetAdapter
    }
}

$RemoteExePath = Get-ExePath -PathRoot $RemoteDirectory -Platform $RemotePlatform -IsRemote $true -ExtraArtifactDir $ExtraArtifactDir
$LocalExePath = Get-ExePath -PathRoot $LocalDirectory -Platform $LocalPlatform -IsRemote $false -ExtraArtifactDir $ExtraArtifactDir

# See if we are an AZP PR
$PrBranchName = $env:SYSTEM_PULLREQUEST_TARGETBRANCH
if ([string]::IsNullOrWhiteSpace($PrBranchName)) {
    # Mainline build, just get branch name
    $AzpBranchName = $env:BUILD_SOURCEBRANCH
    if ([string]::IsNullOrWhiteSpace($AzpBranchName)) {
        # Non azure build
        $BranchName = Get-CurrentBranch -RepoDir $RootDir
    } else {
        # Azure Build
        $BuildReason = $env:BUILD_REASON
        if ("Manual" -eq $BuildReason) {
            $BranchName = "main"
        } else {
            $BranchName = $AzpBranchName.Substring(11);
        }
    }
} else {
    # PR Build
    $BranchName = $PrBranchName
}

if (![string]::IsNullOrWhiteSpace($ForceBranchName)) {
    $BranchName = $ForceBranchName
}

$LastCommitHashes = Get-LatestCommitHashes -Branch $BranchName
$PreviousResults = Get-LatestCpuTestResults -Branch $BranchName -CommitHashes $LastCommitHashes

function Invoke-Test {
    param ([TestRunDefinition]$Test, [RemoteConfig]$RemoteConfig)

    Write-Output "Running Test $Test"

    $RemoteExe = Get-ExeName -PathRoot $RemoteDirectory -Platform $RemotePlatform -IsRemote $true -TestPlat $RemoteConfig -ExtraArtifactDir $ExtraArtifactDir
    $LocalExe = Get-ExeName -PathRoot $LocalDirectory -Platform $LocalPlatform -IsRemote $false -TestPlat $Test.Local -ExtraArtifactDir $ExtraArtifactDir

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

    $RemoteArguments = $RemoteConfig.Arguments

    if ($LocalArguments.Contains("-stats:1")) {
        $RemoteArguments += " -stats:1"
    }

    if ($XDP) {
        $RemoteArguments += " -cpu:-1"
        $LocalArguments += " -cpu:-1"
    }

    if ($Kernel) {
        $Arch = Split-Path (Split-Path $LocalExe -Parent) -Leaf
        $RootBinPath = Split-Path (Split-Path (Split-Path $LocalExe -Parent) -Parent) -Parent
        $KernelDir = Join-Path $RootBinPath "winkernel" $Arch

        Copy-Item (Join-Path $KernelDir "secnetperfdrvpriv.sys") (Split-Path $LocalExe -Parent)
        Copy-Item (Join-Path $KernelDir "msquicpriv.sys") (Split-Path $LocalExe -Parent)

        $LocalArguments = "-driverNamePriv:secnetperfdrvpriv $LocalArguments"
    }

    if ($IsWindows) {
        # Copy to tmp folder
        $CopyToDirectory = "C:\RunningTests"
        New-Item -Path $CopyToDirectory -ItemType Directory -Force | Out-Null
        $ExeFolder = Split-Path $LocalExe -Parent
        Copy-Item -Path "$ExeFolder\*" -Destination $CopyToDirectory -Recurse -Force
        $LocalExe = Join-Path $CopyToDirectory (Split-Path $LocalExe -Leaf)
    }

    Write-LogAndDebug "Running Remote: $RemoteExe Args: $RemoteArguments"

    # Starting the server
    $RemoteJob = Invoke-RemoteExe -Exe $RemoteExe -RunArgs $RemoteArguments -RemoteDirectory $RemoteDirectory
    $ReadyToStart = Wait-ForRemoteReady -Job $RemoteJob -Matcher $Test.RemoteReadyMatcher

    if (!$ReadyToStart) {
        Stop-Job -Job $RemoteJob
        $RetVal = Receive-Job -Job $RemoteJob
        $RetVal = $RetVal -join "`n"
        Cancel-RemoteLogs -RemoteDirectory $RemoteDirectory
        Write-Error "Test Remote for $Test failed to start: $RetVal"
    }

    $AllRunsResults = @()

    Start-Tracing -LocalDirectory $LocalDirectory

    $NumIterations = $Test.Iterations
    if ($ForceIterations -gt 0) {
        $NumIterations = $ForceIterations
    }

    try {
        1..$NumIterations | ForEach-Object {
            Write-LogAndDebug "Running Local: $LocalExe Args: $LocalArguments"
            $LocalResults = Invoke-LocalExe -Exe $LocalExe -RunArgs $LocalArguments -Timeout $Timeout -OutputDir $OutputDir
            Write-LogAndDebug $LocalResults
            $AllLocalParsedResults = Get-TestResult -Results $LocalResults -Matcher $Test.ResultsMatcher
            $AllRunsResults += $AllLocalParsedResults
            if ($PGO) {
                # Merge client PGO Counts
                Merge-PGOCounts -Path $LocalExePath
            }

            $FormattedStrings = @()

            for ($i = 1; $i -lt $AllLocalParsedResults.Count; $i++) {
                $Formatted = [string]::Format($Test.Formats[$i - 1], $AllLocalParsedResults[$i])
                $FormattedStrings += $Formatted
            }

            $Joined = [string]::Join(", ", $FormattedStrings)

            $OutputString = "Run $($_): $Joined"

            Write-Output $OutputString
            $LocalResults | Write-LogAndDebug
        }
    } finally {
        $RemoteResults = Wait-ForRemote -Job $RemoteJob
        Write-LogAndDebug $RemoteResults.ToString()

        Stop-RemoteLogs -RemoteDirectory $RemoteDirectory

        if ($Kernel) {
            net.exe stop secnetperfdrvpriv /y | Out-Null
            net.exe stop msquicpriv /y | Out-Null
            sc.exe delete secnetperfdrvpriv | Out-Null
            sc.exe delete msquicpriv | Out-Null
        }

        Stop-Tracing -LocalDirectory $LocalDirectory -OutputDir $OutputDir -Test $Test

        if ($Record) {
            if ($Local) {
                $LocalLogPath = (Join-Path $RemoteDirectory serverlogs)
                Copy-Item -Path $LocalLogPath -Destination (Join-Path $OutputDir $Test.ToString()) -Recurse -Force
                try {
                    Remove-Item -Path "$LocalLogPath/*" -Recurse -Force
                } catch [System.Management.Automation.ItemNotFoundException] {
                    # Ignore Not Found for when the directory does not exist
                    # This will still throw if a file cannot successfuly be deleted
                }
            } else {
                try {
                    Get-RemoteLogDirectory -Local (Join-Path $OutputDir $Test.ToString()) -Remote (Join-Path $RemoteDirectory serverlogs) -SmbDir (Join-Path $RemoteDirectorySMB serverlogs) -Cleanup
                } catch {
                    Write-Host "Failed to get remote logs"
                }
            }
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
                        -CurrentCommitDate $CurrentCommitDate `
                        -PreviousResults $PreviousResults `
                        -OutputDir $OutputDir `
                        -ExePath $LocalExe
}

$LocalDataCache = LocalSetup

if ($Record -and $IsWindows) {
    try { wpr.exe -cancel -instancename msquicperf 2> $null } catch { }
    Invoke-TestCommand -Session $Session -ScriptBlock {
        try { wpr.exe -cancel -instancename msquicperf 2> $null } catch { }
    }
}

try {
    [TestRunConfig]$Tests = Get-Tests -Path $TestsFile -RemotePlatform $RemotePlatform -LocalPlatform $LocalPlatform

    if ($null -eq $Tests) {
        Write-Error "Tests are not valid"
    }

    Remove-PerfServices

    if ($IsWindows) {
        Cancel-RemoteLogs -RemoteDirectory $RemoteDirectory

        try {
            $CopyToDirectory = "C:\RunningTests"
            Remove-Item -Path "$CopyToDirectory/*" -Recurse -Force
        } catch [System.Management.Automation.ItemNotFoundException] {
            # Ignore Not Found for when the directory does not exist
            # This will still throw if a file cannot successfuly be deleted
        }
    }

    # Find All Remote processes, and kill them
    if (!$Local) {
        $ExeName = $Tests.Remote.Exe
        Invoke-TestCommand -Session $Session -ScriptBlock {
            param ($ExeName)
            try {
                Stop-Process -Name $ExeName -Force
            } catch {
            }
        } -ArgumentList $ExeName
    }

    if (!$SkipDeploy -and !$Local) {
        Copy-Artifacts -From $LocalDirectory -To $RemoteDirectory -SmbDir $RemoteDirectorySMB
    }

    Cancel-LocalTracing -LocalDirectory $LocalDirectory
    Cancel-RemoteLogs -RemoteDirectory $RemoteDirectory

    Invoke-Expression "$(Join-Path $LocalDirectory prepare-machine.ps1) -UninstallXdp"
    if (!$Local) {
        Invoke-TestCommand -Session $Session -ScriptBlock {
            param ($RemoteDirectory)
            Invoke-Expression "$(Join-Path $RemoteDirectory prepare-machine.ps1) -UninstallXdp"
        } -ArgumentList $RemoteDirectory
    }

    if ($XDP) {
        Invoke-Expression "$(Join-Path $LocalDirectory prepare-machine.ps1) -InstallXdpDriver -Force"
        Invoke-TestCommand -Session $Session -ScriptBlock {
            param ($RemoteDirectory)
            Invoke-Expression "$(Join-Path $RemoteDirectory prepare-machine.ps1) -InstallXdpDriver -Force"
        } -ArgumentList $RemoteDirectory
    }

    foreach ($Test in $Tests.Tests) {
        if ($TestToRun -ne "" -and $Test.TestName -ne $TestToRun) {
            continue
        }
        Invoke-Test -Test $Test -RemoteConfig $Tests.Remote
    }

    if ($PGO) {
        Write-Host "Saving msquic.pgd out for publishing."
        Copy-Item "$LocalExePath\msquic.pgd" $OutputDir
    }

    Check-Regressions
} finally {
    if ($XDP) {
        Invoke-Expression "$(Join-Path $LocalDirectory prepare-machine.ps1) -UninstallXdp"
        Invoke-TestCommand -Session $Session -ScriptBlock {
            param ($RemoteDirectory)
            Invoke-Expression "$(Join-Path $RemoteDirectory prepare-machine.ps1) -UninstallXdp"
        } -ArgumentList $RemoteDirectory
    }
    if ($null -ne $Session) {
        Remove-PSSession -Session $Session
    }
    LocalTeardown($LocalDataCache)
}
