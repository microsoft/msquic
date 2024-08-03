<#

NOTE:

This script assumes the latest MsQuic commit is built and downloaded as artifacts in the current session.

.PARAMETER LogProfile
    Configures the logging scope for the test. None by default.

.PARAMETER MsQuicCommit
    The MsQuic commit to use for the test. Defaults to "manual" which means the latest commit built and downloaded as artifacts in the current session.

.PARAMETER plat
    The platform (linux or windows) this test is running on.

.PARAMETER os
    The full OS name and version being tested (i.e., ubuntu-20.04).

.PARAMETER arch
    The architecture being tested (i.e., x64).

.PARAMETER tls
    The TLS library being used (openssl or schannel). Not all libraries are supported on all platforms.

.PARAMETER io
    The network IO interface to be used (not all are supported on all platforms).

.PARAMETER filter
    Run only the tests whose arguments match one of the positive patterns but
    none of the negative patterns (prefixed by '-'). '?' matches any single
    character; '*' matches any substring; ';' separates two patterns.

#>

# Import the helper module.
Using module .\secnetperf-helpers.psm1

param (
    [ValidateSet("", "NULL", "Basic.Light", "Datapath.Light", "Datapath.Verbose", "Stacks.Light", "Stacks.Verbose", "RPS.Light", "RPS.Verbose", "Performance.Light", "Basic.Verbose", "Performance.Light", "Performance.Verbose", "Full.Light", "Full.Verbose", "SpinQuic.Light", "SpinQuicWarnings.Light")]
    [string]$LogProfile = "",

    [Parameter(Mandatory = $true)]
    [string]$MsQuicCommit = "manual",

    [Parameter(Mandatory = $true)]
    [string]$environment = "azure",

    [Parameter(Mandatory = $true)]
    [ValidateSet("windows", "linux")]
    [string]$plat = "windows",

    [Parameter(Mandatory = $true)]
    [string]$os = "windows-2022",

    [Parameter(Mandatory = $true)]
    [ValidateSet("x64", "arm64")]
    [string]$arch = "x64",

    [Parameter(Mandatory = $true)]
    [ValidateSet("openssl", "openssl3", "schannel")]
    [string]$tls = "schannel",

    [Parameter(Mandatory = $false)]
    [ValidateSet("", "iocp", "rio", "xdp", "qtip", "wsk", "epoll", "kqueue")]
    [string]$io = "",

    [Parameter(Mandatory = $false)]
    [string]$filter = "",

    [Parameter(Mandatory = $false)]
    [string]$RemoteName = "netperf-peer",

    [Parameter(Mandatory = $false)]
    [string]$UserName = "secnetperf"
)

Set-StrictMode -Version "Latest"
$PSDefaultParameterValues["*:ErrorAction"] = "Stop"


$RemotePowershellSupported = $env:netperf_remote_powershell_supported
$RunId = $env:netperf_run_id
$SyncerSecret = $env:netperf_syncer_secret

$psVersion = $PSVersionTable.PSVersion
if ($psVersion.Major -lt 7) {
    $IsWindows = $true
}

Write-Host "Running tests with the following parameters:"
Write-Host "$RemotePowershellSupported, $RunId"

# Set up some important paths.
$RemoteDir = "C:/_work/quic"
if (!$isWindows) {
    if ($UserName -eq "root") {
        $RemoteDir = "/$UserName/_work/quic"
    } else {
        $RemoteDir = "/home/$UserName/_work/quic"
    }
}

$SecNetPerfDir = "artifacts/bin/$plat/$($arch)_Release_$tls"
$SecNetPerfPath = "$SecNetPerfDir/secnetperf"
if ($io -eq "") {
    if ($isWindows) {
        $io = "iocp"
    } else {
        $io = "epoll"
    }
}
$NoLogs = ($LogProfile -eq "" -or $LogProfile -eq "NULL")
if ($isWindows -and $NoLogs) {
    # Always collect basic, low volume logs on Windows.
    $LogProfile = "Basic.Light"
}

$useXDP = ($io -eq "xdp" -or $io -eq "qtip")
if ($RemotePowershellSupported -eq $true) {

    # Set up the connection to the peer over remote powershell.
    Write-Host "Connecting to $RemoteName"
    $Attempts = 0
    while ($Attempts -lt 5) {
        if ($environment -eq "azure") {
            if ($isWindows) {
                Write-Host "Attempting to connect..."
                $Session = New-PSSession -ComputerName $RemoteName -ConfigurationName PowerShell.7
                break
            } else {
                # On Azure in 1ES Linux environments, remote powershell is not supported (yet).
                $Session = "NOT_SUPPORTED"
                Write-Host "Remote PowerShell is not supported in Azure 1ES Linux environments"
                break
            }
        }
        try {
            if ($isWindows) {
                $username = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon').DefaultUserName
                $password = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon').DefaultPassword | ConvertTo-SecureString -AsPlainText -Force
                $cred = New-Object System.Management.Automation.PSCredential ($username, $password)
                $Session = New-PSSession -ComputerName $RemoteName -Credential $cred -ConfigurationName PowerShell.7
            } else {
                $Session = New-PSSession -HostName $RemoteName -UserName $UserName -SSHTransport
            }
            break
        } catch {
            Write-Host "Error $_"
            $Attempts += 1
            Start-Sleep -Seconds 10
        }
    }

    if ($null -eq $Session) {
        Write-GHError "Failed to create remote session"
        exit 1
    }

} else {
    $Session = "NOT_SUPPORTED"
    Write-Host "Remote PowerShell is not supported in this environment"
}

if ($Session -ne "NOT_SUPPORTED") {
    # Make sure nothing is running from a previous run. This only applies to non-azure / 1ES environments.
    Write-Host "NOT RUNNING ON AZURE AND POWERSHELL SUPPORTED"
    Write-Host "Session: $Session, $(!($Session -eq "NOT_SUPPORTED"))"
    Cleanup-State $Session $RemoteDir
}

# Create intermediary files.
New-Item -ItemType File -Name "latency.txt"

if ($io -eq "wsk") {
    # WSK also needs the kernel mode binaries in the usermode path.
    Write-Host "Moving kernel binaries to usermode path"
    $KernelDir = "artifacts/bin/winkernel/$($arch)_Release_$tls"
    Copy-Item "$KernelDir/secnetperfdrvpriv.sys" $SecNetPerfDir
    Copy-Item "$KernelDir/secnetperfdrvpriv.pdb" $SecNetPerfDir
    Copy-Item "$KernelDir/msquicpriv.sys" $SecNetPerfDir
    Copy-Item "$KernelDir/msquicpriv.pdb" $SecNetPerfDir
    # Remove all the other kernel binaries since we don't need them any more.
    Remove-Item -Force -Recurse $KernelDir | Out-Null
}


if (!($Session -eq "NOT_SUPPORTED")) {
    # Copy the artifacts to the peer.
    Write-Host "Copying files to peer"
    Invoke-Command -Session $Session -ScriptBlock {
        if (Test-Path $Using:RemoteDir) {
            Remove-Item -Force -Recurse $Using:RemoteDir | Out-Null
        }
        New-Item -ItemType Directory -Path $Using:RemoteDir -Force | Out-Null
    }
    Copy-Item -ToSession $Session ./artifacts -Destination "$RemoteDir/artifacts" -Recurse
    Copy-Item -ToSession $Session ./scripts -Destination "$RemoteDir/scripts" -Recurse
    Copy-Item -ToSession $Session ./src/manifest/MsQuic.wprp -Destination "$RemoteDir/scripts"

    # Create the logs directories on both machines.
    New-Item -ItemType Directory -Path ./artifacts/logs | Out-Null
    Invoke-Command -Session $Session -ScriptBlock {
        New-Item -ItemType Directory -Path $Using:RemoteDir/artifacts/logs | Out-Null
    }
}

# Collect some info about machine state.
if (!$NoLogs -and $isWindows -and !($Session -eq "NOT_SUPPORTED")) {
    $Arguments = "-SkipNetsh"
    if (Get-Help Get-NetView -Parameter SkipWindowsRegistry -ErrorAction Ignore) {
        $Arguments += " -SkipWindowsRegistry"
    }
    if (Get-Help Get-NetView -Parameter SkipNetshTrace -ErrorAction Ignore) {
        $Arguments += " -SkipNetshTrace"
    }

    Write-Host "::group::Collecting information on local machine state"
    try {
        Invoke-Expression "Get-NetView -OutputDirectory ./artifacts/logs $Arguments"
        Remove-Item ./artifacts/logs/msdbg.$env:COMPUTERNAME -recurse
        $filePath = (Get-ChildItem -Path ./artifacts/logs/ -Recurse -Filter msdbg.$env:COMPUTERNAME*.zip)[0].FullName
        Rename-Item $filePath "get-netview.local.zip"
        Write-Host "Generated get-netview.local.zip"
    } catch { Write-Host $_ }
    Write-Host "::endgroup::"

    Write-Host "::group::Collecting information on peer machine state"
    try {
        Invoke-Command -Session $Session -ScriptBlock {
            Invoke-Expression "Get-NetView -OutputDirectory $Using:RemoteDir/artifacts/logs $Using:Arguments"
            Remove-Item $Using:RemoteDir/artifacts/logs/msdbg.$env:COMPUTERNAME -recurse
            $filePath = (Get-ChildItem -Path $Using:RemoteDir/artifacts/logs/ -Recurse -Filter msdbg.$env:COMPUTERNAME*.zip)[0].FullName
            Rename-Item $filePath "get-netview.peer.zip"
        }
        Copy-Item -FromSession $Session -Path "$RemoteDir/artifacts/logs/get-netview.peer.zip" -Destination ./artifacts/logs/
        Write-Host "Generated get-netview.peer.zip"
    } catch { Write-Host $_ }
    Write-Host "::endgroup::"
}

$json = @{}
$json["commit"] = "$MsQuicCommit"
# Persist environment information:
if ($isWindows) {
    $windowsEnv = Get-CimInstance Win32_OperatingSystem | Select-Object Version
    $json["os_version"] = $windowsEnv.Version
} else {
    $osInfo = bash -c "cat /etc/os-release"
    $osInfoLines = $osInfo -split "`n"
    $osName = $osInfoLines | Where-Object { $_ -match '^PRETTY_NAME=' } | ForEach-Object { $_ -replace '^PRETTY_NAME="|"$', '' }
    $kernelVersion = bash -c "uname -r"
    $json["os_version"] = "$osName $kernelVersion"
}
$allTests = [System.Collections.Specialized.OrderedDictionary]::new()

# > All tests:
$allTests["tput-up"] = "-exec:maxtput -up:12s -ptput:1"
$allTests["tput-down"] = "-exec:maxtput -down:12s -ptput:1"
$allTests["hps-conns-100"] = "-exec:maxtput -rconn:1 -share:1 -conns:100 -run:12s -prate:1"
$allTests["rps-up-512-down-4000"] = "-exec:lowlat -rstream:1 -up:512 -down:4000 -run:20s -plat:1"

$hasFailures = $false
$json["run_args"] = $allTests

try {

# Prepare the machines for the testing.
if ($isWindows -and !($environment -eq "azure")) {
    Write-Host "Preparing local machine for testing"
    ./scripts/prepare-machine.ps1 -ForTest -InstallSigningCertificates

    Write-Host "Preparing peer machine for testing"
    Invoke-Command -Session $Session -ScriptBlock {
        & "$Using:RemoteDir/scripts/prepare-machine.ps1" -ForTest -InstallSigningCertificates
    }

    $HasTestSigning = $false
    try { $HasTestSigning = ("$(bcdedit)" | Select-String -Pattern "testsigning\s+Yes").Matches.Success } catch { }
    if (!$HasTestSigning) { Write-Host "Test Signing Not Enabled!" }
}

if (!($Session -eq "NOT_SUPPORTED")) {
    # Configure the dump collection.
    Configure-DumpCollection $Session
}

# Install any dependent drivers.
if ($useXDP -and $isWindows) { Install-XDP $Session $RemoteDir }
if ($io -eq "wsk") { Install-Kernel $Session $RemoteDir $SecNetPerfDir }

if (!$isWindows) {
    # Make sure the secnetperf binary is executable.
    Write-Host "Updating secnetperf permissions"
    $GRO = "on"
    if ($io -eq "xdp") {
        $GRO = "off"
    }
    if (!($Session -eq "NOT_SUPPORTED")) {
        Invoke-Command -Session $Session -ScriptBlock {
            $env:LD_LIBRARY_PATH = "${env:LD_LIBRARY_PATH}:$Using:RemoteDir/$Using:SecNetPerfDir"
            chmod +x "$Using:RemoteDir/$Using:SecNetPerfPath"
            if ($Using:os -eq "ubuntu-22.04") {
                sudo sh -c "ethtool -K eth0 generic-receive-offload $Using:GRO"
            }
        }
    }
    $fullPath = Repo-Path $SecNetPerfDir
    $env:LD_LIBRARY_PATH = "${env:LD_LIBRARY_PATH}:$fullPath"
    chmod +x "./$SecNetPerfPath"
    if ($os -eq "ubuntu-22.04") {
        sudo sh -c "ethtool -K eth0 generic-receive-offload $GRO"
    }

    if ((Get-Content "/etc/security/limits.conf") -notcontains "root soft core unlimited") {
        # Enable core dumps for the system.
        Write-Host "Setting core dump size limit"
        sudo sh -c "echo "root soft core unlimited" >> /etc/security/limits.conf"
        sudo sh -c "echo "root hard core unlimited" >> /etc/security/limits.conf"
        sudo sh -c "echo "* soft core unlimited" >> /etc/security/limits.conf"
        sudo sh -c "echo "* hard core unlimited" >> /etc/security/limits.conf"
        # Increase the number of file descriptors.
        sudo sh -c "echo 'root soft nofile 1048576' >> /etc/security/limits.conf"
        sudo sh -c "echo 'root hard nofile 1048576' >> /etc/security/limits.conf"
        sudo sh -c "echo '* soft nofile 1048576' >> /etc/security/limits.conf"
        sudo sh -c "echo '* hard nofile 1048576' >> /etc/security/limits.conf"
    }

    # Set the core dump pattern.
    Write-Host "Setting core dump pattern"
    sudo sh -c "echo -n "%e.client.%p.%t.core" > /proc/sys/kernel/core_pattern"
}

Write-Host "Fetching watermark_regression.json"
$regressionJson = Get-Content -Raw -Path "watermark_regression.json" | ConvertFrom-Json

# Run all the test cases.
Write-Host "Setup complete! Running all tests"
foreach ($testId in $allTests.Keys) {
    $ExeArgs = $allTests[$testId] + " -io:$io"
    $Output = Invoke-Secnetperf $Session $RemoteName $RemoteDir $UserName $SecNetPerfPath $LogProfile $testId $ExeArgs $io $filter $environment $RunId $SyncerSecret
    $Test = $Output[-1]
    if ($Test.HasFailures) { $hasFailures = $true }

    for ($tcp = 0; $tcp -lt $Test.Values.Length; $tcp++) {
        if ($Test.Values[$tcp].Length -eq 0) { continue }
        if ($tcp -eq 1) {
            $transport = "tcp"
        } else {
            $transport = "quic"
        }
        $json["$testId-$transport"] = $Test.Values[$tcp]

        if ($Test.Metric -eq "latency") {
            $json["$testId-$transport-lat"] = $Test.Latency[$tcp]
            $LatencyRegression = CheckRegressionLat $Test.Values[$tcp] $regressionJson $testId $transport "$os-$arch-$environment-$io-$tls"
            $json["$testId-$transport-regression"] = $LatencyRegression
        } else {
            $ResultRegression = CheckRegressionResult $Test.Values[$tcp] $testId $transport $regressionJson "$os-$arch-$environment-$io-$tls"
            $json["$testId-$transport-regression"] = $ResultRegression
        }
    }
}

Write-Host "Tests complete!"

} catch {
    Write-GHError "Exception while running tests!"
    Write-GHError $_
    Get-Error
    $_ | Format-List *
    $hasFailures = $true
} finally {

    # Perform any necessary cleanup.
    try {
        if ($Session -eq "NOT_SUPPORTED") {
            throw "Cleanup not needed"
        }
        Cleanup-State $Session $RemoteDir
     } catch { }

    try {
        if (Get-ChildItem -Path ./artifacts/logs -File -Recurse) {
            # Logs or dumps were generated. Copy the necessary symbols/files to
            # the same direcotry be able to open them.
            Write-Host "Copying debugging files to logs directory"
            if ($isWindows) {
                Copy-Item "$SecNetPerfDir/*.pdb" ./artifacts/logs
            } else {
                Copy-Item "$SecNetPerfDir/libmsquic.so" ./artifacts/logs
                Copy-Item "$SecNetPerfDir/secnetperf" ./artifacts/logs
            }
        }
    } catch { }

    # Save the test results.
    Write-Host "`Writing json-test-results-$environment-$os-$arch-$tls-$io.json"
    $json | ConvertTo-Json -Depth 4 | Set-Content -Path "json-test-results-$environment-$os-$arch-$tls-$io.json"
}

# Clear out any exit codes from previous commands.
$global:LastExitCode = 0

if ($hasFailures) {
    exit 1
}
