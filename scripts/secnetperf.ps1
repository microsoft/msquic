<#

NOTE:

This script assumes the latest MsQuic commit is built and downloaded as artifacts in the current session.

.PARAMETER LogProfile
    Configures the logging scope for the test. None by default.

.PARAMETER MsQuicCommit
    The MsQuic commit to use for the test. Defaults to "manual" which means the latest commit built and downloaded as artifacts in the current session.

.PARAMETER ClientOS
    The OS of the client machine. Defaults to "Windows Server 2022".

.PARAMETER ClientArch
    The architecture of the client machine. Defaults to "x64".

.PARAMETER ClientCpu
    The CPU of the client machine. Defaults to "Intel(R) Xeon(R) Platinum 8272CL CPU @ 2.60GHz".

.PARAMETER ClientNic
    The NIC of the client machine. Defaults to "Mellanox ConnectX-5".

.PARAMETER ServerOS
    The OS of the server machine. Defaults to "Windows Server 2022".

.PARAMETER ServerArch
    The architecture of the server machine. Defaults to "x64".

.PARAMETER ServerCpu
    The CPU of the server machine. Defaults to "Intel(R) Xeon(R) Platinum 8272CL CPU @ 2.60GHz".

.PARAMETER ServerNic
    The NIC of the server machine. Defaults to "Mellanox ConnectX-5".

#>

param (
    [ValidateSet("", "NULL", "Basic.Light", "Datapath.Light", "Datapath.Verbose", "Stacks.Light", "Stacks.Verbose", "RPS.Light", "RPS.Verbose", "Performance.Light", "Basic.Verbose", "Performance.Light", "Performance.Verbose", "Full.Light", "Full.Verbose", "SpinQuic.Light", "SpinQuicWarnings.Light")]
    [string]$LogProfile = "",

    [string]$MsQuicCommit = "manual",

    [Parameter(Mandatory = $false)]
    [string]$ClientOS = "Windows Server 2022",

    [Parameter(Mandatory = $false)]
    [string]$ClientArch = "x64",

    [Parameter(Mandatory = $false)]
    [string]$ClientCpu = "Intel(R) Xeon(R) Platinum 8272CL CPU @ 2.60GHz",

    [Parameter(Mandatory = $false)]
    [string]$ClientNic = "Mellanox ConnectX-5",

    [Parameter(Mandatory = $false)]
    [string]$ServerOS = "Windows Server 2022",

    [Parameter(Mandatory = $false)]
    [string]$ServerArch = "x64",

    [Parameter(Mandatory = $false)]
    [string]$ServerCpu = "Intel(R) Xeon(R) Platinum 8272CL CPU @ 2.60GHz",

    [Parameter(Mandatory = $false)]
    [string]$ServerNic = "Mellanox ConnectX-5"
)

# Get the current date and time
$currentDate = Get-Date

# Define the Pacific Standard Time zone ID
# Note: Windows time zones might not use "PST" as the identifier.
# Instead, it often uses specific city names or "Pacific Standard Time"
$pstZoneId = "Pacific Standard Time"

# Get the TimeZoneInfo object for Pacific Standard Time
$pstZone = [TimeZoneInfo]::FindSystemTimeZoneById($pstZoneId)

# Convert the current date and time to Pacific Standard Time
$pstDate = [TimeZoneInfo]::ConvertTime($currentDate, $pstZone)

# Format the date in the "yyyy-MM-dd-HH-mm-ss" format
$formattedDate = $pstDate.ToString("yyyy-MM-dd-HH-mm-ss")

$ThisTest = @{}

$ThisTest["RunDate"] = $formattedDate

$ThisTest["MachineName"] = $env:COMPUTERNAME

$ThisEnvironment = @{
    "Client" = @{
        "OS" = $ClientOS
        "Arch" = $ClientArch
        "CPU" = $ClientCpu
        "NIC" = $ClientNic
    };
    "Server" = @{
        "OS" = $ServerOS
        "Arch" = $ServerArch
        "CPU" = $ServerCpu
        "NIC" = $ServerNic
    }
}

$ThisConfiguration = @{
    "MsQuicCommit" = $MsQuicCommit
    "PerfTool" = "secnetperf"
}

$ThisTest["TestEnv"] = $ThisEnvironment
$ThisTest["TestConfig"] = $ThisConfiguration





# Set up the connection to the peer over remote powershell.
Write-Output "Connecting to netperf-peer..."
$Session = New-PSSession -ComputerName "netperf-peer" -ConfigurationName PowerShell.7
if ($null -eq $Session) {
    Write-Error "Failed to create remote session"
    exit
}
$RemoteAddress = $Session.ComputerName
Write-Output "Successfully conencted to peer: $RemoteAddress"

# Make sure nothing is running from a previous run.
Invoke-Command -Session $Session -ScriptBlock {
    Get-Process | Where-Object { $_.Name -eq "secnetperf.exe" } | Stop-Process
}

# Copy the artifacts to the peer.
Write-Output "Copying files to peer..."
Invoke-Command -Session $Session -ScriptBlock {
    Remove-Item -Force -Recurse "C:\_work" -ErrorAction Ignore
}
Copy-Item -ToSession $Session .\artifacts -Destination C:\_work\quic\artifacts -Recurse
Copy-Item -ToSession $Session .\scripts -Destination C:\_work\quic\scripts -Recurse

try {

mkdir .\artifacts\logs | Out-Null

# Prepare the machines for the testing.
Write-Output "Preparing machines for testing..."
.\scripts\prepare-machine.ps1 -ForTest
Invoke-Command -Session $Session -ScriptBlock {
    C:\_work\quic\scripts\prepare-machine.ps1 -ForTest
}

# Logging to collect quic traces while running the tests.

if ($LogProfile -ne "" -and $LogProfile -ne "NULL") {
    Write-Output "Starting logging with log profile: $LogProfile..."
    .\scripts\log.ps1 -Start -Profile $LogProfile
}

# Run secnetperf on the server.
Write-Output "Starting secnetperf server..."
$Job = Invoke-Command -Session $Session -ScriptBlock {
    C:\_work\quic\artifacts\bin\windows\x64_Release_schannel\secnetperf.exe -exec:maxtput
} -AsJob

# Wait for the server to start.
Write-Output "Waiting for server to start..."
Start-Sleep -Seconds 10

# Run secnetperf on the client.
Write-Output "Running tests on the client..."

# Define the array of Secnetperf run commands
# TODO: Add more tests here. Include TCP tests too.
$commands = @(
    ".\artifacts\bin\windows\x64_Release_schannel\secnetperf.exe -target:netperf-peer -exec:maxtput -test:tput -upload:10000 -timed:1",
    ".\artifacts\bin\windows\x64_Release_schannel\secnetperf.exe -target:netperf-peer -exec:maxtput -test:tput -upload:10000 -timed:1 -tcp:1"
)
# Along with their metadata
$commandMetadata = @(
    "Max throughput test using QUIC protocol with -upload:10000, -timed:1",
    "Max throughput test using TCP protocol with -upload:10000, -timed:1"
)

$ConsoleOutput = @{}

for ($i = 0; $i -lt $commands.Count; $i++) {
    Write-Output "Running test: $($commandMetadata[$i])"
    $Output = Invoke-Expression $commands[$i]
    $Output
    $ConsoleOutput[$commandMetadata[$i]] = $Output
    # Wait for a bit in between tests.
    Start-Sleep -Seconds 1
}

if ($LogProfile -ne "" -and $LogProfile -ne "NULL") {
    Write-Output "Stopping logging..."
    .\scripts\log.ps1 -Stop -OutputPath .\artifacts\logs\quic
}
#Get-Content .\artifacts\logs\quic.log

function Wait-ForRemote {
    param ($Job, $ErrorAction = "Stop")
    # Ping side-channel socket on 9999 to tell the app to die
    $Socket = New-Object System.Net.Sockets.UDPClient
    $BytesToSend = @(
        0x57, 0xe6, 0x15, 0xff, 0x26, 0x4f, 0x0e, 0x57,
        0x88, 0xab, 0x07, 0x96, 0xb2, 0x58, 0xd1, 0x1c
    )
    for ($i = 0; $i -lt 120; $i++) {
        $Socket.Send($BytesToSend, $BytesToSend.Length, $RemoteAddress, 9999) | Out-Null
        $Completed = Wait-Job -Job $Job -Timeout 1
        if ($null -ne $Completed) {
            break;
        }
    }

    Stop-Job -Job $Job | Out-Null
    $RetVal = Receive-Job -Job $Job -ErrorAction $ErrorAction
    return $RetVal -join "`n"
}

# Kill the server process.
Write-Output Wait-ForRemote $Job

# Save the test results.
Write-Output "Saving test results..."
$ThisTest["TestRuns"] = $ConsoleOutput
$jsonString = $ThisTest | ConvertTo-Json -Depth 10
Set-Content -Path 'test_result.json' -Value $jsonString

} finally {
    # TODO: Do any further book keeping here.
}
