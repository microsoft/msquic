
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

.\scripts\log.ps1 -Start -Profile Full.Light

# Run secnetperf on the server.
Write-Output "Starting secnetperf server..."
$Job = Invoke-Command -Session $Session -ScriptBlock {
    C:\_work\quic\artifacts\bin\windows\x64_Release_schannel\secnetperf.exe -exec:maxtput
} -AsJob

# Run secnetperf on the client.
Write-Output "Running tests on the client..."
for ($i = 0; $i -lt 1; $i++) {
    Write-Output "Running test $i..."
    .\artifacts\bin\windows\x64_Release_schannel\secnetperf.exe -target:netperf-peer -exec:maxtput -test:tput -upload:10000 -timed:1
}

.\scripts\log.ps1 -Stop -OutputPath .\artifacts\logs\quic
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

} finally {

# Grab other logs
Write-Output "Grabbing registry..."
reg export "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileNotification" .\artifacts\logs\ProfileNotification.reg
Write-Output "Grabbing profsvc logs..."
dir C:\Windows\system32\Logfiles\WMI\prof*
Write-Output "Stopping session..."
logman stop profsvc -ets -ErrorAction Ignore
Start-Sleep 5
Write-Output "Copying profsvc logs..."
Copy-Item $env:WINDIR\System32\LogFiles\WMI\profsvc.etl.* .\artifacts\logs
dir .\artifacts\logs
#netsh trace convert .\artifacts\logs\profsvc.etl

}
