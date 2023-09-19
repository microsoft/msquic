
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

# Run secnetperf on the server.
Write-Output "Starting secnetperf server..."
$Job = Invoke-Command -Session $Session -ScriptBlock {
    C:\_work\quic\artifacts\bin\windows\x64_Release_schannel\secnetperf.exe -exec:maxtput
} -AsJob

# Run secnetperf on the client.
Write-Output "Running tests on the client..."
for ($i = 0; $i -lt 5; $i++) {
    Write-Output "Running test $i..."
    .\artifacts\bin\windows\x64_Release_schannel\secnetperf.exe -target:netperf-peer -exec:maxtput -test:tput -upload:10000 -timed:1
}

# Kill the server process.
Invoke-Command -Session $Session -ScriptBlock {
    Get-Process | Where-Object { $_.Name -eq "secnetperf.exe" } | Stop-Process
}
