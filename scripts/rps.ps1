<#

.SYNOPSIS
Runs the client side of the RPS performance tests for multiple different
configurations.

.PARAMETER Target
    The name or IP address of the server machine to connect to.

.PARAMETER Iterations
    The number of runs for each configuration.

#>

param (
    [Parameter(Mandatory = $false)]
    [string]$Target = "quic-server",

    [Parameter(Mandatory = $false)]
    [Int32]$Iterations = 5
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Run through all the different connection counts from 100 to 3000.
for ($Count=100; $Count -le 3000; $Count+=100) {
    Write-Host "==$($Count)c=="
    for ($i=0; $i -lt $Iterations; $i++) {
        (.\quicperf.exe `
            -TestName:RPS `
            -Target:$Target `
            -conns:$Count) | Select-Object -Last 1
        Start-Sleep -Milliseconds 2000
    }
}
