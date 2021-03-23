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
    [Int32]$Iterations = 3
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Run through all the different connection and request counts.
for ($Conns=100; $Conns -le 1000; $Conns+=100) {
    for ($RequestsPerConn=1; $RequestsPerConn -le 8; $RequestsPerConn+=1) {
        $Requests = $Conns * $RequestsPerConn
        Write-Host "==$($Conns)c$($Requests)r=="
        for ($i=0; $i -lt $Iterations; $i++) {
            (.\secnetperf.exe `
                -Test:RPS `
                -Target:$Target `
                -conns:$Conns `
                -requests:$Requests) | Select-Object -Last 2
            Start-Sleep -Milliseconds 2000
        }
    }
}
