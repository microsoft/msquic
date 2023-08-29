
# For local unit testing, often certain bugs only appear due to a specific ordering of events in the network.
# To catch those edge cases, lots of iterations are required. Manually doing them is tiresome.
# This script automates the process of finding those bugs.
# Additionally, running this script with large NumIterations gives confidence.

# Example Usage:
# .\scripts\iter_command.ps1 -commandToRun "./scripts/test.ps1 -Filter *StreamReliable* -LogProfile Full.Light" -numIterations 100


param (
    [string]$commandToRun,
    [int]$numIterations
)

if ($commandToRun -eq $null) {
    Write-Host "Error: 'commandToRun' parameter cannot be null."
    exit
}

if ($numIterations -eq $null) {
    Write-Host "Error: 'commandToRun' parameter cannot be null."
    exit
}

if ($numIterations -le 0) {
    Write-Host "Error: 'numIterations' parameter must be greater than 0."
    exit
}

for ($i = 1; $i -le $numIterations; $i++) {
    Invoke-Expression $commandToRun
    Write-Host "-------------------------------------------"
}
