Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent
$ResultsPath = Join-Path $RootDir "artifacts/PerfDataResults"

# Enumerate files
$Files = Get-ChildItem -Path $ResultsPath -Recurse -File

Write-Host $Files

$Files | ForEach-Object {
    $DataToWrite = Get-Content $_ | ConvertFrom-Json
    Write-Host $DataToWrite
    $DataToWrite | Add-Member -NotePropertyName "AuthKey" -NotePropertyValue $env:MAPPED_DEPLOYMENT_KEY
    $JsonToWrite = $DataToWrite | ConvertTo-Json

    $Result = Invoke-RestMethod -Uri "https://msquicperformanceresults.azurewebsites.net/performance" -Body $JsonToWrite -Method 'Post' -ContentType "application/json"
    Write-Host $Result
}
