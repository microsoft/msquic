# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent
$RootDir = Split-Path $RootDir -Parent

$ResultsPath = Join-Path $RootDir "artifacts/PerfDataResults"

# Enumerate files
$Files = Get-ChildItem -Path $ResultsPath -Recurse -File

$Files | ForEach-Object {
    $DataToWrite = Get-Content $_ | ConvertFrom-Json
    $DataToWrite | Add-Member -NotePropertyName "AuthKey" -NotePropertyValue $env:MAPPED_DEPLOYMENT_KEY
    $JsonToWrite = $DataToWrite | ConvertTo-Json

    Invoke-RestMethod -Uri "https://msquicperformanceresults.azurewebsites.net/performance" -Body $JsonToWrite -Method 'Post' -ContentType "application/json"
}
