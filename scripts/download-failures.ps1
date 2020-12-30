<#

.SYNOPSIS
This script will download all faulure logs, along with their associated builds, from AZP.

.PARAMETER AccessToken
    Specifies the AccessToken used to access the artifacts. This token only needs Build (Read)
    permissions.

.PARAMETER BuildNumber
    Specifies the build number to grab artifacts from

.EXAMPLE
    download-failures.ps1 -AccessToken GetAccessTokenFromAzureHere -BuildNumber BuildNumberFromAzure

#>

param (
    [Parameter(Mandatory = $true)]
    [string]$AccessToken,

    [Parameter(Mandatory = $true)]
    [string]$BuildNumber
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

$RootDir = Split-Path $PSScriptRoot -Parent
$LogsFolder = Join-Path $RootDir "artifacts" "failurelogs"
$BuildLogFolder = Join-Path $LogsFolder $BuildNumber
New-Item -Path $LogsFolder -ItemType Directory -Force | Out-Null

$URL = "https://dev.azure.com/ms/msquic/_apis/build/builds/$BuildNumber"

$AzureDevOpsAuthenicationHeader = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$($AccessToken)")) }

$Artifacts =  Invoke-RestMethod -Uri "$URL/artifacts" -Method "GET" -ContentType "application/json" -Headers $AzureDevOpsAuthenicationHeader

if ($Artifacts.count -eq 0) {
    Write-Error "No Artifacts found"
}

$ContainerId = $null

#Find Artifacts container id
foreach ($Artifact in $Artifacts.value) {
    if ($Artifact.name -eq "artifacts") {
        $ContainerId = $Artifact.resource.data
        $ContainerId = $ContainerId.Substring(2)
        break
    }
}

if ($null -eq $ContainerId) {
    Write-Error "Artifacts for build not found"
}

# Check to see if we have any "logs" artifacts
foreach ($Artifact in $Artifacts.value) {
    if ($Artifact.name -ne "logs") {
        continue
    }

    # Download logs artifact
    $ArtifactUrl = $Artifact.resource.downloadUrl
    $ArtifactsZip = Join-Path $LogsFolder "Logs_$BuildNumber.zip"
    Invoke-WebRequest -Uri $ArtifactUrl -Method "GET" -OutFile $ArtifactsZip
    Expand-Archive -Path $ArtifactsZip -DestinationPath $BuildLogFolder -Force

    $ContainerRootUri = "https://dev.azure.com/ms/_apis/resources/Containers/$ContainerId" + "?itemPath=artifacts/bin/"

    # Find all failing builds, download all artifacts for said build
    $FailingConfigs = Get-ChildItem "$BuildLogFolder/logs/*/*"

    foreach ($Config in $FailingConfigs) {
        $Arch = $Config.Name
        $Os = $config.Parent.Name
        $Config = "$Os/$Arch"
        $DownloadUri = $ContainerRootUri + $Config + "&%24format=zip&saveAbsolutePath=false"
        $DownloadFile = Join-Path $BuildLogFolder "$Os$Arch.zip"
        Invoke-WebRequest -Uri $DownloadUri -Method "GET" -OutFile $DownloadFile -Headers $AzureDevOpsAuthenicationHeader
        $BinFolder = Join-Path $BuildLogFolder "bin" $os
        Write-Host $BinFolder
        Expand-Archive -Path $DownloadFile -DestinationPath $BinFolder -Force
    }

    break
}
