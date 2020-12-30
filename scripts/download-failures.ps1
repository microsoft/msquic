<#

.SYNOPSIS
This script will download all faulure logs, along with their associated builds, from AZP.

.PARAMETER AccessToken
    Specifies the AccessToken used to access the artifacts. This token only needs Build (Read)
    permissions. This can also be read from an AZP_ACCESS_TOKEN environment variable if not passed in.

    PATs can be grabbed by using the instructions at the following link.
    https://docs.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate?view=azure-devops&tabs=preview-page
    It only needs to support Build (Read)

.PARAMETER BuildNumber
    Specifies the build number to grab artifacts from

.EXAMPLE
    download-failures.ps1 -AccessToken GetAccessTokenFromAzureHere -BuildNumber BuildNumberFromAzure

#>

param (
    [Parameter(Mandatory = $false)]
    [string]$AccessToken = $null,

    [Parameter(Mandatory = $true)]
    [string]$BuildNumber,

    [Parameter(Mandatory = $false)]
    [ValidateSet("None", "All", "LogsOnly")]
    [string]$Download = "None",

    [Parameter(Mandatory = $false)]
    [switch]$List = $false
)

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

$RootDir = Split-Path $PSScriptRoot -Parent
$LogsFolder = Join-Path $RootDir "artifacts" "failurelogs"
$BuildLogFolder = Join-Path $LogsFolder $BuildNumber

function Get-Build {
    $URL = "https://dev.azure.com/ms/msquic/_apis/build/builds/$BuildNumber"
    $Artifacts =  Invoke-RestMethod -Uri "$URL/artifacts" -Method "GET" -ContentType "application/json"
    if ($Artifacts.count -eq 0) {
        Write-Error "No Artifacts found"
    }
    return $Artifacts
}

function Get-Logs {
    param (
        [Parameter(Mandatory =$true)]
        $Artifacts
    )


    New-Item -Path $LogsFolder -ItemType Directory -Force | Out-Null

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
        break
    }
}

function Get-Artifacts {
    param (
        [Parameter(Mandatory =$true)]
        $Artifacts
    )

    if ([string]::IsNullOrWhiteSpace($AccessToken)) {
        $AccessToken = $env:AZP_ACCESS_TOKEN
        if ([string]::IsNullOrWhiteSpace($AccessToken)) {
            Write-Error "No access token found in either parameters or AZP_ACCESS_TOKEN env variable"
        }
    }

    $AzureDevOpsAuthenicationHeader = @{Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(":$($AccessToken)")) }

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
}

class Test {
    [string]$Platform
    [string]$Config
    [string]$Executable
    [string]$TestName
    [System.IO.DirectoryInfo]$Folder

    Test([string]$Platform, [string]$Config, [string]$Executable, [string]$TestName, [System.IO.DirectoryInfo]$Folder) {
        $this.Platform = $Platform
        $this.Config = $Config
        $this.Executable = $Executable
        $this.Folder = $Folder
        $this.TestName = $TestName
    }

    [string]ToString() {
        return "{0} ({1}_{2})" -f $this.TestName, $this.Platform, $this.Config
    }
}

function Get-TestList {
    $TestList = @()
    $OperatingSystems = Get-ChildItem -Path "$BuildLogFolder/logs"
    foreach ($OSDir in $OperatingSystems) {
        $Platform = $OSDir.Name
        $Configs = Get-ChildItem -Path $OSDir
        foreach ($ConfigDir in $Configs) {
            $Config = $ConfigDir.Name
            $TestExecutables = Get-ChildItem $ConfigDir
            foreach ($ExeDir in $TestExecutables) {
                $ExeName = $ExeDir.Name
                $Dates = Get-ChildItem -Path $ExeDir
                foreach ($DateDir in $Dates) {
                    $Tests = Get-ChildItem -Path $DateDir
                    foreach ($TestDir in $Tests) {
                        $TestName = $TestDir.Name
                        $Test = [Test]::new($Platform, $Config, $ExeName, $TestName, $TestDir)
                        $TestList += $Test
                    }
                }
            }
        }
    }
    return $TestList
}

if ($Download -eq "All" -or $Download -eq "LogsOnly") {
    $Artifacts = Get-Build
    Get-Logs -Artifacts $Artifacts
    if ($Download -eq "All") {
        Get-Artifacts -Artifacts $Artifacts
    }
}

if ($List) {
    $TestList = Get-TestList

    Write-Host "Test List:"
    $Count = 1
    foreach ($Test in $TestList) {
        Write-Host ("`t${Count}: " + $Test.ToString())
        $Count++
    }
    [ValidateScript({$_ -ge 0 -and $_ -lt $Count})]
    [int]$Selection = Read-Host "Select a test to view, or 0 to exit"
    if ($Selection -ne 0) {
        $Test = $TestList[$Selection - 1]
        #TODO See what a test dump looks like
        $Test
    }
}


