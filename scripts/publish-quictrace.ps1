<#

.SYNOPSIS

.EXAMPLE
    public-quictrace.ps1

#>

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

$RIDs = @("win-x64", "linux-x64", "osx-x64")

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

$ToolDir = Join-Path $RootDir "src/plugins/trace/exe"
$BinFolder = Join-Path $ToolDir "bin"

$RootOutputFolder = Join-Path $RootDir "artifacts/bin/quictrace/published"


foreach ($RID in $RIDs) {
    # Clear out bin folder
    if (Test-Path $BinFolder) { Remove-Item $BinFolder -Recurse -Force | Out-Null }

    $ExeName = "QuicTrace"
    if ($RID.Contains("win")) {
        $ExeName = "QuicTrace.exe"
    }

    $FullOutputFile = Join-Path $BinFolder "Release/net6.0/$RID/publish/$ExeName"

    # Publish Non Trimmed
    dotnet publish $ToolDir -r $RID -c Release -p:PublishSingleFile=true --self-contained true -p:EnableCompressionInSingleFile=true

    $ArtifactFolder = Join-Path $RootOutputFolder $RID
    if (!(Test-Path $ArtifactFolder)) { New-Item -Path $ArtifactFolder -ItemType Directory -Force | Out-Null }
    Copy-Item $FullOutputFile $ArtifactFolder

    # Clear out bin folder
    if (Test-Path $BinFolder) { Remove-Item $BinFolder -Recurse -Force | Out-Null }

    # Publish Trimmed
    dotnet publish $ToolDir -r $RID -c Release -p:PublishSingleFile=true --self-contained true -p:EnableCompressionInSingleFile=true -p:PublishTrimmed=true

    $TrimmedArtifactFolder = Join-Path $ArtifactFolder "trimmed"
    if (!(Test-Path $TrimmedArtifactFolder)) { New-Item -Path $TrimmedArtifactFolder -ItemType Directory -Force | Out-Null }
    Copy-Item $FullOutputFile $TrimmedArtifactFolder
}
