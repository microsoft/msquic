Set-StrictMode -Version "Latest";
$PSDefaultParameterValues["*:ErrorAction"] = "Stop";

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent;

$SourceVersion = $env:BUILD_SOURCEVERSION;
$SourceBranch = $env:BUILD_SOURCEBRANCH;
$BuildId = $env:BUILD_BUILDID;
$VersionNumber = "1.10.0-$BuildId";

class BuildData {
    [string]$SourceVersion;
    [string]$SourceBranch;
    [string]$VersionNumber;

    BuildData($SourceVersion, $SourceBranch, $VersionNumber) {
        $this.SourceVersion = $SourceVersion;
        $this.SourceBranch = $SourceBranch;
        $this.VersionNumber = $VersionNumber;
    }
}

$Data = [BuildData]::new($SourceVersion, $SourceBranch, $VersionNumber)

$OutputDirectory = Join-Path $RootDir artifacts versions

if (!(Test-Path $OutputDirectory)) {
    New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
}

$OutputFile = Join-Path $OutputDirectory versions.json

$Data | ConvertTo-Json -Depth 100 | Out-File $OutputFile
