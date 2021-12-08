param (
    [Parameter(Mandatory = $true)]
    [string]$BranchToPushTo,

    [Parameter(Mandatory = $false)]
    [string]$PRTitle = "Ingest latest MsQuic (automated)",

    [Parameter(Mandatory = $false)]
    [string]$MSRCNumber = ""
)

Set-StrictMode -Version "Latest";
$PSDefaultParameterValues["*:ErrorAction"] = "Stop";

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent;

$ArtifactsDir = Join-Path $RootDir "artifacts";

class CheckinFile {
    [string]$Source;
    [string]$Path;
    [string]$Type = "File";

    CheckinFile($ManifestFile, $MSRCNumber) {
        $this.Source = $ManifestFile;
        $outputFile = "msquic.man"
        if (![string]::IsNullOrWhiteSpace($MSRCNumber)) {
            $outputFile = "msquic-msrc-$MSRCNumber.man"
        }
        $this.Path = "minio/netio/quic/msquic/$outputFile";
    }
}

class CheckinBranch {
    [string]$collection;
    [string]$project;
    [string]$repo;
    [string]$name;
    [string]$completePR = "False";
    [string]$pullRequestTitle;
    [CheckinFile[]]$CheckinFiles;

    CheckinBranch($ManifestFile, $BranchToPushTo, $MSRCNumber) {
        $this.collection = "microsoft";
        $this.project = "OS";
        $this.repo = "os.2020";
        $this.name = $BranchToPushTo;
        $this.CheckinFiles = @([CheckinFile]::new($ManifestFile, $MSRCNumber));
    }
}

class GitCheckin {
    [CheckinBranch[]]$Branch;

    GitCheckin($ManifestFile, $BranchToPushTo, $MSRCNumber) {
        $this.Branch = @([CheckinBranch]::new($ManifestFile, $BranchToPushTo, $MSRCNumber));
    }
}

$ManifestFile = Join-Path $ArtifactsDir package msquic.man

$Checkin = [GitCheckin]::new($ManifestFile, $BranchToPushTo, $MSRCNumber)

$CheckinFile = Join-Path $ArtifactsDir package GitCheckin.json

$Checkin | ConvertTo-Json -Depth 100 | Out-File $CheckinFile

$Manifest = @"
### StartMeta
# Manifest_Format_Version=2
### EndMeta

// Description: Microsoft QUIC Library (https://github.com/microsoft/msquic)
// The following metadata comments are used for ingesting the latest version
// MSQUIC_METADATA_HASH: REPLACE_WITH_COMMIT_HASH
// MSQUIC_METADATA_SOURCE_BRANCH: REPLACE_WITH_BRANCH
// MSQUIC_METADATA_ONEBRANCH_BUILD_ID: REPLACE_WITH_OB_BUILD_ID
// Owner: quicdev
msquic.`$(Platform),[REPLACE_WITH_VERSION_NUMBER],Drop,CollectionOfFiles,https://microsoft.artifacts.visualstudio.com/DefaultCollection/,,`$(Destination)
"@

$VersionFile = Join-Path $ArtifactsDir bin windows x64_Release_schannel versions.json

$Versions = Get-Content -Path $VersionFile | ConvertFrom-Json

$CommitHash = $Versions.SourceVersion
$CommitBranch = $Versions.SourceBranch
$VersionNumber = $Versions.VersionNumber
$OneBranchBuildId = $Versions.BuildId
$CurrentBuildId = $env:BUILD_BUILDID
$FullVersion = "$VersionNumber-$CurrentBuildId"

$Manifest = $Manifest.Replace("REPLACE_WITH_COMMIT_HASH", $CommitHash).Replace("REPLACE_WITH_BRANCH", $CommitBranch).Replace("REPLACE_WITH_VERSION_NUMBER", $FullVersion).Replace("REPLACE_WITH_OB_BUILD_ID", $OneBranchBuildId)

$Manifest | Out-File $ManifestFile
