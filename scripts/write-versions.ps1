param (
    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Debug",

    [Parameter(Mandatory = $false)]
    [ValidateSet("x86", "x64", "arm", "arm64", "arm64ec")]
    [string]$Arch = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("gamecore_console", "uwp", "windows", "linux", "macos", "android", "ios")] # For future expansion
    [string]$Platform = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("schannel", "openssl")]
    [string]$Tls = ""
)

Set-StrictMode -Version "Latest";
$PSDefaultParameterValues["*:ErrorAction"] = "Stop";

$BuildConfig = & (Join-Path $PSScriptRoot get-buildconfig.ps1) -Platform $Platform -Tls $Tls -Arch $Arch -ExtraArtifactDir "" -Config $Config

$ArtifactsDir = $BuildConfig.ArtifactsDir

$SourceVersion = $env:BUILD_SOURCEVERSION;
$SourceBranch = $env:BUILD_SOURCEBRANCH;
$BuildId = $env:BUILD_BUILDID;
$VersionNumber = "2.1.0";

class BuildData {
    [string]$SourceVersion;
    [string]$SourceBranch;
    [string]$VersionNumber;
    [string]$BuildId;

    BuildData($SourceVersion, $SourceBranch, $VersionNumber, $BuildId) {
        $this.SourceVersion = $SourceVersion;
        $this.SourceBranch = $SourceBranch;
        $this.VersionNumber = $VersionNumber;
        $this.BuildId = $BuildId;
    }
}

$Data = [BuildData]::new($SourceVersion, $SourceBranch, $VersionNumber, $BuildId)

$OutputFile = Join-Path $ArtifactsDir versions.json

$Data | ConvertTo-Json -Depth 100 | Out-File $OutputFile
