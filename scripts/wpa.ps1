<#

.SYNOPSIS
This script provides helpers for running Windows Performance Analyzer.

.PARAMETER Config
    Sets the debug or release configuration of the plugin to use.

.PARAMETER FilePath
    A path to a file to open

.EXAMPLE
   wpa.ps1

.EXAMPLE
   wpa.ps1 -FilePath quic.etl

.EXAMPLE
    wpa.ps1 -Config Debug

#>

param (
    [Parameter(Mandatory = $false)]
    [string]$FilePath = "",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Debug", "Release")]
    [string]$Config = "Release"
)

Set-StrictMode -Version 'Latest'

# This script can either be run directly from the git repo or from a release
# package. The behavior is slightly different depending on the location it is
# run from. We deterimine the location by checking the script's directory.
$InGitRepo = ($RootDir = Split-Path $PSScriptRoot -Leaf) -eq "scripts"

# Calculate the path to the plugin's directory.
$PluginSearchPath = ""
if ($InGitRepo) {
    # Look for the locally built version of the plugin.
    $PluginSearchPath = Join-Path (Split-Path $PSScriptRoot -Parent) "artifacts" "bin" "quictrace" $Config
} else {
    # Look for the plugin in install (current) directory.
    $PluginSearchPath = $PSScriptRoot
}

$MinStoreWPAVersion = New-Object -TypeName System.Version -ArgumentList "10.0.22500.0" # TODO - What is the actual min version?
$WPAPreviewStoreLink = "https://www.microsoft.com/en-us/p/windows-performance-analyzer-preview/9n58qrw40dfw"
$WPAPath = "$env:LOCALAPPDATA\Microsoft\WindowsApps\wpa.exe"

# Make sure WPA (preview version) is installed. If not, launch the store to
# install it.
$wpaPreviewStorePkg = Get-AppPackage -Name Microsoft.WindowsPerformanceAnalyzerPreview
if (-not $wpaPreviewStorePkg -or $wpaPreviewStorePkg.Status -ne "Ok") {
    Write-Error -Category NotInstalled -Message "REQUIRED PREREQUISITE Store Windows Performance Analyzer (Preview) is not installed. Please install it from the Store. Launching $WPAPreviewStoreLink"
    Start-Process "$WPAPreviewStoreLink"
    if (!$InGitRepo) { Pause }
    Exit
}

$v = New-Object -TypeName System.Version -ArgumentList $wpaPreviewStorePkg.Version
# Is MinStoreWPAVersion same, later, or earlier than current WPA version?
$WpaVersionComparison = $MinStoreWPAVersion.CompareTo($v);
switch ($WpaVersionComparison ) {
    # MinStoreWPAVersion the same as current WPA
    0 { break }
    # MinStoreWPAVersion later than current WPA
    1 {
        Write-Error -Category NotInstalled  -Message "Current WPA version is $v. Need minimum of WPA $MinStoreWPAVersion. Redirecting to Store WPA so that you can update...";
        Start-Process "$WPAPreviewStoreLink"
        if (!$InGitRepo) { Pause }
        Exit
    }
    # MinStoreWPAVersion earlier than current WPA. That's ok
    -1 { break }
}

# Make sure the plugin is present.
if (!(Test-Path (Join-Path $PluginSearchPath "QuicTrace.dll"))) {
    if ($InGitRepo) {
        $PluginSlnPath = Join-Path (Split-Path $PSScriptRoot -Parent) "src" "plugins" "QuicTrace.sln"
        Write-Error -Category NotInstalled -Message "QuicTrace.dll is not found. Launching $PluginSlnPath"
        Start-Process "$PluginSlnPath"
    } else {
        Write-Error -Category NotInstalled -Message "QuicTrace.dll is not found. Please build the plugin first."
    }
    if (!$InGitRepo) { Pause }
    Exit
}

# Build up the arguments and start WPA.exe.
$startInfo = New-Object System.Diagnostics.ProcessStartInfo
$startInfo.FileName = $WPAPath
$startInfo.Arguments = "-addsearchdir `"$PluginSearchPath`""
if ($FilePath -ne "") {
    $startInfo.Arguments = $startInfo.Arguments + " -i `"$FilePath`""
}
$startInfo.RedirectStandardOutput = $true
$startInfo.UseShellExecute = $false
$startInfo.CreateNoWindow = $false

Write-Debug "Launching $WPAPath $($startInfo.Arguments)"

$process = New-Object System.Diagnostics.Process
$process.StartInfo = $startInfo
$process.Start() | Out-Null
