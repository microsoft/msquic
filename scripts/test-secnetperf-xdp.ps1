<#
.SYNOPSIS
    Tests XDP performance-test parameter forwarding without installing drivers.
#>

#Requires -Version 7.0

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$TestRoot = Join-Path ([System.IO.Path]::GetTempPath()) "secnetperf-xdp-$([guid]::NewGuid())"
$TestScripts = Join-Path $TestRoot "scripts"
$TestModule = $null
$global:SecnetperfXdpTest = @{
    Installs = [System.Collections.Generic.List[string]]::new()
    Commands = [System.Collections.Generic.List[string]]::new()
    Waits = 0
}

function Assert-Equal($Actual, $Expected) {
    if ($Actual -cne $Expected) {
        throw "Expected '$Expected', got '$Actual'."
    }
}

function Assert-Rejected([scriptblock]$Action, [string]$Message) {
    $InstallCount = $global:SecnetperfXdpTest.Installs.Count
    try {
        & $Action
    } catch {
        if ($_.ToString() -notlike "*$Message*") { throw }
        Assert-Equal $global:SecnetperfXdpTest.Installs.Count $InstallCount
        return
    }
    throw "Expected rejection containing '$Message'."
}

try {
    New-Item -ItemType Directory -Path $TestScripts | Out-Null
    foreach ($File in @("secnetperf-helpers.psm1", "quic_callback.ps1", "xdp.json")) {
        Copy-Item (Join-Path $PSScriptRoot $File) $TestScripts
    }
    @'
param([switch]$InstallXdpDriver, [string]$UseXdp)
if (!$InstallXdpDriver) { throw "Expected XDP installation." }
$global:SecnetperfXdpTest.Installs.Add($UseXdp)
'@ | Set-Content (Join-Path $TestScripts "prepare-machine.ps1")

    $TestModule = Import-Module (Join-Path $TestScripts "secnetperf-helpers.psm1") -Force -PassThru
    & $TestModule {
        function script:whoami { }
        function script:NetperfSendCommand($Command) {
            $global:SecnetperfXdpTest.Commands.Add($Command)
        }
        function script:NetperfWaitServerFinishExecution {
            $global:SecnetperfXdpTest.Waits++
        }
        function script:Invoke-Command($Session, $ScriptBlock) {
            if ($Session -ne "test-session") { throw "Unexpected remote session." }
            # Emulate captured remoting variables without contacting another machine.
            $Text = $ScriptBlock.ToString().Replace('$Using:RemoteDir', '$RemoteDir').Replace('$Using:UseXdp', '$UseXdp')
            & ([scriptblock]::Create($Text))
        }
    }

    $Tokens = $null
    $ParseErrors = $null
    $PerfAst = [System.Management.Automation.Language.Parser]::ParseFile(
        (Join-Path $PSScriptRoot "secnetperf.ps1"), [ref]$Tokens, [ref]$ParseErrors)
    if ($ParseErrors.Count) { throw "secnetperf.ps1 has parse errors: $ParseErrors" }
    $IoFunction = $PerfAst.Find({
        param($Node)
        $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $Node.Name -eq "Is-XdpRequiredByIo"
    }, $true)
    $RequiredAssignment = $PerfAst.Find({
        param($Node)
        $Node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $Node.Left.Extent.Text -eq '$XdpRequired'
    }, $true)
    $InstallCondition = $PerfAst.Find({
        param($Node)
        $Node -is [System.Management.Automation.Language.IfStatementAst] -and
            $Node.Extent.Text -like '*Install-XDP $Session*'
    }, $true)
    $PerfSetup = [scriptblock]::Create(
        $PerfAst.ParamBlock.Extent.Text + "`n" +
        $IoFunction.Extent.Text + "`n" +
        $RequiredAssignment.Extent.Text + "`n" +
        $InstallCondition.Extent.Text + "`n" +
        'return $UseXdp')

    Push-Location $TestRoot
    try {
        $Session = "NOT_SUPPORTED"
        $RemoteDir = $TestRoot
        foreach ($Version in @("xdp-v1.4", "xdp-prerelease")) {
            foreach ($Io in @("xdp", "qtip", "server-xdp", "iocp")) {
                $global:SecnetperfXdpTest.Installs.Clear()
                $global:SecnetperfXdpTest.Commands.Clear()
                $global:SecnetperfXdpTest.Waits = 0
                $Parameters = @{
                    MsQuicCommit = "test"; environment = "azure"; plat = "windows"
                    os = "windows-2022"; arch = "x64"; tls = "schannel"
                    io = $(if ($Io -eq "server-xdp") { "iocp" } else { $Io })
                    serverio = $(if ($Io -eq "server-xdp") { "xdp" } else { "" })
                }
                if ($Version -eq "xdp-prerelease") { $Parameters.UseXdp = $Version }
                Assert-Equal (& $PerfSetup @Parameters) $Version

                if ($Io -eq "iocp" -or !$IsWindows) {
                    Assert-Equal $global:SecnetperfXdpTest.Installs.Count 0
                    Assert-Equal $global:SecnetperfXdpTest.Commands.Count 0
                } else {
                    Assert-Equal $global:SecnetperfXdpTest.Installs.Count 1
                    Assert-Equal $global:SecnetperfXdpTest.Installs[0] $Version
                    Assert-Equal $global:SecnetperfXdpTest.Commands[0] "Install_XDP;$Version"
                    Assert-Equal $global:SecnetperfXdpTest.Waits 1
                    & (Join-Path $TestScripts "quic_callback.ps1") -Command $global:SecnetperfXdpTest.Commands[0]
                    Assert-Equal $global:SecnetperfXdpTest.Installs.Count 2
                    Assert-Equal $global:SecnetperfXdpTest.Installs[1] $Version
                }
            }
            $global:SecnetperfXdpTest.Installs.Clear()
            Install-XDP -Session "test-session" -RemoteDir $TestRoot -UseXdp $Version
            Assert-Equal $global:SecnetperfXdpTest.Installs.Count 2
            Assert-Equal $global:SecnetperfXdpTest.Installs[0] $Version
            Assert-Equal $global:SecnetperfXdpTest.Installs[1] $Version
        }

        foreach ($Version in @("unknown", " ", "xdp-v1.4;extra")) {
            Assert-Rejected {
                Install-XDP -Session "NOT_SUPPORTED" -RemoteDir $TestRoot -UseXdp $Version
            } "Unknown XDP version"
        }
        Assert-Rejected {
            Install-XDP -Session "NOT_SUPPORTED" -RemoteDir $TestRoot -UseXdp ""
        } "empty"
        foreach ($Command in @("Install_XDP", "Install_XDP;", "Install_XDP; ", "Install_XDP;xdp-v1.4;extra")) {
            Assert-Rejected {
                & (Join-Path $TestScripts "quic_callback.ps1") -Command $Command
            } "requires an XDP version"
        }
        Assert-Rejected {
            & (Join-Path $TestScripts "quic_callback.ps1") -Command "Install_XDP;unknown"
        } "Unknown XDP version"
    } finally {
        Pop-Location
    }
    Write-Host "PASS: default/override, IO gating, local/remote/cache forwarding, and invalid version rejection."
} finally {
    if ($null -ne $TestModule) { Remove-Module $TestModule }
    Remove-Variable SecnetperfXdpTest -Scope Global
    foreach ($File in @("secnetperf-helpers.psm1", "quic_callback.ps1", "xdp.json", "prepare-machine.ps1")) {
        $Path = Join-Path $TestScripts $File
        if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path }
    }
    if (Test-Path -LiteralPath $TestScripts) { Remove-Item -LiteralPath $TestScripts }
    if (Test-Path -LiteralPath $TestRoot) { Remove-Item -LiteralPath $TestRoot }
}
