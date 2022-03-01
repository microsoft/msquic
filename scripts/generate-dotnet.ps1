<#

.SYNOPSIS
    This script generates C# bindings using ClangSharpPInvokeGenerator.
    Due to bugs in the tool, this is currently not an automated process

#>

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

$ToolPath = Join-Path $RootDir build dotnetgenerator

if (Test-Path $ToolPath) { Remove-Item $ToolPath -Recurse -Force | Out-Null }

dotnet tool install ClangSharpPInvokeGenerator --version 13.0.0-beta1 --tool-path $ToolPath

$MsQuicHeader = Join-Path $RootDir src inc msquic.h
$MsQuicGeneratedSource = Join-Path $RootDir src cs lib msquic_generated.cs

$LicenseHeader = Join-Path $RootDir src cs LicenseHeader.txt

$ToolExe = Join-Path $ToolPath ClangSharpPInvokeGenerator.exe

$Arguments = @(
    "-f $MsQuicHeader", # Header to parse
    "-n Microsoft.Quic", # Namespace to place generated code in
    "-o $MsQuicGeneratedSource", # Output file
    "-m MsQuic", # Class to place global functions and definitions in
    "-l msquic", # Library to import for functions
    "-c exclude-enum-operators", # Exclude enum operators from generated
    "-r _SOCKADDR_INET=QuicAddr", # Remap _SOCKADDR_INET to QuicAddr
    "-c generate-macro-bindings", # Generate values for macros (Such as status codes)
    "-h $LicenseHeader", # Add license header to file
    "-e QUIC_UINT62_MAX", # Exclude QUIC_UINT62_MAX from generator
    "-e MsQuicOpen2", # Exclude MsQuicOpen2 macro from generator
    "-e QUIC_API_VERSION_1", # Exclude v1 API define
    "-D QUIC_API_ENABLE_INSECURE_FEATURES", # Enable insecure features to be generated
    "-D QUIC_API_ENABLE_PREVIEW_FEATURES" # Enable preview features to be generated
    "-e QUIC_DATAGRAM_SEND_STATE_IS_FINAL" # Cannot generate macro functions
    "-e QUIC_PARAM_IS_GLOBAL" # Cannot generate macro functions
)

$FullArgs = $Arguments -join " "

Invoke-Expression "$ToolExe $FullArgs"

(Get-Content $MsQuicGeneratedSource) `
    -replace '\(anonymous struct.+\)\"', "(anonymous struct)`"" `
    -replace '\(anonymous union.+\)\"', "(anonymous union)`"" `
    -replace "public enum .*?_FLAGS","[System.Flags]`n    `$0" `
    | `
    Out-File $MsQuicGeneratedSource

$LASTEXITCODE = 0
