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
    -replace "const int", "const uint" `
    -replace "  QUIC_EXECUTION_PROFILE_TYPE_", "  " `
    -replace "  QUIC_EXECUTION_PROFILE_", "  " `
    -replace "  QUIC_LOAD_BALANCING_", "  " `
    -replace "  QUIC_CREDENTIAL_TYPE_", "  " `
    -replace "  QUIC_CREDENTIAL_FLAG_", "  " `
    -replace "  QUIC_ALLOWED_CIPHER_SUITE_", "  " `
    -replace "  QUIC_CERTIFICATE_HASH_STORE_FLAG_", "  " `
    -replace "  QUIC_CONNECTION_SHUTDOWN_FLAG_", "  " `
    -replace "  QUIC_SERVER_", "  " `
    -replace "  QUIC_SEND_RESUMPTION_FLAG_", "  " `
    -replace "  QUIC_STREAM_SCHEDULING_SCHEME_", "  " `
    -replace "QUIC_STREAM_OPEN_FLAG_0_RTT", "ZERO_RTT" `
    -replace "  QUIC_STREAM_OPEN_FLAG_", "  " `
    -replace "  QUIC_STREAM_START_FLAG_", "  " `
    -replace "  QUIC_STREAM_SHUTDOWN_FLAG_", "  " `
    -replace "QUIC_RECEIVE_FLAG_0_RTT", "ZERO_RTT" `
    -replace "  QUIC_RECEIVE_FLAG_", "  " `
    -replace "  QUIC_SEND_FLAG_", "  " `
    -replace "  QUIC_DATAGRAM_SEND_", "  " `
    -replace "QUIC_TLS_PROTOCOL_1_3", "TLS_1_3" `
    -replace "  QUIC_TLS_PROTOCOL_", "  " `
    -replace "  QUIC_CIPHER_ALGORITHM_", "  " `
    -replace "  QUIC_HASH_ALGORITHM_", "  " `
    -replace "  QUIC_KEY_EXCHANGE_ALGORITHM_", "  " `
    -replace "  QUIC_CIPHER_SUITE_", "  " `
    -replace "  QUIC_CONGESTION_CONTROL_ALGORITHM_", "  " `
    -replace "  QUIC_PERF_COUNTER_", "  " `
    -replace "  QUIC_LISTENER_EVENT_", "  " `
    -replace "  QUIC_CONNECTION_EVENT_", "  " `
    -replace "  QUIC_STREAM_EVENT_", "  " `
    -replace "public", "internal" `
    | `
    Out-File $MsQuicGeneratedSource

$Solution = Join-Path $RootDir src cs MsQuicNet.sln

dotnet format $Solution

$LASTEXITCODE = 0
