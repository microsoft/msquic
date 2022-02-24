<#

.SYNOPSIS
    This script generates C# bindings using ClangSharpPInvokeGenerator.
    Due to bugs in the tool, this is currently not an automated process

#>

Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

$MsQuicHeader = Join-Path $RootDir src inc msquic.h
$MsQuicGeneratedSource = Join-Path $RootDir src cs lib msquic_generated.cs

$LicenseHeader = Join-Path $RootDir src cs LicenseHeader.txt

ClangSharpPInvokeGenerator -f $MsQuicHeader -n Microsoft.Quic -o $MsQuicGeneratedSource -m MsQuic -l msquic `
    -c exclude-enum-operators -r _SOCKADDR_INET=QuicAddr -c generate-macro-bindings -h $LicenseHeader `
    -e QUIC_UINT62_MAX -e MsQuicOpen2 -e QUIC_API_VERSION_1 -D QUIC_API_ENABLE_INSECURE_FEATURES `
    -D QUIC_API_ENABLE_PREVIEW_FEATURES

$ReplaceDir = $RootDir + "\"

(Get-Content $MsQuicGeneratedSource).Replace($ReplaceDir, "").Replace($ReplaceDir.Replace("\", "/"), "") | `
    Out-File $MsQuicGeneratedSource
