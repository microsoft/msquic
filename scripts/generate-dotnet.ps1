Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

$MsQuicHeader = Join-Path $RootDir src inc msquic.h
$MsQuicGeneratedSource = Join-Path $RootDir src cs lib msquic_generated.cs

$MsQuicWindowsGeneratedSource = Join-Path $RootDir src cs lib msquic_generated_windows.cs

$MsQuicWindowsHeader = Join-Path $RootDir src inc msquic_winuser.h

ClangSharpPInvokeGenerator -f $MsQuicHeader -n Microsoft.Quic -o $MsQuicGeneratedSource -m MsQuic -l msquic -c exclude-enum-operators -r _SOCKADDR_INET=QuicAddr -c generate-macro-bindings

ClangSharpPInvokeGenerator -f $MsQuicWindowsHeader -n Microsoft.Quic -o $MsQuicWindowsGeneratedSource -m MsQuic -l msquic -c generate-macro-bindings
