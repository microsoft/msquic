Set-StrictMode -Version 'Latest'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

# Root directory of the project.
$RootDir = Split-Path $PSScriptRoot -Parent

$MsQuicHeader = Join-Path $RootDir src inc msquic.h
$MsQuicGeneratedSource = Join-Path $RootDir src cs lib msquic_generated.cs

$MsQuicWindowsGeneratedSource = Join-Path $RootDir src cs lib msquic_generated_windows.cs
$MsQuicPosixGeneratedSource = Join-Path $RootDir src cs lib msquic_generated_posix.cs

$MsQuicWindowsHeader = Join-Path $RootDir src inc msquic_winuser.h
$MsQuicPosixHeader = Join-Path $RootDir src inc msquic_posix.h

ClangSharpPInvokeGenerator -f $MsQuicHeader -n Microsoft.Quic -o $MsQuicGeneratedSource -m MsQuic -l msquic -c exclude-enum-operators -r _SOCKADDR_INET=QuicAddr -c generate-macro-bindings `
    -e QUIC_UINT62_MAX

if ($IsWindows) {
    ClangSharpPInvokeGenerator -f $MsQuicWindowsHeader -n Microsoft.Quic -o $MsQuicWindowsGeneratedSource -m MsQuic_Windows -l msquic -c generate-macro-bindings -c exclude-funcs-with-body `
        -D CSHARP_GENERATION `
        -e QUIC_ADDR_STR `
        -e QUIC_ADDR_V4_PORT_OFFSET `
        -e QUIC_ADDR_V4_IP_OFFSET `
        -e QUIC_ADDR_V6_PORT_OFFSET `
        -e QUIC_ADDR_V6_IP_OFFSET `
} else {
        ClangSharpPInvokeGenerator -f $MsQuicPosixHeader -n Microsoft.Quic -o $MsQuicPosixGeneratedSource -m MsQuic_Posix -l msquic -c generate-macro-bindings -c exclude-funcs-with-body `
        -D CSHARP_GENERATION `
        -e QUIC_ADDR_STR `
        -e QUIC_ADDR_V4_PORT_OFFSET `
        -e QUIC_ADDR_V4_IP_OFFSET `
        -e QUIC_ADDR_V6_PORT_OFFSET `
        -e QUIC_ADDR_V6_IP_OFFSET `
}
