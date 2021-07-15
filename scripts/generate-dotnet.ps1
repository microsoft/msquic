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

$LicenseHeader = Join-Path $RootDir src cs LicenseHeader.txt

if ($IsWindows) {
    ClangSharpPInvokeGenerator -f $MsQuicHeader -n Microsoft.Quic -o $MsQuicGeneratedSource -m MsQuic -l msquic `
    -c exclude-enum-operators -r _SOCKADDR_INET=QuicAddr -c generate-macro-bindings -h $LicenseHeader `
    -e QUIC_UINT62_MAX

    ClangSharpPInvokeGenerator -f $MsQuicWindowsHeader -n Microsoft.Quic -o $MsQuicWindowsGeneratedSource -m MsQuic_Windows -l msquic `
        -c generate-macro-bindings -c exclude-funcs-with-body -h $LicenseHeader `
        -D CSHARP_GENERATION `
        -e QUIC_ADDR_STR `
        -e QUIC_ADDR_V4_PORT_OFFSET `
        -e QUIC_ADDR_V4_IP_OFFSET `
        -e QUIC_ADDR_V6_PORT_OFFSET `
        -e QUIC_ADDR_V6_IP_OFFSET `
        -e QUIC_ADDRESS_FAMILY_UNSPEC `
        -e QUIC_ADDRESS_FAMILY_INET `
        -e QUIC_ADDRESS_FAMILY_INET6

    # In the current version of PInvokeGenerator, macros with ternarys are generated incorrectly. Manually fix this up
    (Get-Content $MsQuicWindowsGeneratedSource).Replace("public static readonly", "public const") | Set-Content $MsQuicWindowsGeneratedSource
} else {
        ClangSharpPInvokeGenerator -f $MsQuicPosixHeader -n Microsoft.Quic -o $MsQuicPosixGeneratedSource -m MsQuic_Posix -l msquic `
        -c generate-macro-bindings -c exclude-funcs-with-body -h $LicenseHeader `
        -D CSHARP_GENERATION `
        -e QUIC_ADDR_STR `
        -e QUIC_ADDR_V4_PORT_OFFSET `
        -e QUIC_ADDR_V4_IP_OFFSET `
        -e QUIC_ADDR_V6_PORT_OFFSET `
        -e QUIC_ADDR_V6_IP_OFFSET `
        -e _strnicmp `
        -e QUIC_ADDR `
        -e TRUE `
        -e FALSE `
        -e QUIC_ADDRESS_FAMILY_UNSPEC `
        -e QUIC_ADDRESS_FAMILY_INET `
        -e QUIC_ADDRESS_FAMILY_INET6

    # In the current version of PInvokeGenerator, macros with ternarys are generated incorrectly. Manually fix this up
    (Get-Content $MsQuicPosixGeneratedSource).Replace("public static readonly", "public const") | Set-Content $MsQuicPosixGeneratedSource
}
