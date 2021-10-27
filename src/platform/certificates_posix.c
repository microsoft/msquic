/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Shims the certificate functions on posix

Environment:

    Posix

--*/

#include "platform_internal.h"

#ifdef QUIC_CLOG
#include "certificates_posix.c.clog.h"
#endif

QUIC_STATUS
CxPlatCertExtractPrivateKey(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _In_z_ const char* Password,
    _Outptr_result_buffer_(*PfxSize) uint8_t** PfxBytes,
    _Out_ uint32_t* PfxSize
    )
{
    UNREFERENCED_PARAMETER(CredConfig);
    UNREFERENCED_PARAMETER(Password);
    UNREFERENCED_PARAMETER(PfxBytes);
    UNREFERENCED_PARAMETER(PfxSize);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_Success_(return != FALSE)
BOOLEAN
CxPlatCertVerifyRawCertificate(
    _In_reads_bytes_(X509CertLength) unsigned char* X509Cert,
    _In_ int X509CertLength,
    _In_opt_ const char* SNI,
    _In_ QUIC_CREDENTIAL_FLAGS CredFlags,
    _Out_opt_ uint32_t* PlatformVerificationError
    )
{
    UNREFERENCED_PARAMETER(X509Cert);
    UNREFERENCED_PARAMETER(X509CertLength);
    UNREFERENCED_PARAMETER(SNI);
    UNREFERENCED_PARAMETER(CredFlags);
    UNREFERENCED_PARAMETER(PlatformVerificationError);
    return 0;
}
