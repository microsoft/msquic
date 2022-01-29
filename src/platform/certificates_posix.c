/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Shims the certificate functions on posix

Environment:

    Posix

--*/

#include "platform_internal.h"

#include "msquic.h"

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

_Success_(return == TRUE)
BOOLEAN
CxPlatGetTestCertificate(
    _In_ CXPLAT_TEST_CERT_TYPE Type,
    _In_ CXPLAT_SELF_SIGN_CERT_TYPE StoreType,
    _In_ uint32_t CredType,
    _Out_ QUIC_CREDENTIAL_CONFIG* Params,
    _When_(CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH, _Out_)
    _When_(CredType != QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH, _Reserved_)
        QUIC_CERTIFICATE_HASH* CertHash,
    _When_(CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE, _Out_)
    _When_(CredType != QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE, _Reserved_)
        QUIC_CERTIFICATE_HASH_STORE* CertHashStore,
    _When_(CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE, _Out_)
    _When_(CredType != QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE, _Reserved_)
        QUIC_CERTIFICATE_FILE* CertFile,
    _When_(CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED, _Out_)
    _When_(CredType != QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED, _Reserved_)
        QUIC_CERTIFICATE_FILE_PROTECTED* CertFileProtected,
    _When_(CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12, _Out_)
    _When_(CredType != QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12, _Reserved_)
        QUIC_CERTIFICATE_PKCS12* Pkcs12,
    _When_(CredType == QUIC_CREDENTIAL_TYPE_NONE, _Out_z_bytecap_(100))
    _When_(CredType != QUIC_CREDENTIAL_TYPE_NONE, _Reserved_)
        char Principal[100]
    )
{
    return
        CxPlatGetTestCertificateOpenSSL(
            Type,
            StoreType,
            CredType,
            Params,
            CertHash,
            CertHashStore,
            CertFile,
            CertFileProtected,
            Pkcs12,
            Principal);
}


_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatFreeTestCert(
    _In_ QUIC_CREDENTIAL_CONFIG* Params
    )
{
    CxPlatFreeTestCertOpenSSL(Params);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
const QUIC_CREDENTIAL_CONFIG*
CxPlatGetSelfSignedCert(
    _In_ CXPLAT_SELF_SIGN_CERT_TYPE Type,
    _In_ BOOLEAN IsClient
    )
{
    return
        CxPlatGetSelfSignedCertOpenSSL(
            Type,
            IsClient);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatFreeSelfSignedCert(
    _In_ const QUIC_CREDENTIAL_CONFIG* Params
    )
{
    return CxPlatFreeSelfSignedCertOpenSSL(Params);
}
