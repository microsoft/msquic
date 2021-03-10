/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Stub implementation for generating the self-signed certificate.

--*/

#define QUIC_TEST_APIS 1

#include "platform_internal.h"
#ifdef QUIC_CLOG
#include "selfsign_stub.c.clog.h"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
const QUIC_CREDENTIAL_CONFIG*
CxPlatGetSelfSignedCert(
    _In_ CXPLAT_SELF_SIGN_CERT_TYPE Type,
    _In_ BOOLEAN ClientCertificate
    )
{
    UNREFERENCED_PARAMETER(Type);
    UNREFERENCED_PARAMETER(ClientCertificate);

    QUIC_CREDENTIAL_CONFIG* Params = malloc(sizeof(QUIC_CREDENTIAL_CONFIG));
    if (Params != NULL) {
        CxPlatZeroMemory(Params, sizeof(*Params));
        Params->Type = CXPLAT_CREDENTIAL_TYPE_NULL;
    }
    return Params;
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
    _When_(CredType == QUIC_CREDENTIAL_TYPE_NONE, _Out_z_bytecap_(100))
    _When_(CredType != QUIC_CREDENTIAL_TYPE_NONE, _Reserved_)
        char Principal[100]
    )
{
    // Not yet supported
    UNREFERENCED_PARAMETER(Type);
    UNREFERENCED_PARAMETER(StoreType);
    UNREFERENCED_PARAMETER(CredType);
    UNREFERENCED_PARAMETER(Params);
    UNREFERENCED_PARAMETER(CertHash);
    UNREFERENCED_PARAMETER(CertHashStore);
    UNREFERENCED_PARAMETER(Principal);
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatFreeTestCert(
    _In_ QUIC_CREDENTIAL_CONFIG* Params
    )
{
    UNREFERENCED_PARAMETER(Params);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatFreeSelfSignedCert(
    _In_ const QUIC_CREDENTIAL_CONFIG* Params
    )
{
    UNREFERENCED_PARAMETER(Params);
}
