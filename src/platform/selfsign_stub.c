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

QUIC_CREDENTIAL_CONFIG*
CxPlatGetTestCertificate(
    _In_ CXPLAT_TEST_CERT_TYPE Type,
    _In_ CXPLAT_SELF_SIGN_CERT_TYPE StoreType,
    _In_ uint32_t CredType
    )
{
    // Not yet supported
    UNREFERENCED_PARAMETER(Type);
    UNREFERENCED_PARAMETER(StoreType);
    UNREFERENCED_PARAMETER(CredType);
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
    free((void*)Params);
}
