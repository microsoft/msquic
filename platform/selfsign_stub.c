/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Stub implementation for generating the self-signed certificate.

--*/

#ifdef QUIC_BUILD_STUB

#define QUIC_TEST_APIS 1

#include "platform_internal.h"

#ifdef QUIC_LOGS_WPP
#include "selfsign_stub.tmh"
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_SEC_CONFIG_PARAMS*
QuicPlatGetSelfSignedCert(
    _In_ QUIC_SELF_SIGN_CERT_TYPE Type
    )
{
    UNREFERENCED_PARAMETER(Type);

    QUIC_SEC_CONFIG_PARAMS* Params = malloc(sizeof(QUIC_SEC_CONFIG_PARAMS));
    if (Params != NULL) {
        QuicZeroMemory(Params, sizeof(*Params));
        Params->Flags = QUIC_SEC_CONFIG_FLAG_CERTIFICATE_NULL;
    }
    return Params;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPlatFreeSelfSignedCert(
    _In_ QUIC_SEC_CONFIG_PARAMS* Params
    )
{
    free(Params);
}

#endif
