/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Shims the certificate functions on posix

Environment:

    Posix

--*/

#include "platform_internal.h"

#define OPENSSL_SUPPRESS_DEPRECATED 1 // For hmac.h, which was deprecated in 3.0
#include "openssl/err.h"
#include "openssl/hmac.h"
#include "openssl/kdf.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"

#ifdef QUIC_CLOG
#include "posix_openssl.c.clog.h"
#endif

QUIC_STATUS
CxPlatTlsExtractPrivateKey(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _Out_ EVP_PKEY** EvpPrivateKey,
    _Out_ X509** X509Cert
    )
{
    UNREFERENCED_PARAMETER(CredConfig);
    UNREFERENCED_PARAMETER(EvpPrivateKey);
    UNREFERENCED_PARAMETER(X509Cert);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_Success_(return != FALSE)
BOOLEAN
CxPlatTlsVerifyCertificate(
    _In_ X509* X509Cert,
    _In_opt_ const char* SNI,
    _In_ QUIC_CREDENTIAL_FLAGS CredFlags,
    _Out_opt_ uint32_t* PlatformVerificationError
    )
{
    UNREFERENCED_PARAMETER(X509Cert);
    UNREFERENCED_PARAMETER(SNI);
    UNREFERENCED_PARAMETER(CredFlags);
    UNREFERENCED_PARAMETER(PlatformVerificationError);
    return 0;
}
