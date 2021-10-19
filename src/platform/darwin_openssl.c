/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the certificate functions by calling the darwin keychain store

Environment:

    Darwin

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

#include <Security/Security.h>

#ifdef QUIC_CLOG
#include "darwin_openssl.c.clog.h"
#endif

static
QUIC_STATUS
CxPlatTlsMapTrustResultToQuicStatus(
    _In_ CFIndex ErrorResult
    )
{
    switch (ErrorResult) {
        case errSecCertificateRevoked:
            return QUIC_STATUS_REVOKED_CERTIFICATE;
        case errSecCertificateExpired:
            return QUIC_STATUS_CERT_EXPIRED;
        case errSecNotTrusted:
            return QUIC_STATUS_CERT_UNTRUSTED_ROOT;
        default:
            return QUIC_STATUS_TLS_ERROR;
    }
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
    BOOLEAN Result = FALSE;
    unsigned char* OpenSSLCertBuffer = NULL;
    CFDataRef CfData = NULL;
    SecCertificateRef Certificate = NULL;
    OSStatus Status = 0;
    CFMutableArrayRef PolicyArray = NULL;
    SecTrustRef TrustRef = NULL;
    CFStringRef SNIString = NULL;
    SecPolicyRef SSLPolicy = NULL;
    SecPolicyRef RevocationPolicy = NULL;
    CFErrorRef ErrorRef = NULL;
    int OpenSSLCertLength = 0;

    OpenSSLCertLength = i2d_X509(X509Cert, &OpenSSLCertBuffer);
    if (OpenSSLCertLength <= 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "i2d_X509 failed");
        goto Exit;
    }

    CfData =
        CFDataCreateWithBytesNoCopy(
            NULL,
            (const UInt8*)OpenSSLCertBuffer,
            OpenSSLCertLength,
            kCFAllocatorNull);
    if (CfData == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "CFDataCreateWithBytesNoCopy failed");
        goto Exit;
    }

    Certificate = SecCertificateCreateWithData(NULL, CfData);
    if (Certificate == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "SecCertificateCreateWithData failed");
        goto Exit;
    }

    if (SNI != NULL) {
        SNIString = CFStringCreateWithCStringNoCopy(NULL, SNI, kCFStringEncodingUTF8, kCFAllocatorNull);
        if (SNIString == NULL) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "CFStringCreateWithCStringNoCopy failed");
            goto Exit;
        }
    }

    PolicyArray = CFArrayCreateMutable(NULL, 3, NULL);
    if (PolicyArray == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "CFArrayCreateMutable failed");
        goto Exit;
    }

    SSLPolicy =
        SecPolicyCreateSSL(
            (CredFlags & QUIC_CREDENTIAL_FLAG_CLIENT) ? TRUE : FALSE,
            SNIString);
    if (SSLPolicy == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "SecPolicyCreateSSL failed");
        goto Exit;
    }

    CFArrayAppendValue(PolicyArray, SSLPolicy);

    if (CredFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN) {
        RevocationPolicy =
            SecPolicyCreateRevocation(
                kSecRevocationUseAnyAvailableMethod |
                kSecRevocationRequirePositiveResponse);
        if (RevocationPolicy == NULL) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "SecPolicyCreateRevocation failed");
            goto Exit;
        }

        CFArrayAppendValue(PolicyArray, RevocationPolicy);
    }

    Status =
        SecTrustCreateWithCertificates(
            Certificate,
            PolicyArray,
            &TrustRef);

    if (Status != noErr) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "SecTrustCreateWithCertificates failed");
        goto Exit;
    }

    Result = SecTrustEvaluateWithError(TrustRef, &ErrorRef);

    if (!Result) {
        if (PlatformVerificationError != NULL) {
            *PlatformVerificationError =
                CxPlatTlsMapTrustResultToQuicStatus(
                    CFErrorGetCode(ErrorRef));
        }
    }

Exit:

    if (ErrorRef != NULL) {
        CFRelease(ErrorRef);
    }

    if (TrustRef != NULL) {
        CFRelease(TrustRef);
    }

    if (RevocationPolicy != NULL) {
        CFRelease(RevocationPolicy);
    }

    if (SSLPolicy != NULL) {
        CFRelease(SSLPolicy);
    }

    if (SNIString != NULL) {
        CFRelease(SNIString);
    }

    if (PolicyArray != NULL) {
        CFRelease(PolicyArray);
    }

    if (Certificate != NULL) {
        CFRelease(Certificate);
    }

    if (CfData != NULL) {
        CFRelease(CfData);
    }

    if (OpenSSLCertBuffer != NULL) {
        OPENSSL_free(OpenSSLCertBuffer);
    }
    UNREFERENCED_PARAMETER(CredFlags);
    return Result;
}

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
