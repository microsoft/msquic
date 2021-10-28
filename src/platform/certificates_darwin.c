/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the certificate functions by calling the darwin keychain store

Environment:

    Darwin

--*/


#include "platform_internal.h"

#include <Security/Security.h>

#ifdef QUIC_CLOG
#include "certificates_darwin.c.clog.h"
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
CxPlatCertVerifyRawCertificate(
    _In_reads_bytes_(X509CertLength) unsigned char* X509Cert,
    _In_ int X509CertLength,
    _In_opt_ const char* SNI,
    _In_ QUIC_CREDENTIAL_FLAGS CredFlags,
    _Out_opt_ uint32_t* PlatformVerificationError
    )
{
    BOOLEAN Result = FALSE;
    CFDataRef CfData = NULL;
    SecCertificateRef Certificate = NULL;
    OSStatus Status = 0;
    CFMutableArrayRef PolicyArray = NULL;
    SecTrustRef TrustRef = NULL;
    CFStringRef SNIString = NULL;
    SecPolicyRef SSLPolicy = NULL;
    SecPolicyRef RevocationPolicy = NULL;
    CFErrorRef ErrorRef = NULL;

    CfData =
        CFDataCreateWithBytesNoCopy(
            NULL,
            (const UInt8*)X509Cert,
            X509CertLength,
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

    UNREFERENCED_PARAMETER(CredFlags);
    return Result;
}

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
