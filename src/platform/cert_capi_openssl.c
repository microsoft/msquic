/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the certificate functions by calling the Windows certificate
    store.

Environment:

    Windows User Mode

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
#include "cert_capi_openssl.c.clog.h"
#endif

#ifdef _WIN32
#include <wincrypt.h>
#include <msquic.h>

QUIC_STATUS
QuicTlsExtractPrivateKey(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _Out_ RSA** RsaKey,
    _Out_ X509** X509Cert
    )
{
    QUIC_CERTIFICATE* Cert = NULL;
    BYTE* KeyData = NULL;
    RSA* Rsa = NULL;
    DWORD KeyLength = 0;
    NCRYPT_KEY_HANDLE KeyHandle = 0;
    PCCERT_CONTEXT CertCtx = NULL;
    X509* X509CertStorage = NULL;
    QUIC_STATUS Status;
    int Ret = 0;

    if (QUIC_FAILED(
        Status =
            QuicCertCreate(CredConfig, &Cert))) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "QuicCertCreate");
        goto Exit;
    }

    CertCtx = (PCCERT_CONTEXT)Cert;
    X509CertStorage =
        d2i_X509(
            NULL,
            (const unsigned char**)&CertCtx->pbCertEncoded,
            CertCtx->cbCertEncoded);
    if (X509CertStorage == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "d2i_X509 failed");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    KeyHandle = (NCRYPT_KEY_HANDLE)QuicCertGetPrivateKey(Cert);
    if (KeyHandle == 0) {
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Exit;
    }

    if (FAILED(
        Status =
            NCryptExportKey(
                KeyHandle,
                0,
                BCRYPT_RSAFULLPRIVATE_BLOB,
                NULL,
                NULL,
                0,
                &KeyLength,
                0))) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "NCryptExportKey failed. Need exportable certificate");
        goto Exit;
    }

    KeyData = QUIC_ALLOC_NONPAGED(KeyLength, QUIC_POOL_TLS_RSA);
    if (KeyData == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "RSA Key",
            KeyLength);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    if (FAILED(Status =
        NCryptExportKey(
            KeyHandle,
            0,
            BCRYPT_RSAFULLPRIVATE_BLOB,
            NULL,
            KeyData,
            KeyLength,
            &KeyLength,
            0))) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "NCryptExportKey failed. Need exportable certificate");
        goto Exit;
    }

    BCRYPT_RSAKEY_BLOB* Blob = (BCRYPT_RSAKEY_BLOB*)KeyData;

    if (Blob->Magic != BCRYPT_RSAFULLPRIVATE_MAGIC) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "NCryptExportKey resulted in incorrect magic number");
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Exit;
    }

    Rsa = RSA_new();
    if (Rsa == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "RSA_new failed");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    // n is the modulus common to both public and private key
    BIGNUM* n = BN_bin2bn(KeyData + sizeof(BCRYPT_RSAKEY_BLOB) + Blob->cbPublicExp, Blob->cbModulus, NULL);
    // e is the public exponent
    BIGNUM* e = BN_bin2bn(KeyData + sizeof(BCRYPT_RSAKEY_BLOB), Blob->cbPublicExp, NULL);
    // d is the private exponent
    BIGNUM* d = BN_bin2bn(KeyData + sizeof(BCRYPT_RSAKEY_BLOB) + Blob->cbPublicExp + Blob->cbModulus + Blob->cbPrime1 + Blob->cbPrime2 + Blob->cbPrime1 + Blob->cbPrime2 + Blob->cbPrime1, Blob->cbModulus, NULL);

    Ret = RSA_set0_key(Rsa, n, e, d);
    if (Ret != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "RSA_set0_key failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    // p and q are the first and second factor of n
    BIGNUM* p = BN_bin2bn(KeyData + sizeof(BCRYPT_RSAKEY_BLOB) + Blob->cbPublicExp + Blob->cbModulus, Blob->cbPrime1, NULL);
    BIGNUM* q = BN_bin2bn(KeyData + sizeof(BCRYPT_RSAKEY_BLOB) + Blob->cbPublicExp + Blob->cbModulus + Blob->cbPrime1, Blob->cbPrime2, NULL);

    Ret = RSA_set0_factors(Rsa, p, q);
    if (Ret != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "RSA_set0_factors failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    // dmp1, dmq1 and iqmp are the exponents and coefficient for CRT calculations
    BIGNUM* dmp1 = BN_bin2bn(KeyData + sizeof(BCRYPT_RSAKEY_BLOB) + Blob->cbPublicExp + Blob->cbModulus + Blob->cbPrime1 + Blob->cbPrime2, Blob->cbPrime1, NULL);
    BIGNUM* dmq1 = BN_bin2bn(KeyData + sizeof(BCRYPT_RSAKEY_BLOB) + Blob->cbPublicExp + Blob->cbModulus + Blob->cbPrime1 + Blob->cbPrime2 + Blob->cbPrime1, Blob->cbPrime2, NULL);
    BIGNUM* iqmp = BN_bin2bn(KeyData + sizeof(BCRYPT_RSAKEY_BLOB) + Blob->cbPublicExp + Blob->cbModulus + Blob->cbPrime1 + Blob->cbPrime2 + Blob->cbPrime1 + Blob->cbPrime2, Blob->cbPrime1, NULL);

    Ret = RSA_set0_crt_params(Rsa, dmp1, dmq1, iqmp);
    if (Ret != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "RSA_set0_crt_params failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    *RsaKey = Rsa;
    Rsa = NULL;
    *X509Cert = X509CertStorage;
    X509CertStorage = NULL;
    Status = QUIC_STATUS_SUCCESS;

Exit:
    if (X509CertStorage != NULL) {
        X509_free(X509CertStorage);
    }

    if (Rsa != NULL) {
        RSA_free(Rsa);
    }

    if (KeyData != NULL) {
        QUIC_FREE(KeyData, QUIC_POOL_TLS_RSA);
    }

    if (CertCtx != NULL) {
        QuicCertDeletePrivateKey((void*)CertCtx);
    }

    if (Cert != NULL && CredConfig->Type != QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT) {
        QuicCertFree(Cert);
    }

    return Status;
}
#else
QUIC_STATUS
QuicTlsExtractPrivateKey(
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
#endif
