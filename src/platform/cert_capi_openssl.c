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

#include <wincrypt.h>
#include <msquic.h>


QUIC_STATUS
QuicTlsExtractPrivateKey(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _Out_ EVP_PKEY** EvpPrivateKey,
    _Out_ X509** X509Cert
    )
{
    QUIC_CERTIFICATE* Cert = NULL;
    BYTE* KeyData = NULL;
    RSA* Rsa = NULL;
    DWORD KeyLength = 0;
    EVP_PKEY* PrivateKey = NULL;
    NCRYPT_KEY_HANDLE KeyHandle = 0;
    PCCERT_CONTEXT CertCtx = NULL;
    X509* X509CertStorage = NULL;
    QUIC_STATUS Status;


    if (QUIC_FAILED(
        Status =
            QuicCertCreate(CredConfig, &Cert))) {
        goto Exit;
    }

    CertCtx = (PCCERT_CONTEXT)Cert;
    X509CertStorage =
        d2i_X509(
            NULL,
            (const unsigned char**)&CertCtx->pbCertEncoded,
            CertCtx->cbCertEncoded);

    if (X509CertStorage == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    // TODO Null Check This
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

    KeyData = QUIC_ALLOC_NONPAGED(KeyLength, QUIC_POOL_TMP_ALLOC);
    if (KeyData == NULL) {
        // TODO Logging
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
        goto Exit;
    }

    BCRYPT_RSAKEY_BLOB* Blob = (BCRYPT_RSAKEY_BLOB*)KeyData;

    if (Blob->Magic != BCRYPT_RSAFULLPRIVATE_MAGIC) {
        // Invalid Cert
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Exit;
    }

    Rsa = RSA_new();
    if (Rsa == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    // n is the modulus common to both public and private key
    BIGNUM* n = BN_bin2bn(KeyData + sizeof(BCRYPT_RSAKEY_BLOB) + Blob->cbPublicExp, Blob->cbModulus, NULL);
    // e is the public exponent
    BIGNUM* e = BN_bin2bn(KeyData + sizeof(BCRYPT_RSAKEY_BLOB), Blob->cbPublicExp, NULL);
    // d is the private exponent
    BIGNUM* d = BN_bin2bn(KeyData + sizeof(BCRYPT_RSAKEY_BLOB) + Blob->cbPublicExp + Blob->cbModulus + Blob->cbPrime1 + Blob->cbPrime2 + Blob->cbPrime1 + Blob->cbPrime2 + Blob->cbPrime1, Blob->cbModulus, NULL);

    // TODO Error checking
    RSA_set0_key(Rsa, n, e, d);

    // p and q are the first and second factor of n
    BIGNUM* p = BN_bin2bn(KeyData + sizeof(BCRYPT_RSAKEY_BLOB) + Blob->cbPublicExp + Blob->cbModulus, Blob->cbPrime1, NULL);
    BIGNUM* q = BN_bin2bn(KeyData + sizeof(BCRYPT_RSAKEY_BLOB) + Blob->cbPublicExp + Blob->cbModulus + Blob->cbPrime1, Blob->cbPrime2, NULL);

    RSA_set0_factors(Rsa, p, q);

    // dmp1, dmq1 and iqmp are the exponents and coefficient for CRT calculations
    BIGNUM* dmp1 = BN_bin2bn(KeyData + sizeof(BCRYPT_RSAKEY_BLOB) + Blob->cbPublicExp + Blob->cbModulus + Blob->cbPrime1 + Blob->cbPrime2, Blob->cbPrime1, NULL);
    BIGNUM* dmq1 = BN_bin2bn(KeyData + sizeof(BCRYPT_RSAKEY_BLOB) + Blob->cbPublicExp + Blob->cbModulus + Blob->cbPrime1 + Blob->cbPrime2 + Blob->cbPrime1, Blob->cbPrime2, NULL);
    BIGNUM* iqmp = BN_bin2bn(KeyData + sizeof(BCRYPT_RSAKEY_BLOB) + Blob->cbPublicExp + Blob->cbModulus + Blob->cbPrime1 + Blob->cbPrime2 + Blob->cbPrime1 + Blob->cbPrime2, Blob->cbPrime1, NULL);

    RSA_set0_crt_params(Rsa, dmp1, dmq1, iqmp);

    PrivateKey = EVP_PKEY_new();
    if (PrivateKey == NULL) {
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    EVP_PKEY_assign_RSA(PrivateKey, Rsa);

    Rsa = NULL;
    *EvpPrivateKey = PrivateKey;
    PrivateKey = NULL;
    *X509Cert = X509CertStorage;
    X509CertStorage = NULL;
    Status = QUIC_STATUS_SUCCESS;

Exit:
    if (X509CertStorage != NULL) {
        X509_free(X509CertStorage);
    }

    if (PrivateKey != NULL) {
        EVP_PKEY_free(PrivateKey);
    }

    if (Rsa != NULL) {
        RSA_free(Rsa);
    }

    if (KeyData != NULL) {
        QUIC_FREE(KeyData, QUIC_POOL_TMP_ALLOC); // TODO Add tag
    }

    if (CertCtx != NULL) {
        QuicCertDeletePrivateKey((void*)CertCtx);
    }

    if (Cert != NULL) {
        QuicCertFree(Cert);
    }

    return Status;
}
