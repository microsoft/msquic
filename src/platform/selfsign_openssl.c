/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    OpenSSL implementation for generating the self-signed certificate.

--*/

#define QUIC_TEST_APIS 1

#include "platform_internal.h"
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/kdf.h"
#include "openssl/rsa.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "selfsign_openssl.c.clog.h"

//
// Generates a self signed cert using low level OpenSSL APIs.
//
QUIC_STATUS
QuicTlsGenerateSelfSignedCert(
    _In_z_ char *CertFileName,
    _In_z_ char *PrivateKeyFileName,
    _In_z_ char *SNI
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;
    EVP_PKEY *PKey = NULL;
    BIGNUM *BigNum = NULL;
    RSA * Rsa = NULL;
    X509 *X509 = NULL;
    X509_NAME *Name = NULL;
    FILE *Fd = NULL;

    PKey = EVP_PKEY_new();

    if (PKey == NULL) {
        QuicTraceLogError(FN_selfsign_opensslc127736118cc2d5595f12d8afb0bc56b, "[TLS] EVP_PKEY_new() failed.");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    BigNum = BN_new();

    if (BigNum == NULL) {
        QuicTraceLogError(FN_selfsign_opensslfe5e8db30d1d3ecb6509556988c9b3a1, "[TLS] BN_new() failed.");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = BN_set_word(BigNum, RSA_F4);

    if (Ret != 1) {
        QuicTraceLogError(FN_selfsign_openssl805217919553b3b01cd7b0fcd2ad3d8e, "[TLS] BN_set_word() failed.");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Rsa = RSA_new();

    if (Rsa == NULL) {
        QuicTraceLogError(FN_selfsign_openssl9ad9fa0b1072e8efa689e4bec75763d1, "[TLS] RSA_new() failed.");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = RSA_generate_key_ex(Rsa, 2048, BigNum, NULL);

    if (Ret != 1) {
        QuicTraceLogError(FN_selfsign_openssla0e51324c09915fcabf2444b1938ab2f, "[TLS] RSA_generate_key_ex() failed.");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = EVP_PKEY_assign_RSA(PKey, Rsa);

    if (Ret != 1) {
        QuicTraceLogError(FN_selfsign_openssld38daeb187fe185dfb06653bde718d4c, "[TLS] EVP_PKEY_assign_RSA() failed.");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    X509 = X509_new();

    if (X509 == NULL) {
        QuicTraceLogError(FN_selfsign_opensslb9bf4ef0753f00337102eded740abde8, "[TLS] X509_new() failed.");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = ASN1_INTEGER_set(X509_get_serialNumber(X509), 1);

    if (Ret != 1) {
        QuicTraceLogError(FN_selfsign_openssl174350b9ebb57b662c8c7b169fc55f1a, "[TLS] ASN1_INTEGER_set() failed.");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    X509_gmtime_adj(X509_get_notBefore(X509), 0);
    X509_gmtime_adj(X509_get_notAfter(X509), 31536000L);

    X509_set_pubkey(X509, PKey);

    Name = X509_get_subject_name(X509);

    Ret =
        X509_NAME_add_entry_by_txt(
            Name,
            "C",
            MBSTRING_ASC,
            (unsigned char *)"CA",
            -1,
            -1,
            0);

    if (Ret != 1) {
        QuicTraceLogError(FN_selfsign_openssl8ddef828bc555ccfd88a6b2251f7292b, "[TLS] X509_NAME_add_entry_by_txt() failed.");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret =
        X509_NAME_add_entry_by_txt(
            Name,
            "O",
            MBSTRING_ASC,
            (unsigned char *)"Microsoft",
            -1,
            -1,
            0);

    if (Ret != 1) {
        QuicTraceLogError(FN_selfsign_openssl8ddef828bc555ccfd88a6b2251f7292b, "[TLS] X509_NAME_add_entry_by_txt() failed.");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret =
        X509_NAME_add_entry_by_txt(
            Name,
            "CN",
            MBSTRING_ASC,
            (unsigned char *)SNI,
            -1,
            -1,
            0);

    if (Ret != 1) {
        QuicTraceLogError(FN_selfsign_openssl8ddef828bc555ccfd88a6b2251f7292b, "[TLS] X509_NAME_add_entry_by_txt() failed.");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = X509_set_issuer_name(X509, Name);

    if (Ret != 1) {
        QuicTraceLogError(FN_selfsign_openssl49b07c01f59b641cdfce3bb0eda41ccc, "[TLS] X509_set_issuer_name() failed.");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = X509_sign(X509, PKey, EVP_sha1());

    if (Ret <= 0) {
        QuicTraceLogError(FN_selfsign_openssl2aeca81363e26209e08f7710970beffd, "[TLS] X509_sign() failed.");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Fd = fopen(PrivateKeyFileName, "wb");

    if (Fd == NULL) {
        QuicTraceLogError(FN_selfsign_openssl9bce86d6dcf2f55921124f561b62080f, "[TLS] fopen() failed.");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = PEM_write_PrivateKey(Fd, PKey, NULL, NULL, 0, NULL, NULL);

    if (Ret != 1) {
        QuicTraceLogError(FN_selfsign_opensslc751bf4dc901c1a13f91a3bcd1d9b1d9, "[TLS] PEM_write_PrivateKey() failed.");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    fclose(Fd);
    Fd = NULL;

    Fd = fopen(CertFileName, "wb");

    if (Fd == NULL) {
        QuicTraceLogError(FN_selfsign_openssl9bce86d6dcf2f55921124f561b62080f, "[TLS] fopen() failed.");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = PEM_write_X509(Fd, X509);

    if (Ret != 1) {
        QuicTraceLogError(FN_selfsign_opensslcdfc999a26196eeb603320c983e61869, "[TLS] PEM_write_X509() failed.");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    fclose(Fd);
    Fd = NULL;

Exit:

    if (PKey != NULL) {
        EVP_PKEY_free(PKey);
        PKey= NULL;
    }

    if (BigNum != NULL) {
        BN_free(BigNum);
        BigNum = NULL;
    }

    if (X509 != NULL) {
        X509_free(X509);
        X509 = NULL;
    }

    if (Fd != NULL) {
        fclose(Fd);
        Fd = NULL;
    }

    return Status;
}

static char* QuicTestCertFilename = (char*)"localhost_cert.pem";
static char* QuicTestPrivateKeyFilename = (char*)"localhost_key.pem";

typedef struct QUIC_SEC_CONFIG_PARAMS_INTERNAL {
    QUIC_SEC_CONFIG_PARAMS;
    QUIC_CERTIFICATE_FILE CertFile;
    const char* TempDir;
    char CertFilepath[50];
    char PrivateKeyFilepath[50];

} QUIC_SEC_CONFIG_PARAMS_INTERNAL;

#define TEMP_DIR_TEMPLATE "/tmp/quictest.XXXXXX"

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_SEC_CONFIG_PARAMS*
QuicPlatGetSelfSignedCert(
    _In_ QUIC_SELF_SIGN_CERT_TYPE Type
    )
{
    UNREFERENCED_PARAMETER(Type);

    QUIC_SEC_CONFIG_PARAMS_INTERNAL* Params =
        malloc(sizeof(QUIC_SEC_CONFIG_PARAMS_INTERNAL) + sizeof(TEMP_DIR_TEMPLATE));
    if (Params == NULL) {
        return NULL;
    }

    QuicZeroMemory(Params, sizeof(*Params));
    Params->Flags = QUIC_SEC_CONFIG_FLAG_CERTIFICATE_FILE;
    Params->Certificate = &Params->CertFile;
    Params->CertFile.CertificateFile = Params->CertFilepath;
    Params->CertFile.PrivateKeyFile = Params->PrivateKeyFilepath;

    char* Template = (char*)(Params + 1);
    memcpy(Template, TEMP_DIR_TEMPLATE, sizeof(TEMP_DIR_TEMPLATE));

    Params->TempDir = mkdtemp(Template);
    if (Params->TempDir == NULL) {
        QuicTraceLogError(FN_selfsign_opensslfa73f8926cf0667c631d674bbaaa24d1, "[TLS] mkdtemp failed.");
        goto Error;
    }

    QuicCopyMemory(
        Params->CertFilepath,
        Params->TempDir,
        strlen(Params->TempDir));
    QuicCopyMemory(
        Params->CertFilepath + strlen(Params->TempDir),
        "/",
        1);
    QuicCopyMemory(
        Params->CertFilepath + strlen(Params->TempDir) + 1,
        QuicTestCertFilename,
        strlen(QuicTestCertFilename));
    QuicCopyMemory(
        Params->PrivateKeyFilepath,
        Params->TempDir,
        strlen(Params->TempDir));
    QuicCopyMemory(
        Params->PrivateKeyFilepath + strlen(Params->TempDir),
        "/",
        1);
    QuicCopyMemory(
        Params->PrivateKeyFilepath + strlen(Params->TempDir) + 1,
        QuicTestPrivateKeyFilename,
        strlen(QuicTestPrivateKeyFilename));

    if (QUIC_FAILED(
        QuicTlsGenerateSelfSignedCert(
            Params->CertFilepath,
            Params->PrivateKeyFilepath,
            (char *)"localhost"))) {
        goto Error;
    }

    return (QUIC_SEC_CONFIG_PARAMS*)Params;

Error:

    free(Params);

    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicPlatFreeSelfSignedCert(
    _In_ QUIC_SEC_CONFIG_PARAMS* _Params
    )
{
    QUIC_SEC_CONFIG_PARAMS_INTERNAL* Params =
        (QUIC_SEC_CONFIG_PARAMS_INTERNAL*)_Params;

    char RmCmd[32] = {0};
    strncpy(RmCmd, "rm -rf ", 7 + 1);
    strncat(RmCmd, Params->TempDir, strlen(Params->TempDir) + 1);
    if (system(RmCmd) == -1) {
        QuicTraceLogError(FN_selfsign_openssl0f54fbec435802718e07ac871986d61e, "[TLS] Tempdir del error.");
    }

    free(Params);
}
