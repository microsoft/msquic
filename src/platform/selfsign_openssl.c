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
#ifdef QUIC_CLOG
#include "selfsign_openssl.c.clog.h"
#endif

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
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_PKEY_new() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    BigNum = BN_new();

    if (BigNum == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "BN_new() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = BN_set_word(BigNum, RSA_F4);

    if (Ret != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "BN_set_word() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Rsa = RSA_new();

    if (Rsa == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "RSA_new() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = RSA_generate_key_ex(Rsa, 2048, BigNum, NULL);

    if (Ret != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "RSA_generate_key_ex() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = EVP_PKEY_assign_RSA(PKey, Rsa);

    if (Ret != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_PKEY_assign_RSA() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    X509 = X509_new();

    if (X509 == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "X509_new() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = ASN1_INTEGER_set(X509_get_serialNumber(X509), 1);

    if (Ret != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "ASN1_INTEGER_set() failed");
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
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "X509_NAME_add_entry_by_txt() failed");
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
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "X509_NAME_add_entry_by_txt() failed");
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
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "X509_NAME_add_entry_by_txt() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = X509_set_issuer_name(X509, Name);

    if (Ret != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "X509_set_issuer_name() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = X509_sign(X509, PKey, EVP_sha1());

    if (Ret <= 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "X509_sign() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Fd = fopen(PrivateKeyFileName, "wb");

    if (Fd == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "fopen() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = PEM_write_PrivateKey(Fd, PKey, NULL, NULL, 0, NULL, NULL);

    if (Ret != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "PEM_write_PrivateKey() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    fclose(Fd);
    Fd = NULL;

    Fd = fopen(CertFileName, "wb");

    if (Fd == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "fopen() failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = PEM_write_X509(Fd, X509);

    if (Ret != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "PEM_write_X509() failed");
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
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "mkdtemp failed");
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
    strcat(RmCmd, Params->TempDir);
    if (system(RmCmd) == -1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Tempdir del error");
    }

    free(Params);
}
