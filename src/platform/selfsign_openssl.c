/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    OpenSSL implementation for generating the self-signed certificate.

--*/

#define QUIC_TEST_APIS 1
#define _CRT_SECURE_NO_WARNINGS // NOLINT bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp

#include <fcntl.h>
#ifndef _WIN32
#include <glob.h>
#endif
#include "platform_internal.h"
#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable:4100) // Unreferenced parameter errcode in inline function
#endif
#include "openssl/err.h"
#include "openssl/kdf.h"
#include "openssl/pem.h"
#include "openssl/pkcs12.h"
#include "openssl/rsa.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#include "openssl/x509v3.h"

#include <sys/stat.h>
#include <sys/types.h>
#ifdef _WIN32
#pragma warning(pop)
#endif
#ifdef __APPLE__
#include <TargetConditionals.h>
#endif
#ifdef QUIC_CLOG
#include "selfsign_openssl.c.clog.h"
#endif


static uint8_t* ReadPkcs12(const char* Name, uint32_t* Length) {
    size_t FileSize = 0;
    FILE* Handle = fopen(Name, "rb");
    if (Handle == NULL) {
        return NULL;
    }
#ifdef _WIN32
    struct _stat Stat;
    if (_fstat(_fileno(Handle), &Stat) == 0) {
        FileSize = (int)Stat.st_size;
    }
#else
    struct stat Stat;
    if (fstat(fileno(Handle), &Stat) == 0) {
        FileSize = (int)Stat.st_size;
    }
#endif
    if (FileSize == 0) {
        fclose(Handle);
        return NULL;
    }

    uint8_t* Buffer = (uint8_t *)malloc(FileSize);
    if (Buffer == NULL) {
        fclose(Handle);
        return NULL;
    }

    size_t ReadLength = 0;
    *Length = 0;
    do {
        ReadLength = fread(Buffer + *Length, 1, FileSize - *Length, Handle);
        *Length += (uint32_t)ReadLength;
    } while (ReadLength > 0 && *Length < (uint32_t)FileSize);
    fclose(Handle);
    if (*Length != FileSize) {
        free(Buffer);
        return NULL;
    }
    return Buffer;
}

//
// Generates a signed cert using low level OpenSSL APIs.
// Issue certificate from provided CA, or create self-signed
// certificate.
//


QUIC_STATUS
GenerateX509Cert(
    _In_opt_ X509 *CaX509,
    _In_opt_ EVP_PKEY *CaPKey,
    _In_z_ char *SNI,
    _In_ BOOLEAN GenCaCert,
    _Out_ X509 **OutCert,
    _Out_ EVP_PKEY **PrivKey
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;
    EVP_PKEY *PKey = NULL;
    EVP_PKEY_CTX *EcKeyCtx = NULL;
    X509 *Cert = NULL;
    X509_NAME *Name = NULL;
    X509_NAME *IssuerName = NULL;

    // Generate private key (RSA)
    PKey = EVP_PKEY_new();
    if (PKey == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_PKEY_new failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    EcKeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (EcKeyCtx == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_PKEY_CTX_new_id failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = EVP_PKEY_keygen_init(EcKeyCtx);
    if (Ret != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_PKEY_keygen_init failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    Ret = EVP_PKEY_keygen(EcKeyCtx, &PKey);
    if (Ret != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "EVP_PKEY_keygen failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    // Generate X509 certificate
    Cert = X509_new();
    if (Cert == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "X509_new failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    X509_set_version(Cert, 3);

    Ret = ASN1_INTEGER_set(X509_get_serialNumber(Cert), 1);
    if (Ret != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "ASN1_INTEGER_set failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    X509_gmtime_adj(X509_getm_notBefore(Cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(Cert), 31536000L);

    X509_set_pubkey(Cert, PKey);

    Name = X509_get_subject_name(Cert);

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
            "X509_NAME_add_entry_by_txt failed");
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
            "X509_NAME_add_entry_by_txt failed");
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
            "X509_NAME_add_entry_by_txt failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    // Issue certificate from CA cert, or create self-signed cert
    if (CaX509 != NULL) {
        IssuerName = X509_get_subject_name(CaX509);
    }
    else {
        IssuerName = Name;
    }

    Ret = X509_set_issuer_name(Cert, IssuerName);
    if (Ret != 1) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "X509_set_issuer_name failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    if (GenCaCert == TRUE) {
        // Set basicConstraints: critical,CA:TRUE
        X509_EXTENSION *ex;
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, Cert, Cert, NULL, NULL, 0);

        ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_basic_constraints,
                                 "critical,CA:TRUE");
        if (ex == NULL) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "X509V3_EXT_conf_nid failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        Ret = X509_add_ext(Cert, ex, -1);
        X509_EXTENSION_free(ex);

        if (Ret <= 0) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "X509_add_ext failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }
    }

    // Self signed or issued by CA
    if (CaPKey != NULL) {
        Ret = X509_sign(Cert, CaPKey, EVP_sha256());
    } else {
        Ret = X509_sign(Cert, PKey, EVP_sha256());
    }

    if (Ret <= 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "X509_sign failed");
        Status = QUIC_STATUS_TLS_ERROR;
        goto Exit;
    }

    *OutCert = Cert;
    *PrivKey = PKey;

    if (EcKeyCtx != NULL) {
        EVP_PKEY_CTX_free(EcKeyCtx);
        EcKeyCtx = NULL;
    }

    return Status;

Exit:
    if (PKey != NULL) {
        EVP_PKEY_free(PKey);
        PKey= NULL;
    }

    if (EcKeyCtx != NULL) {
        EVP_PKEY_CTX_free(EcKeyCtx);
        EcKeyCtx = NULL;
    }

    if (Cert != NULL) {
        X509_free(Cert);
        Cert = NULL;
    }

    return Status;
}

QUIC_STATUS
CxPlatTlsGenerateSelfSignedCert(
    _In_z_ char *CertFileName,
    _When_(OutputPkcs12 == TRUE, _Reserved_)
    _When_(OutputPkcs12 == FALSE, _In_z_)
        char *PrivateKeyFileName,
    _In_opt_z_ char *CaFileName,
    _In_z_ char *SNI,
    _In_opt_z_ char *Password,
    _In_ BOOLEAN OutputPkcs12
    )
{
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    int Ret = 0;
    EVP_PKEY *CaPKey = NULL;
    X509 *CaX509 = NULL;
    EVP_PKEY *PKey = NULL;
    X509 *x509 = NULL;
    PKCS12 *Pkcs12 = NULL;
    FILE *Fd = NULL;

    if (CaFileName != NULL) {
        // Generate CA certificate
        Status = GenerateX509Cert(
            NULL, NULL, "CA Cert", TRUE, &CaX509, &CaPKey);

        if (Status != QUIC_STATUS_SUCCESS) {
            goto Exit;
        }
    }

    Status = GenerateX509Cert(
        CaX509, CaPKey, SNI, FALSE, &x509, &PKey);

    if (Status != QUIC_STATUS_SUCCESS) {
        goto Exit;
    }

    if (CaFileName != NULL) {
        Fd = fopen(CaFileName, "wb");
        if (Fd == NULL) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "fopen failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        Ret = PEM_write_X509(Fd, CaX509);
        if (Ret != 1) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "PEM_write_X509 failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        fclose(Fd);
        Fd = NULL;
    }

    if (!OutputPkcs12) {

        Fd = fopen(PrivateKeyFileName, "wb");
        if (Fd == NULL) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "fopen failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        Ret =
            PEM_write_PrivateKey(
                Fd,
                PKey,
                Password == NULL ? NULL : EVP_aes_128_ecb(),
                NULL,
                0,
                NULL,
                Password);
        if (Ret != 1) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "PEM_write_PrivateKey failed");
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
                "fopen failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        Ret = PEM_write_X509(Fd, x509);
        if (Ret != 1) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "PEM_write_X509 failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        fclose(Fd);
        Fd = NULL;

    } else {

        Pkcs12 =
            PKCS12_create(
                Password,
                "MsQuicTest",
                PKey,
                x509,
                NULL,
                Password == NULL ? -1 : 0,
                Password == NULL ? -1 : 0,
                0, 0, 0);

        if (Pkcs12 == NULL) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "PKCS12_create failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        Fd = fopen(CertFileName, "wb");
        if (Fd == NULL) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "fopen failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        Ret = i2d_PKCS12_fp(Fd, Pkcs12);
        if (Ret != 1) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "i2d_PKCS12_fp failed");
            Status = QUIC_STATUS_TLS_ERROR;
            goto Exit;
        }

        fclose(Fd);
        Fd = NULL;
    }

Exit:

    if (CaPKey != NULL) {
        EVP_PKEY_free(CaPKey);
        CaPKey= NULL;
    }

    if (CaX509 != NULL) {
        X509_free(CaX509);
        CaX509 = NULL;
    }

    if (PKey != NULL) {
        EVP_PKEY_free(PKey);
        PKey= NULL;
    }

    if (x509 != NULL) {
        X509_free(x509);
        x509 = NULL;
    }

    if (Pkcs12 != NULL) {
        PKCS12_free(Pkcs12);
    }

    if (Fd != NULL) {
        fclose(Fd);
        Fd = NULL;
    }

    return Status;
}

static char* QuicTestServerCertFilename = (char*)"localhost_cert.pem";
static char* QuicTestServerPrivateKeyFilename = (char*)"localhost_key.pem";
static char* QuicTestServerCertFilenameSS = (char*)"localhost_ss_cert.pem";
static char* QuicTestServerPrivateKeyFilenameSS = (char*)"localhost_ss_key.pem";
static char* QuicTestServerPrivateKeyProtectedFilename = (char*)"localhost_key_prot.pem";
static char* QuicTestServerPrivateKeyProtectedFilenameSS = (char*)"localhost_ss_key_prot.pem";
static char* QuicTestServerPkcs12Filename = (char*)"localhost_certkey.p12";
static char* QuicTestServerCaCertFilename = (char*)"localhost_ca_cert.pem";
static char* QuicTestClientCertFilename = (char*)"client_cert.pem";
static char* QuicTestClientCaCertFilename = (char*)"client_ca_cert.pem";
static char* QuicTestClientPrivateKeyFilename = (char*)"client_key.pem";
static char* QuicTestClientCertFilenameSS = (char*)"client_ss_cert.pem";
static char* QuicTestClientPrivateKeyFilenameSS = (char*)"client_ss_key.pem";
static char* QuicTestClientPrivateKeyProtectedFilename = (char*)"client_key_prot.pem";
static char* QuicTestClientPrivateKeyProtectedFilenameSS = (char*)"client_ss_key_prot.pem";
static char* QuicTestClientPkcs12Filename = (char*)"client_certkey.p12";

#ifndef MAX_PATH
#define MAX_PATH 50
#endif

#define TEST_PASS "placeholder"

typedef struct CXPLAT_CREDENTIAL_CONFIG_INTERNAL {
    QUIC_CREDENTIAL_CONFIG;
    QUIC_CERTIFICATE_FILE CertFile;
    char CertFilepath[MAX_PATH];
    char PrivateKeyFilepath[MAX_PATH];
    char CaFilepath[MAX_PATH];

} CXPLAT_CREDENTIAL_CONFIG_INTERNAL;

#define TEMP_DIR_TEMPLATE   "/tmp/quictest.XXXXXX"
#define TEMP_DIR_SEARCH     "/tmp/quictest.*"

_Success_(return)
BOOLEAN
FindOrCreateTempFiles(
    const char* const CertFileName,
    const char* const KeyFileName,
    const char* const CaFileName,
    char* CertFilePath,
    char* KeyFilePath,
    char* CaFilePath
    )
{
#ifdef _WIN32
    char TempPath [MAX_PATH] = {0};
    char TempCertPath[MAX_PATH] = {0};
    char TempKeyPath[MAX_PATH] = {0};
    char TempCaPath[MAX_PATH] = {0};
    DWORD PathLength = GetTempPathA(sizeof(TempPath), TempPath);
    if (PathLength > MAX_PATH || PathLength <= 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "GetTempPathA failed");
        return FALSE;
    }
    CxPlatCopyMemory(
        TempCertPath,
        TempPath,
        PathLength);
    CxPlatCopyMemory(
        TempCertPath + PathLength,
        CertFileName,
        strlen(CertFileName));
    CxPlatCopyMemory(
        TempCertPath + PathLength + strlen(CertFileName),
        "*\0",
        2);

    WIN32_FIND_DATAA FindData = {0};
    HANDLE FindHandle = FindFirstFileA(TempCertPath, &FindData);
    if (FindHandle == INVALID_HANDLE_VALUE) {
        FindClose(FindHandle);
        //
        // File doesn't exist, create it
        //
        UINT TempFileStatus =
            GetTempFileNameA(
                TempPath,
                CertFileName,
                0,
                CertFilePath);
        if (TempFileStatus == 0) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "GetTempFileNameA Cert Path failed");
            return FALSE;
        }
    } else {
        CxPlatCopyMemory(CertFilePath, TempPath, PathLength);
        CxPlatCopyMemory(
            CertFilePath + PathLength,
            FindData.cFileName,
            strnlen(FindData.cFileName, sizeof(FindData.cFileName)));
        FindClose(FindHandle);
        FindHandle = INVALID_HANDLE_VALUE;
    }

    if (KeyFileName != NULL && KeyFilePath != NULL) {
        CxPlatCopyMemory(
            TempKeyPath,
            TempPath,
            PathLength);
        CxPlatCopyMemory(
            TempKeyPath + PathLength,
            KeyFileName,
            strlen(KeyFileName));
        CxPlatCopyMemory(
            TempKeyPath + PathLength + strlen(KeyFileName),
            "*\0",
            2);

        FindHandle = FindFirstFileA(TempKeyPath, &FindData);
        if (FindHandle == INVALID_HANDLE_VALUE) {
            FindClose(FindHandle);
            //
            // File doesn't exist, create it
            //
            UINT TempFileStatus =
                GetTempFileNameA(
                    TempPath,
                    KeyFileName,
                    0,
                    KeyFilePath);
            if (TempFileStatus == 0) {
                QuicTraceEvent(
                    LibraryError,
                    "[ lib] ERROR, %s.",
                    "GetTempFileNameA Key Path failed");
                return FALSE;
            }
        } else {
            CxPlatCopyMemory(KeyFilePath, TempPath, PathLength);
            CxPlatCopyMemory(
                KeyFilePath + PathLength,
                FindData.cFileName,
                strnlen(FindData.cFileName, sizeof(FindData.cFileName)));
            FindClose(FindHandle);
            FindHandle = INVALID_HANDLE_VALUE;
        }
    }

    if (CaFileName != NULL && CaFilePath != NULL) {
        CxPlatCopyMemory(
            TempCaPath,
            TempPath,
            PathLength);
        CxPlatCopyMemory(
            TempCaPath + PathLength,
            CaFileName,
            strlen(CaFileName));
        CxPlatCopyMemory(
            TempCaPath + PathLength + strlen(CaFileName),
            "*\0",
            2);

        FindHandle = FindFirstFileA(TempCaPath, &FindData);
        if (FindHandle == INVALID_HANDLE_VALUE) {
            FindClose(FindHandle);
            //
            // File doesn't exist, create it
            //
            UINT TempFileStatus =
                GetTempFileNameA(
                    TempPath,
                    CaFileName,
                    0,
                    CaFilePath);
            if (TempFileStatus == 0) {
                QuicTraceEvent(
                    LibraryError,
                    "[ lib] ERROR, %s.",
                    "GetTempFileNameA Key Path failed");
                return FALSE;
            }
        } else {
            CxPlatCopyMemory(CaFilePath, TempPath, PathLength);
            CxPlatCopyMemory(
                CaFilePath + PathLength,
                FindData.cFileName,
                strnlen(FindData.cFileName, sizeof(FindData.cFileName)));
            FindClose(FindHandle);
            FindHandle = INVALID_HANDLE_VALUE;
        }
    }

#else

    char TempPath[MAX_PATH] = {0};
    char* TempDir = NULL;

    glob_t GlobData = {0};
    if (glob(TEMP_DIR_SEARCH, 0, NULL, &GlobData) != 0 || GlobData.gl_pathc == 0) {
        globfree(&GlobData);
        //
        // Temp dir not found, create it
        //
        CxPlatCopyMemory(TempPath, TEMP_DIR_TEMPLATE, sizeof(TEMP_DIR_TEMPLATE));

        TempDir = mkdtemp(TempPath);
        if (TempDir == NULL) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "mkdtemp failed");
            return FALSE;
        }
    } else {
        //
        // Assume the first result is the desired folder
        //
        strncpy(
            TempPath,
            GlobData.gl_pathv[0],
            strnlen(GlobData.gl_pathv[0], sizeof(TempPath)));
        globfree(&GlobData);
        TempDir = TempPath;
    }

    CxPlatCopyMemory(
        CertFilePath,
        TempDir,
        strlen(TempDir));
    CxPlatCopyMemory(
        CertFilePath + strlen(TempDir),
        "/",
        1);
    CxPlatCopyMemory(
        CertFilePath + strlen(TempDir) + 1,
        CertFileName,
        strlen(CertFileName) + 1);

    if (KeyFilePath != NULL && KeyFileName != NULL) {
        CxPlatCopyMemory(
            KeyFilePath,
            TempDir,
            strlen(TempDir));
        CxPlatCopyMemory(
            KeyFilePath + strlen(TempDir),
            "/",
            1);
        CxPlatCopyMemory(
            KeyFilePath + strlen(TempDir) + 1,
            KeyFileName,
            strlen(KeyFileName) + 1);
    }

    if (CaFilePath != NULL && CaFileName != NULL) {
        CxPlatCopyMemory(
            CaFilePath,
            TempDir,
            strlen(TempDir));
        CxPlatCopyMemory(
            CaFilePath + strlen(TempDir),
            "/",
            1);
        CxPlatCopyMemory(
            CaFilePath + strlen(TempDir) + 1,
            CaFileName,
            strlen(CaFileName) + 1);
    }

#endif

    return TRUE;
}

_Success_(return)
BOOLEAN
FindOrCreateTempCaFile(
    const char* const CaFileName,
    char* CaFilePath
    )
{
#ifdef _WIN32
    char TempPath [MAX_PATH] = {0};
    char TempCaPath[MAX_PATH] = {0};
    DWORD PathLength = GetTempPathA(sizeof(TempPath), TempPath);
    if (PathLength > MAX_PATH || PathLength <= 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "GetTempPathA failed");
        return FALSE;
    }

    if (CaFileName != NULL && CaFilePath != NULL) {
        CxPlatCopyMemory(
            TempCaPath,
            TempPath,
            PathLength);
        CxPlatCopyMemory(
            TempCaPath + PathLength,
            CaFileName,
            strlen(CaFileName));
        CxPlatCopyMemory(
            TempCaPath + PathLength + strlen(CaFileName),
            "*\0",
            2);

        WIN32_FIND_DATAA FindData = {0};
        HANDLE FindHandle = FindFirstFileA(TempCaPath, &FindData);
        if (FindHandle == INVALID_HANDLE_VALUE) {
            FindClose(FindHandle);
            //
            // File doesn't exist, create it
            //
            UINT TempFileStatus =
                GetTempFileNameA(
                    TempPath,
                    CaFileName,
                    0,
                    CaFilePath);
            if (TempFileStatus == 0) {
                QuicTraceEvent(
                    LibraryError,
                    "[ lib] ERROR, %s.",
                    "GetTempFileNameA Key Path failed");
                return FALSE;
            }
        } else {
            CxPlatCopyMemory(CaFilePath, TempPath, PathLength);
            CxPlatCopyMemory(
                CaFilePath + PathLength,
                FindData.cFileName,
                strnlen(FindData.cFileName, sizeof(FindData.cFileName)));
            FindClose(FindHandle);
            FindHandle = INVALID_HANDLE_VALUE;
        }
    }

#else

    char TempPath[MAX_PATH] = {0};
    char* TempDir = NULL;

    glob_t GlobData = {0};
    if (glob(TEMP_DIR_SEARCH, 0, NULL, &GlobData) != 0 || GlobData.gl_pathc == 0) {
        globfree(&GlobData);
        //
        // Temp dir not found, create it
        //
        CxPlatCopyMemory(TempPath, TEMP_DIR_TEMPLATE, sizeof(TEMP_DIR_TEMPLATE));

        TempDir = mkdtemp(TempPath);
        if (TempDir == NULL) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "mkdtemp failed");
            return FALSE;
        }
    } else {
        //
        // Assume the first result is the desired folder
        //
        strncpy(
            TempPath,
            GlobData.gl_pathv[0],
            strnlen(GlobData.gl_pathv[0], sizeof(TempPath)));
        globfree(&GlobData);
        TempDir = TempPath;
    }

    if (CaFilePath != NULL && CaFileName != NULL) {
        CxPlatCopyMemory(
            CaFilePath,
            TempDir,
            strlen(TempDir));
        CxPlatCopyMemory(
            CaFilePath + strlen(TempDir),
            "/",
            1);
        CxPlatCopyMemory(
            CaFilePath + strlen(TempDir) + 1,
            CaFileName,
            strlen(CaFileName) + 1);
    }

#endif

    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
const char*
CxPlatGetSelfSignedCertCaCertificateFileName(
    _In_ BOOLEAN ClientCertificate
    )
{
    const char* CaFileName = NULL;

    if (ClientCertificate) {
#ifdef _WIN32
        CaFileName = "msquicopensslclientcacert";
#else
        CaFileName = QuicTestClientCaCertFilename;
#endif
    } else {
#ifdef _WIN32
        CaFileName = "msquicopensslservercacert";
#else
        CaFileName = QuicTestServerCaCertFilename;
#endif
    }

    char* CaFilePath = malloc(sizeof(char)*MAX_PATH);
    if (CaFilePath == NULL) {
        return NULL;
    }

    if (!FindOrCreateTempCaFile(CaFileName, CaFilePath)) {
        free(CaFilePath);
        return NULL;
    }

    return CaFilePath;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_CREDENTIAL_CONFIG*
CxPlatGetSelfSignedCert(
    _In_ CXPLAT_SELF_SIGN_CERT_TYPE Type,
    _In_ BOOLEAN ClientCertificate,
    _In_z_ const char* CaCertificateFile
    )
{
    const char* CertFileName = NULL;
    const char* KeyFileName = NULL;
    const char* CaFileName = NULL;
    BOOLEAN CreateCA = (Type == CXPLAT_SELF_SIGN_CA_CERT_USER ||
                        Type == CXPLAT_SELF_SIGN_CA_CERT_MACHINE);

    // Different architectures store files in different locations
    if (CreateCA) {
        if (ClientCertificate) {
#ifdef _WIN32
            CertFileName = "msquicopensslclientcert";
            KeyFileName = "msquicopensslclientkey";
            CaFileName = "msquicopensslclientcacert";
#else
            CertFileName = QuicTestClientCertFilename;
            KeyFileName = QuicTestClientPrivateKeyFilename;
            CaFileName = QuicTestClientCaCertFilename;
#endif
        } else {
#ifdef _WIN32
            CertFileName = "msquicopensslservercert";
            KeyFileName = "msquicopensslserverkey";
            CaFileName = "msquicopensslservercacert";
#else
            CertFileName = QuicTestServerCertFilename;
            KeyFileName = QuicTestServerPrivateKeyFilename;
            CaFileName = QuicTestServerCaCertFilename;
#endif
        }
    } else {
        if (ClientCertificate) {
#ifdef _WIN32
            CertFileName = "msquicopensslclientcertss";
            KeyFileName = "msquicopensslclientkeyss";
#else
            CertFileName = QuicTestClientCertFilenameSS;
            KeyFileName = QuicTestClientPrivateKeyFilenameSS;
#endif
        } else {
#ifdef _WIN32
            CertFileName = "msquicopensslservercertss";
            KeyFileName = "msquicopensslserverkeyss";
#else
            CertFileName = QuicTestServerCertFilenameSS;
            KeyFileName = QuicTestServerPrivateKeyFilenameSS;
#endif
        }
    }

    // Hack to allocate space for filepaths that will be properly
    // deallocated without explicit deallocation
    CXPLAT_CREDENTIAL_CONFIG_INTERNAL* Params =
        malloc(sizeof(CXPLAT_CREDENTIAL_CONFIG_INTERNAL) + sizeof(TEMP_DIR_TEMPLATE));
    if (Params == NULL) {
        return NULL;
    }

    CxPlatZeroMemory(Params, sizeof(*Params));
    Params->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    Params->CertificateFile = &Params->CertFile;
    Params->CertFile.CertificateFile = Params->CertFilepath;
    Params->CertFile.PrivateKeyFile = Params->PrivateKeyFilepath;

    if (CreateCA) {
        if (CaCertificateFile) {
            Params->CaCertificateFile = CaCertificateFile;
        } else {
            Params->CaCertificateFile = Params->CaFilepath;
        }
    } else {
        Params->CaCertificateFile = NULL;
    }

    if (!FindOrCreateTempFiles(
            CertFileName,
            KeyFileName,
            CaFileName,
            Params->CertFilepath,
            Params->PrivateKeyFilepath,
            (CreateCA ? Params->CaFilepath : NULL))) {
        goto Error;
    }

    if (QUIC_FAILED(
        CxPlatTlsGenerateSelfSignedCert(
            Params->CertFilepath,
            Params->PrivateKeyFilepath,
            CreateCA ?
                Params->CaFilepath:
                NULL,
            ClientCertificate ?
                (char *)"MsQuicClient":
                (char *)"localhost",
            NULL,
            FALSE))) {
        goto Error;
    }

    return (QUIC_CREDENTIAL_CONFIG*)Params;

Error:

#if _WIN32
    DeleteFileA(Params->CertFilepath);
    DeleteFileA(Params->PrivateKeyFilepath);
#endif
    free(Params);

    return NULL;
}

// Generate certificates for testing, either self-signed certificates
// or from a self-signed CA certificate.
_IRQL_requires_max_(PASSIVE_LEVEL)
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
    _When_(CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE, _Out_)
    _When_(CredType != QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE, _Reserved_)
        QUIC_CERTIFICATE_FILE* CertFile,
    _When_(CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED, _Out_)
    _When_(CredType != QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED, _Reserved_)
        QUIC_CERTIFICATE_FILE_PROTECTED* CertFileProtected,
    _When_(CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12, _Out_)
    _When_(CredType != QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12, _Reserved_)
        QUIC_CERTIFICATE_PKCS12* Pkcs12,
    _When_(CredType == QUIC_CREDENTIAL_TYPE_NONE, _Out_z_bytecap_(100))
    _When_(CredType != QUIC_CREDENTIAL_TYPE_NONE, _Reserved_)
        char Principal[100]
    )
{
    UNREFERENCED_PARAMETER(StoreType);
    UNREFERENCED_PARAMETER(Params);
    UNREFERENCED_PARAMETER(CertHash);
    UNREFERENCED_PARAMETER(CertHashStore);
    UNREFERENCED_PARAMETER(Principal);
    BOOLEAN Result = FALSE;
    if ((Type == CXPLAT_TEST_CERT_SELF_SIGNED_SERVER ||
         Type == CXPLAT_TEST_CERT_SELF_SIGNED_CLIENT ||
         Type == CXPLAT_TEST_CERT_CA_CLIENT ||
         Type == CXPLAT_TEST_CERT_CA_SERVER) &&
        (CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE ||
         CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED ||
         CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12)) {

        const char* CertFileName = NULL;
        const char* KeyFileName = NULL;
        const char* CaFileName = NULL;
        char* CertFilePath = NULL;
        char* KeyFilePath = NULL;
        char* CaFilePath = NULL;
        BOOLEAN IsClient = (Type == CXPLAT_TEST_CERT_SELF_SIGNED_CLIENT ||
                            Type == CXPLAT_TEST_CERT_CA_CLIENT);
        BOOLEAN IsCa = (Type == CXPLAT_TEST_CERT_CA_CLIENT ||
                        Type == CXPLAT_TEST_CERT_CA_SERVER);


        // Optionally generate self-signed CA certificate to use when
        // generate test certificate
        if (IsCa) {
            if (Type == CXPLAT_TEST_CERT_CA_CLIENT) {
                CaFileName = QuicTestClientCaCertFilename;
            } else if (Type == CXPLAT_TEST_CERT_CA_SERVER) {
                CaFileName = QuicTestServerCaCertFilename;
            }
            CaFilePath = malloc(MAX_PATH);
            if (CaFilePath == NULL) {
                return FALSE;
            }
        }

        if (CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE) {
            // Generate plaintext certificate files
            if (IsCa) {
                if (IsClient) {
                    CertFileName = QuicTestClientCertFilename;
                    KeyFileName = QuicTestClientPrivateKeyFilename;
                } else {
                    CertFileName = QuicTestServerCertFilename;
                    KeyFileName = QuicTestServerPrivateKeyFilename;
                }
            } else {
                if (IsClient) {
                    CertFileName = QuicTestClientCertFilenameSS;
                    KeyFileName = QuicTestClientPrivateKeyFilenameSS;
                } else {
                    CertFileName = QuicTestServerCertFilenameSS;
                    KeyFileName = QuicTestServerPrivateKeyFilenameSS;
                }
            }

            CertFilePath = malloc(MAX_PATH * 2);
            if (CertFilePath == NULL) {
                if (CaFilePath != NULL) {
                    free(CaFilePath);
                    CaFilePath = NULL;
                }
                return FALSE;
            }
            KeyFilePath = CertFilePath + MAX_PATH;

            _Analysis_assume_(CertFile != NULL);
            CertFile->CertificateFile = CertFilePath;
            CertFile->PrivateKeyFile = KeyFilePath;
        } else if (CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {
            // Generate password protected certificate files
            if (IsCa) {
                if (IsClient) {
                    CertFileName = QuicTestClientCertFilename;
                    KeyFileName = QuicTestClientPrivateKeyProtectedFilename;
                } else {
                    CertFileName = QuicTestServerCertFilename;
                    KeyFileName = QuicTestServerPrivateKeyProtectedFilename;
                }
            } else {
                if (IsClient) {
                    CertFileName = QuicTestClientCertFilenameSS;
                    KeyFileName = QuicTestClientPrivateKeyProtectedFilenameSS;
                } else {
                    CertFileName = QuicTestServerCertFilenameSS;
                    KeyFileName = QuicTestServerPrivateKeyProtectedFilenameSS;
                }
            }


            CertFilePath =
                malloc((MAX_PATH * 2) + sizeof(TEST_PASS));
            if (CertFilePath == NULL) {
                if (CaFilePath != NULL) {
                    free(CaFilePath);
                    CaFilePath = NULL;
                }
                return FALSE;
            }
            KeyFilePath = CertFilePath + MAX_PATH;

            _Analysis_assume_(CertFileProtected != NULL);
            CertFileProtected->CertificateFile = CertFilePath;
            CertFileProtected->PrivateKeyFile = KeyFilePath;
            CertFileProtected->PrivateKeyPassword = KeyFilePath + MAX_PATH;
            CxPlatCopyMemory(KeyFilePath + MAX_PATH, TEST_PASS, sizeof(TEST_PASS));
        } else {
            if (IsClient) {
                CertFileName = QuicTestClientPkcs12Filename;
            } else {
                CertFileName = QuicTestServerPkcs12Filename;
            }
            CertFilePath = malloc(MAX_PATH);
            if (CertFilePath == NULL) {
                if (CaFilePath != NULL) {
                    free(CaFilePath);
                    CaFilePath = NULL;
                }
                return FALSE;
            }
        }

        // Ensure files can be created and find temporary directory for them
        if (!FindOrCreateTempFiles(CertFileName, KeyFileName, CaFileName, CertFilePath, KeyFilePath, CaFilePath)) {
            goto Error;
        }

        // Generate certificate, optionally provide CA to generate from
        if (QUIC_FAILED(
                CxPlatTlsGenerateSelfSignedCert(
                    CertFilePath,
                    KeyFilePath,
                    CaFilePath,
                    Type == CXPLAT_TEST_CERT_SELF_SIGNED_SERVER ? "localhost" : "MsQuicClient",
                    CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE ? NULL : TEST_PASS,
                    CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12))) {
            goto Error;
        }

        if (IsCa) {
            // Save location of CA in parameter
            Params->CaCertificateFile = CaFilePath;
            CaFilePath = NULL;
        }

        if (CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE) {
            Params->CertificateFile = CertFile;
            CertFilePath = NULL;
        } else if (CredType == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {
            Params->CertificateFileProtected = CertFileProtected;
            CertFilePath = NULL;
        } else {
            _Analysis_assume_(Pkcs12 != NULL);
            Params->CertificatePkcs12 = Pkcs12;
            Pkcs12->Asn1Blob = ReadPkcs12(CertFilePath, &Pkcs12->Asn1BlobLength);
            if (Pkcs12->Asn1Blob == NULL) {
                goto Error;
            }
            //
            // Repurpose CertFilePath to store the password.
            //
            Pkcs12->PrivateKeyPassword = CertFilePath;
            CxPlatCopyMemory(CertFilePath, TEST_PASS, sizeof(TEST_PASS));
            CertFilePath = NULL;
        }
        Params->Type = CredType;
        Result = TRUE;
Error:
        if (CertFilePath != NULL) {
            free(CertFilePath);
        }
        if (CaFilePath != NULL) {
            free(CaFilePath);
        }
    }
    return Result;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatFreeTestCert(
    _In_ QUIC_CREDENTIAL_CONFIG* Params
    )
{
    if (Params->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE) {
        free((char*)Params->CertificateFile->CertificateFile);
    } else if (Params->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED) {
        free((char*)Params->CertificateFileProtected->CertificateFile);
    } else if (Params->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12) {
        free((uint8_t*)Params->CertificatePkcs12->Asn1Blob);
        free((char*)Params->CertificatePkcs12->PrivateKeyPassword);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatFreeSelfSignedCert(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig
    )
{
    CXPLAT_CREDENTIAL_CONFIG_INTERNAL* Params =
        (CXPLAT_CREDENTIAL_CONFIG_INTERNAL*)CredConfig;

#ifdef TARGET_OS_IOS
    UNREFERENCED_PARAMETER(CredConfig);
    UNREFERENCED_PARAMETER(Params);
#endif

    free(Params);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatFreeSelfSignedCertCaFile(
    _In_z_ const char* CaFile
    )
{
#ifdef TARGET_OS_IOS
    UNREFERENCED_PARAMETER(CaFile);
#endif

    free((char*) CaFile);
}
