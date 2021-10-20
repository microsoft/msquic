/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Implements the certificate functions by calling the Windows certificate
    store.

Environment:

    Windows User Mode

--*/

#define QUIC_TEST_APIS 1
#include "platform_internal.h"

#define OPENSSL_SUPPRESS_DEPRECATED 1 // For hmac.h, which was deprecated in 3.0
#pragma warning(push)
#pragma warning(disable:4100) // Unreferenced parameter errcode in inline function
#include "openssl/err.h"
#include "openssl/hmac.h"
#include "openssl/kdf.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "openssl/ssl.h"
#include "openssl/x509.h"
#pragma warning(pop)

#ifdef QUIC_CLOG
#include "cert_capi_openssl.c.clog.h"
#endif

#include <wincrypt.h>
#include "msquic.h"

#define CXPLAT_CERT_CREATION_EVENT_NAME                 L"MsQuicCertEvent"
#define CXPLAT_CERT_CREATION_EVENT_WAIT                 10000
#define CXPLAT_CERTIFICATE_TEST_FRIENDLY_NAME           L"MsQuicTestCert2"
#define CXPLAT_CERTIFICATE_TEST_CLIENT_FRIENDLY_NAME    L"MsQuicTestClientCert"
#define CXPLAT_KEY_CONTAINER_NAME                       L"MsQuicSelfSignKey2"
#define CXPLAT_KEY_SIZE                                 2048

#define CXPLAT_TEST_CERT_VALID_SERVER_FRIENDLY_NAME     L"MsQuicTestServer"
#define CXPLAT_TEST_CERT_VALID_CLIENT_FRIENDLY_NAME     L"MsQuicTestClient"
#define CXPLAT_TEST_CERT_EXPIRED_SERVER_FRIENDLY_NAME   L"MsQuicTestExpiredServer"
#define CXPLAT_TEST_CERT_EXPIRED_CLIENT_FRIENDLY_NAME   L"MsQuicTestExpiredClient"
#define CXPLAT_TEST_CERT_VALID_SERVER_SUBJECT_NAME      "MsQuicTestServer"
#define CXPLAT_TEST_CERT_VALID_CLIENT_SUBJECT_NAME      "MsQuicTestClient"
#define CXPLAT_TEST_CERT_EXPIRED_SERVER_SUBJECT_NAME    "MsQuicTestExpiredServer"
#define CXPLAT_TEST_CERT_EXPIRED_CLIENT_SUBJECT_NAME    "MsQuicTestExpiredClient"

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
    PCCERT_CONTEXT CertContext = NULL;
    unsigned char* OpenSSLCertBuffer = NULL;
    int OpenSSLCertLength = 0;

    OpenSSLCertLength = i2d_X509(X509Cert, &OpenSSLCertBuffer);
    if (OpenSSLCertLength <= 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "i2d_X509 failed");
        goto Exit;
    }

    CertContext =
        (PCCERT_CONTEXT)
            CertCreateContext(
                CERT_STORE_CERTIFICATE_CONTEXT,
                X509_ASN_ENCODING,
                OpenSSLCertBuffer,
                OpenSSLCertLength,
                CERT_CREATE_CONTEXT_NOCOPY_FLAG,
                NULL);
    if (CertContext == NULL) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "CertGetCertificateChain failed");
        goto Exit;
    }

    uint32_t CertFlags = 0;
    if (CredFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_END_CERT) {
        CertFlags |= CERT_CHAIN_REVOCATION_CHECK_END_CERT;
    }
    if (CredFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN) {
        CertFlags |= CERT_CHAIN_REVOCATION_CHECK_CHAIN;
    }
    if (CredFlags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT) {
        CertFlags |= CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
    }

    Result =
        CxPlatCertValidateChain(
            CertContext,
            SNI,
            CertFlags,
            CredFlags,
            PlatformVerificationError);

Exit:

    if (CertContext != NULL) {
        CertFreeCertificateContext(CertContext);
    }

    if (OpenSSLCertBuffer != NULL) {
        OPENSSL_free(OpenSSLCertBuffer);
    }

    return Result;
}

QUIC_STATUS
CxPlatTlsExtractPrivateKey(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _In_z_ const uint8_t* Password,
    _Out_ uint8_t** PfxBytes,
    _Out_ uint32_t* PfxSize
    )
{
    QUIC_CERTIFICATE* Cert = NULL;
    HCERTSTORE TempCertStore = NULL;
    CRYPT_DATA_BLOB PfxDataBlob = {0, NULL};
    NCRYPT_KEY_HANDLE KeyHandle = 0;
    PCCERT_CONTEXT CertCtx = NULL;
    DWORD ExportPolicyProperty = 0;
    DWORD ExportPolicyLength = 0;
    QUIC_STATUS Status;

    if (QUIC_FAILED(
        Status =
            CxPlatCertCreate(CredConfig, &Cert))) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CxPlatCertCreate");
        goto Exit;
    }

    CertCtx = (PCCERT_CONTEXT)Cert;

    //
    // TODO: support CSP keys in addition to CNG keys.
    //

    KeyHandle = (NCRYPT_KEY_HANDLE)CxPlatCertGetPrivateKey(Cert);
    if (KeyHandle == 0) {
        Status = QUIC_STATUS_INTERNAL_ERROR;
        goto Exit;
    }

    if (FAILED(Status =
        NCryptGetProperty(
            KeyHandle,
            NCRYPT_EXPORT_POLICY_PROPERTY,
            (PBYTE)&ExportPolicyProperty,
            sizeof(ExportPolicyProperty),
            &ExportPolicyLength, 0))) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "NCryptGetProperty failed");
        goto Exit;
    }

    if ((ExportPolicyProperty & NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG) == 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Requested certificate does not support exporting. An exportable certificate is required");
        //
        // This probably should be a specific error.
        //
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    TempCertStore =
        CertOpenStore(
            CERT_STORE_PROV_MEMORY,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_STORE_ENUM_ARCHIVED_FLAG,
            NULL);

    if (NULL == TempCertStore){
        Status = HRESULT_FROM_WIN32(GetLastError());
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CertOpenStore failed");
        goto Exit;
    }

    if (!CertAddCertificateContextToStore(
            TempCertStore,
            CertCtx,
            CERT_STORE_ADD_REPLACE_EXISTING,
            NULL)) {
        Status = HRESULT_FROM_WIN32(GetLastError());
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CertAddCertificateContextToStore failed");
        goto Exit;
    }

    //
    // TODO: Export certificate chain, support PBES2
    //
    PKCS12_PBES2_EXPORT_PARAMS Pbes2ExportParams = {0};
    Pbes2ExportParams.dwSize = sizeof(PKCS12_PBES2_EXPORT_PARAMS);
    Pbes2ExportParams.pwszPbes2Alg = PKCS12_PBES2_ALG_AES256_SHA256;
    DWORD Flags = EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY | PKCS12_EXPORT_PBES2_PARAMS;

    if (!PFXExportCertStoreEx(
            TempCertStore,
            &PfxDataBlob,
            (LPCWSTR)Password,
            (void*)&Pbes2ExportParams,
            Flags)) {
        Status = HRESULT_FROM_WIN32(GetLastError());
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "PFXExportCertStoreEx get size failed");
        goto Exit;
    }

    PfxDataBlob.pbData = CXPLAT_ALLOC_NONPAGED(PfxDataBlob.cbData, QUIC_POOL_TLS_PFX);

    if (PfxDataBlob.pbData == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "PFX data",
            PfxDataBlob.cbData);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    if (!PFXExportCertStoreEx(
            TempCertStore,
            &PfxDataBlob,
            (LPCWSTR)Password,
            (void*)&Pbes2ExportParams,
            Flags)) {
        Status = HRESULT_FROM_WIN32(GetLastError());
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "PFXExportCertStoreEx get size failed");
        goto Exit;
    }

    *PfxBytes = PfxDataBlob.pbData;
    *PfxSize = PfxDataBlob.cbData;
    PfxDataBlob.pbData = NULL;

    Status = QUIC_STATUS_SUCCESS;

Exit:
    if (PfxDataBlob.pbData != NULL) {
        CXPLAT_FREE(PfxDataBlob.pbData, QUIC_POOL_TLS_PFX);
    }

    if (KeyHandle != 0) {
        CxPlatCertDeletePrivateKey((void*)KeyHandle);
    }

    if (Cert != NULL && CredConfig->Type != QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT) {
        CxPlatCertFree(Cert);
    }

    if (TempCertStore != NULL) {
        CertCloseStore(TempCertStore, 0);
    }

    return Status;
}

_Success_(return != NULL)
PCCERT_CONTEXT
FindCertificate(
    _In_ HCERTSTORE CertStore,
    _In_ BOOLEAN IncludeInvalid,
    _In_z_ const wchar_t* SearchFriendlyName,
    _Out_writes_all_(20) uint8_t* CertHash
    );

_Success_(return == TRUE)
BOOLEAN
CxPlatGetTestCertificateWindows(
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
    _When_(CredType == QUIC_CREDENTIAL_TYPE_NONE, _Out_z_bytecap_(100))
    _When_(CredType != QUIC_CREDENTIAL_TYPE_NONE, _Reserved_)
        char Principal[100]
    )
{
    BOOLEAN Success = FALSE;
    PCCERT_CONTEXT Cert = NULL;
    const wchar_t* FriendlyName = NULL;
    const char* SubjectName = NULL;

    switch (Type) {
    case CXPLAT_TEST_CERT_VALID_SERVER:
        FriendlyName = CXPLAT_TEST_CERT_VALID_SERVER_FRIENDLY_NAME;
        SubjectName = CXPLAT_TEST_CERT_VALID_SERVER_SUBJECT_NAME;
        break;
    case CXPLAT_TEST_CERT_VALID_CLIENT:
        FriendlyName = CXPLAT_TEST_CERT_VALID_CLIENT_FRIENDLY_NAME;
        SubjectName = CXPLAT_TEST_CERT_VALID_CLIENT_SUBJECT_NAME;
        break;
    case CXPLAT_TEST_CERT_EXPIRED_SERVER:
        FriendlyName = CXPLAT_TEST_CERT_EXPIRED_SERVER_FRIENDLY_NAME;
        SubjectName = CXPLAT_TEST_CERT_EXPIRED_SERVER_SUBJECT_NAME;
        break;
    case CXPLAT_TEST_CERT_EXPIRED_CLIENT:
        FriendlyName = CXPLAT_TEST_CERT_EXPIRED_CLIENT_FRIENDLY_NAME;
        SubjectName = CXPLAT_TEST_CERT_EXPIRED_CLIENT_SUBJECT_NAME;
        break;
    default:
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Type,
            "Unsupported Type passed to CxPlatGetTestCertificate");
        return FALSE;
    }

    switch (CredType) {
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH:
        if (CertHash == NULL) {
            QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            (unsigned int)QUIC_STATUS_INVALID_PARAMETER,
            "NULL CertHash passed to CxPlatGetTestCertificate");
            return FALSE;
        }
        break;
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE:
        if (CertHashStore == NULL) {
            QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            (unsigned int)QUIC_STATUS_INVALID_PARAMETER,
            "NULL CertHashStore passed to CxPlatGetTestCertificate");
            return FALSE;
        }
        break;
    case QUIC_CREDENTIAL_TYPE_NONE:
        if (Principal == NULL) {
            QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            (unsigned int)QUIC_STATUS_INVALID_PARAMETER,
            "NULL Principal passed to CxPlatGetTestCertificate");
            return FALSE;
        }
        break;
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT:
        break;
    default:
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            CredType,
            "Unsupported CredType passed to CxPlatGetTestCertificate");
        return FALSE;
    }

    CxPlatZeroMemory(Params, sizeof(*Params));

    HCERTSTORE CertStore =
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_A,
            0,
            0,
            StoreType == CXPLAT_SELF_SIGN_CERT_USER ?
                CERT_SYSTEM_STORE_CURRENT_USER :
                CERT_SYSTEM_STORE_LOCAL_MACHINE,
            "MY");
    if (CertStore == NULL) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "CertOpenStore failed");
        goto Done;
    }
    uint8_t CertHashBytes[20];

    Cert = FindCertificate(
        CertStore,
        TRUE,
        FriendlyName,
        CertHashBytes);

    if (Cert == NULL) {
        goto Done;
    }

    switch (CredType) {
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH:
        Params->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
        Params->CertificateHash = CertHash;
        CxPlatCopyMemory(CertHash->ShaHash, CertHashBytes, sizeof(CertHash->ShaHash));
        break;
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE:
        Params->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE;
        Params->CertificateHashStore = CertHashStore;
        CxPlatCopyMemory(CertHashStore->ShaHash, CertHashBytes, sizeof(CertHashStore->ShaHash));
        strncpy_s(CertHashStore->StoreName, sizeof(CertHashStore->StoreName), "MY", sizeof("MY"));
        CertHashStore->Flags =
            StoreType == CXPLAT_SELF_SIGN_CERT_USER ?
                QUIC_CERTIFICATE_HASH_STORE_FLAG_NONE :
                QUIC_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE;
        break;
    case QUIC_CREDENTIAL_TYPE_NONE:
        //
        // Assume Principal in use here
        //
        Params->Type = QUIC_CREDENTIAL_TYPE_NONE;
        Params->Principal = Principal;
        strncpy_s(Principal, 100, SubjectName, 100);
        break;
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT:
        Params->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT;
        Params->CertificateContext = (QUIC_CERTIFICATE*)Cert;
        Cert = NULL;
        break;
    }
    Success = TRUE;
Done:
    if (Cert != NULL) {
        CertFreeCertificateContext(Cert);
    }
    if (CertStore != NULL) {
        CertCloseStore(CertStore, 0);
    }

    return Success;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatFreeTestCertWindows(
    _In_ QUIC_CREDENTIAL_CONFIG* Params
    )
{
    if (Params->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT) {
        CertFreeCertificateContext((PCCERT_CONTEXT)Params->CertificateContext);
    }
}
