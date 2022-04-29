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
#ifdef QUIC_CLOG
#include "cert_capi.c.clog.h"
#endif

#pragma warning(push)
#pragma warning(disable:6553) // Annotation does not apply to value type.
#include <wincrypt.h>
#pragma warning(pop)
#include "msquic.h"

#ifdef QUIC_RESTRICTED_BUILD
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#endif

typedef union CXPLAT_SIGN_PADDING {
    BCRYPT_PKCS1_PADDING_INFO Pkcs1;
    BCRYPT_PSS_PADDING_INFO Pss;
} CXPLAT_SIGN_PADDING;

//
// Map the TLS signature to the OID value expected in a certificate.
//
static
_Success_(return != NULL)
_Null_terminated_ const char *
OIDFromTLS(
    UINT16 alg
    )
{
    switch (alg) {
    // RSASSA-PKCS1-v1_5
    case 0x0401: return szOID_RSA_SHA256RSA; // rsa_pkcs1_sha256
    case 0x0501: return szOID_RSA_SHA384RSA; // rsa_pkcs1_sha384
    case 0x0601: return szOID_RSA_SHA512RSA; // rsa_pkcs1_sha512

    // ECDSA
    case 0x0403: return szOID_ECDSA_SHA256; // ecdsa_secp256r1_sha256
    case 0x0503: return szOID_ECDSA_SHA384; // ecdsa_secp384r1_sha384
    case 0x0603: return szOID_ECDSA_SHA512; // ecdsa_secp384r1_sha512

    // RSASSA-PSS
    case 0x0804: return szOID_RSA_SHA256RSA; // rsa_pss_sha256
    case 0x0805: return szOID_RSA_SHA384RSA; // rsa_pss_sha384
    case 0x0806: return szOID_RSA_SHA512RSA; // rsa_pss_sha512

    // EdDSA
    case 0x0807: return NULL; // ed25519 supported by bcrypt: BCRYPT_ECC_CURVE_25519
    case 0x0808: return NULL; // ed448   not supported by Windows

    // Legacy
    case 0x0201: return szOID_RSA_SHA1RSA; // rsa_pkcs1_sha1
    case 0x0203: return NULL; // ecdsa_sha1 supported by bcyprpt: BCRYPT_ECDSA_ALGORITHM

    default:     return NULL; // Unknown/unsupported value
    }
}

//
// Map the TLS signature to the algorithm ID value expected in a certificate.
// High byte is the TLS HashAlgorithm:
//  none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5), sha512(6)
//

static
_Success_(return != NULL)
_Null_terminated_ const wchar_t *
SignAlgFromTLS(
    UINT16 alg
    )
{
    switch (alg) {
    // RSASSA-PKCS1-v1_5
    case 0x0401: return BCRYPT_RSA_ALGORITHM; // rsa_pkcs1_sha256
    case 0x0501: return BCRYPT_RSA_ALGORITHM; // rsa_pkcs1_sha384
    case 0x0601: return BCRYPT_RSA_ALGORITHM; // rsa_pkcs1_sha512

    // ECDSA
    case 0x0403: return BCRYPT_ECDSA_P256_ALGORITHM; // ecdsa_secp256r1_sha256
    case 0x0503: return BCRYPT_ECDSA_P384_ALGORITHM; // ecdsa_secp384r1_sha384
    case 0x0603: return BCRYPT_ECDSA_P384_ALGORITHM; // ecdsa_secp384r1_sha512

    // RSASSA-PSS
    case 0x0804: return BCRYPT_RSA_ALGORITHM; // rsa_pss_sha256
    case 0x0805: return BCRYPT_RSA_ALGORITHM; // rsa_pss_sha384
    case 0x0806: return BCRYPT_RSA_ALGORITHM; // rsa_pss_sha512

    // EdDSA
    case 0x0807: return NULL; // ed25519 supported by bcrypt: BCRYPT_ECC_CURVE_25519. not available for EcDSA
    case 0x0808: return NULL; // ed448   not supported by Windows

    // Legacy
    case 0x0201: return BCRYPT_RSA_ALGORITHM; // rsa_pkcs1_sha1
    case 0x0203: return NULL; // ecdsa_sha1 supported by bcyprpt: BCRYPT_ECDSA_ALGORITHM, what is the key size?

    default:
        return NULL;
    }
}

static
_Success_(return != NULL)
_Null_terminated_ const wchar_t *
HashAlgFromTLS(
    UINT16 alg
    )
{
    switch (alg) {
    // RSASSA-PKCS1-v1_5
    case 0x0401: return BCRYPT_SHA256_ALGORITHM; // rsa_pkcs1_sha256
    case 0x0501: return BCRYPT_SHA384_ALGORITHM; // rsa_pkcs1_sha384
    case 0x0601: return BCRYPT_SHA512_ALGORITHM; // rsa_pkcs1_sha512

    // ECDSA
    case 0x0403: return BCRYPT_SHA256_ALGORITHM; // ecdsa_secp256r1_sha256
    case 0x0503: return BCRYPT_SHA384_ALGORITHM; // ecdsa_secp384r1_sha384
    case 0x0603: return BCRYPT_SHA512_ALGORITHM; // ecdsa_secp384r1_sha512

    // RSASSA-PSS
    case 0x0804: return BCRYPT_SHA256_ALGORITHM; // rsa_pss_sha256
    case 0x0805: return BCRYPT_SHA384_ALGORITHM; // rsa_pss_sha384
    case 0x0806: return BCRYPT_SHA512_ALGORITHM; // rsa_pss_sha512

    // EdDSA
    case 0x0807: return NULL; // ed25519 supported by bcrypt: BCRYPT_ECC_CURVE_25519
    case 0x0808: return NULL; // ed448   not supported by Windows

    // Legacy
    case 0x0201: return BCRYPT_SHA1_ALGORITHM; // rsa_pkcs1_sha1
    case 0x0203: return BCRYPT_SHA1_ALGORITHM; // ecdsa_sha1 supported by bcyprpt: BCRYPT_ECDSA_ALGORITHM

    default:
        return NULL;
    }
}

static
_Success_(return != NULL)
BCRYPT_ALG_HANDLE
HashHandleFromTLS(
    UINT16 alg
)
{
    switch (alg) {
    // RSASSA-PKCS1-v1_5
    case 0x0401: return BCRYPT_SHA256_ALG_HANDLE; // rsa_pkcs1_sha256
    case 0x0501: return BCRYPT_SHA384_ALG_HANDLE; // rsa_pkcs1_sha384
    case 0x0601: return BCRYPT_SHA512_ALG_HANDLE; // rsa_pkcs1_sha512

    // ECDSA
    case 0x0403: return BCRYPT_SHA256_ALG_HANDLE; // ecdsa_secp256r1_sha256
    case 0x0503: return BCRYPT_SHA384_ALG_HANDLE; // ecdsa_secp384r1_sha384
    case 0x0603: return BCRYPT_SHA512_ALG_HANDLE; // ecdsa_secp384r1_sha512

    // RSASSA-PSS
    case 0x0804: return BCRYPT_SHA256_ALG_HANDLE; // rsa_pss_sha256
    case 0x0805: return BCRYPT_SHA384_ALG_HANDLE; // rsa_pss_sha384
    case 0x0806: return BCRYPT_SHA512_ALG_HANDLE; // rsa_pss_sha512

    // EdDSA
    case 0x0807: return NULL; // ed25519 supported by bcrypt: BCRYPT_ECC_CURVE_25519
    case 0x0808: return NULL; // ed448   not supported by Windows

    // Legacy
    case 0x0201: return BCRYPT_SHA1_ALG_HANDLE; // rsa_pkcs1_sha1
    case 0x0203: return BCRYPT_SHA1_ALG_HANDLE; // ecdsa_sha1 supported by bcyprpt: BCRYPT_ECDSA_ALGORITHM

    default:
        return NULL;
    }
}

#define CXPLAT_CERTIFICATE_MAX_HASH_SIZE 64

static
_Success_(return != 0)
ULONG
HashSizeFromTLS(
    UINT16 alg
)
{
    switch (alg) {
    // RSASSA-PKCS1-v1_5
    case 0x0401: return 32; // rsa_pkcs1_sha256
    case 0x0501: return 48; // rsa_pkcs1_sha384
    case 0x0601: return 64; // rsa_pkcs1_sha512

    // ECDSA
    case 0x0403: return 32; // ecdsa_secp256r1_sha256
    case 0x0503: return 48; // ecdsa_secp384r1_sha384
    case 0x0603: return 64; // ecdsa_secp384r1_sha512

    // RSASSA-PSS
    case 0x0804: return 32; // rsa_pss_sha256
    case 0x0805: return 48; // rsa_pss_sha384
    case 0x0806: return 64; // rsa_pss_sha512

    // EdDSA
    case 0x0807: return 0; // ed25519 supported by bcrypt: BCRYPT_ECC_CURVE_25519
    case 0x0808: return 0; // ed448   not supported by Windows

    // Legacy
    case 0x0201: return 20; // rsa_pkcs1_sha1
    case 0x0203: return 20; // ecdsa_sha1 supported by bcrypt: BCRYPT_ECDSA_ALGORITHM

    default:
        return 0;
    }
}

static
_Success_(return != ~0u)
DWORD
PaddingTypeFromTLS(
    UINT16 alg
    )
{
    switch (alg) {
    // RSASSA-PKCS1-v1_5
    case 0x0401: return BCRYPT_PAD_PKCS1; // rsa_pkcs1_sha256
    case 0x0501: return BCRYPT_PAD_PKCS1; // rsa_pkcs1_sha384
    case 0x0601: return BCRYPT_PAD_PKCS1; // rsa_pkcs1_sha512

    // ECDSA
    case 0x0403: return BCRYPT_PAD_NONE; // ecdsa_secp256r1_sha256
    case 0x0503: return BCRYPT_PAD_NONE; // ecdsa_secp384r1_sha384
    case 0x0603: return BCRYPT_PAD_NONE; // ecdsa_secp384r1_sha512

    // RSASSA-PSS
    case 0x0804: return BCRYPT_PAD_PSS; // rsa_pss_sha256
    case 0x0805: return BCRYPT_PAD_PSS; // rsa_pss_sha384
    case 0x0806: return BCRYPT_PAD_PSS; // rsa_pss_sha512

    // EdDSA
    case 0x0807: return ~0u; // ed25519 supported by bcrypt: BCRYPT_ECC_CURVE_25519
    case 0x0808: return ~0u; // ed448   not supported by Windows

    // Legacy
    case 0x0201: return BCRYPT_PAD_PKCS1; // rsa_pkcs1_sha1
    case 0x0203: return BCRYPT_PAD_PKCS1; // ecdsa_sha1 supported by bcyprpt: BCRYPT_ECDSA_ALGORITHM

    default:
        return ~0u;
    }
}

static
void
PopulatePaddingParams(
    _Inout_ CXPLAT_SIGN_PADDING* Padding,
    _In_ DWORD PaddingType,
    _In_z_ PCWSTR HashAlg,
    _In_ DWORD SaltSize
    )
{
    if (PaddingType == BCRYPT_PAD_PKCS1) {
        Padding->Pkcs1.pszAlgId = HashAlg;
    } else if (PaddingType == BCRYPT_PAD_PSS) {
        Padding->Pss.pszAlgId = HashAlg;
        Padding->Pss.cbSalt = SaltSize;
    } else {
        CXPLAT_DBG_ASSERT(FALSE);
    }
}

BOOLEAN
CxPlatCertMatchHash(
    _In_ PCCERT_CONTEXT CertContext,
    _In_reads_(20) const UINT8 InputCertHash[20]
    )
{
    UINT8 CertHash[20];
    DWORD CertHashLength = sizeof(CertHash);
    if (!CertGetCertificateContextProperty(
            CertContext,
            CERT_HASH_PROP_ID,
            CertHash,
            &CertHashLength)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "Get CERT_HASH_PROP_ID failed");
        return FALSE;
    }
    if (CertHashLength != sizeof(CertHash)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            CertHashLength,
            "CERT_HASH_PROP_ID incorrect size");
        return FALSE;
    }
    return memcmp(InputCertHash, CertHash, CertHashLength) == 0;
}

BOOLEAN
CxPlatCertMatchPrincipal(
    _In_ PCCERT_CONTEXT CertContext,
    _In_z_ const char* Principal
    )
{
    BOOLEAN MatchFound = FALSE;
    char *CertificateNames = NULL;

    DWORD Length =
        CertGetNameStringA(
            CertContext,
            CERT_NAME_DNS_TYPE,
            CERT_NAME_SEARCH_ALL_NAMES_FLAG,
            NULL,
            NULL,
            0);

    if (Length == 0) {
        goto Exit;
    }

    CertificateNames = CXPLAT_ALLOC_PAGED(Length, QUIC_POOL_PLATFORM_TMP_ALLOC);
    if (CertificateNames == NULL) {
        goto Exit;
    }

    size_t PrincipalLength = strlen(Principal);

    Length =
        CertGetNameStringA(
            CertContext,
            CERT_NAME_DNS_TYPE,
            CERT_NAME_SEARCH_ALL_NAMES_FLAG,
            NULL,
            CertificateNames,
            Length);

    for (char *CertificateName = CertificateNames;
        *CertificateName;
        CertificateName += strlen(CertificateName) + 1) {

        if (_strnicmp(CertificateName, Principal, PrincipalLength) == 0) {
            MatchFound = TRUE;
            break;
        }
    }

Exit:

    if (CertificateNames != NULL) {
        CXPLAT_FREE(CertificateNames, QUIC_POOL_PLATFORM_TMP_ALLOC);
    }

    return MatchFound;
}

PCCERT_CONTEXT
CxPlatCertStoreFind(
    _In_ HCERTSTORE CertStore,
    _In_reads_opt_(20) const UINT8 CertHash[20],
    _In_opt_z_ const char* Principal
    )
{
    PCSTR OID_SERVER_AUTH = szOID_PKIX_KP_SERVER_AUTH;
    PCSTR OID_CLIENT_AUTH = szOID_PKIX_KP_CLIENT_AUTH;
    CERT_ENHKEY_USAGE Usage;
    Usage.cUsageIdentifier = 1;
    Usage.rgpszUsageIdentifier = (LPSTR*)&OID_SERVER_AUTH;

    for (int i = 0; i < 2; ++i) {
        if (i == 0) {
            Usage.rgpszUsageIdentifier = (LPSTR*)&OID_SERVER_AUTH;
        } else if (i == 1) {
            Usage.rgpszUsageIdentifier = (LPSTR*)&OID_CLIENT_AUTH;
        }

        PCCERT_CONTEXT CertCtx;
        for (PCCERT_CONTEXT PrevCertCtx = NULL;
            (CertCtx =
                CertFindCertificateInStore(
                    CertStore,
                    X509_ASN_ENCODING,
                    CERT_FIND_OPTIONAL_ENHKEY_USAGE_FLAG, // FindFlags
                    CERT_FIND_ENHKEY_USAGE,
                    &Usage,
                    PrevCertCtx)) != NULL;
            PrevCertCtx = CertCtx) {

            if (CertHash != NULL && !CxPlatCertMatchHash(CertCtx, CertHash)) {
                continue;
            }

            if (Principal != NULL && !CxPlatCertMatchPrincipal(CertCtx, Principal)) {
                continue;
            }

            return CertCtx;
        }
    }

    return NULL;
}

QUIC_STATUS
CxPlatCertLookupHash(
    _In_opt_ const QUIC_CERTIFICATE_HASH* CertHash,
    _In_opt_z_ const char* Principal,
    _Out_ QUIC_CERTIFICATE** NewCertificate
    )
{
    QUIC_STATUS Status;
    HCERTSTORE CertStore;

    CXPLAT_DBG_ASSERT(CertHash != NULL || Principal != NULL);

    CertStore =
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_A,
            0,
            0,
            CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG | CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG,
            "MY");
    if (CertStore == NULL) {
        Status = HRESULT_FROM_WIN32(GetLastError());
        goto Exit;
    }

    PCCERT_CONTEXT CertCtx =
        CxPlatCertStoreFind(
            CertStore,
            CertHash == NULL ? NULL : CertHash->ShaHash,
            Principal);
    if (CertCtx == NULL) {
        Status = QUIC_STATUS_NOT_FOUND;
        goto Exit;
    }

    Status = QUIC_STATUS_SUCCESS;
    *NewCertificate = (QUIC_CERTIFICATE*)CertCtx;

Exit:

    if (CertStore != NULL) {
        CertCloseStore(CertStore, 0);
    }

    return Status;
}

QUIC_STATUS
CxPlatCertLookupHashStore(
    _In_ const QUIC_CERTIFICATE_HASH_STORE* CertHashStore,
    _In_opt_z_ const char* Principal,
    _Out_ QUIC_CERTIFICATE** NewCertificate
    )
{
    QUIC_STATUS Status;
    HCERTSTORE CertStore;
    uint32_t Flags = CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG | CERT_STORE_READONLY_FLAG;
    if (CertHashStore->Flags & QUIC_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE) {
        Flags |= CERT_SYSTEM_STORE_LOCAL_MACHINE;
    } else {
        Flags |= CERT_SYSTEM_STORE_CURRENT_USER;
    }

    CertStore =
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_A,
            0,
            0,
            Flags,
            CertHashStore->StoreName);
    if (CertStore == NULL) {
        Status = HRESULT_FROM_WIN32(GetLastError());
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CertOpenStore failed");
        goto Exit;
    }

    PCCERT_CONTEXT CertCtx =
        CxPlatCertStoreFind(
            CertStore,
            CertHashStore->ShaHash,
            Principal);
    if (CertCtx == NULL) {
        Status = QUIC_STATUS_NOT_FOUND;
        goto Exit;
    }

    Status = QUIC_STATUS_SUCCESS;
    *NewCertificate = (QUIC_CERTIFICATE*)CertCtx;

Exit:

    if (CertStore != NULL) {
        CertCloseStore(CertStore, 0);
    }

    return Status;
}

QUIC_STATUS
CxPlatCertCreate(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _Out_ QUIC_CERTIFICATE** NewCertificate
    )
{
    QUIC_STATUS Status;

    if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH) {
        if (CredConfig->CertificateHash == NULL && CredConfig->Principal == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status =
                CxPlatCertLookupHash(
                    CredConfig->CertificateHash,
                    CredConfig->Principal,
                    NewCertificate);
        }

    } else if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE) {
        if (CredConfig->CertificateHashStore == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            Status =
                CxPlatCertLookupHashStore(
                    CredConfig->CertificateHashStore,
                    CredConfig->Principal,
                    NewCertificate);
        }

    } else if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT) {
        if (CredConfig->CertificateContext == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
        } else {
            *NewCertificate = (QUIC_CERTIFICATE*)CredConfig->CertificateContext;
            Status = QUIC_STATUS_SUCCESS;
        }

    } else {
        Status = QUIC_STATUS_INVALID_PARAMETER;
    }

    return Status;
}

void
CxPlatCertFree(
    _In_ QUIC_CERTIFICATE* Certificate
    )
{
    (void)CertFreeCertificateContext((PCERT_CONTEXT)Certificate);
}

_Success_(return != FALSE)
BOOLEAN
CxPlatCertSelect(
    _In_opt_ QUIC_CERTIFICATE* Certificate,
    _In_reads_(SignatureAlgorithmsLength)
        const uint16_t *SignatureAlgorithms,
    _In_ size_t SignatureAlgorithmsLength,
    _Out_ uint16_t *SelectedSignature
    )
{
    //
    // High byte of SignatureAlgorithms[] is the TLS HashAlgorithm:
    //  none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5), sha512(6)
    // Low byte of SignatureAlgorithms[] is the TLS SignatureAlgorithm:
    //  anonymous(0), rsa(1), dsa(2), ecdsa(3)
    //

    PCCERT_CONTEXT CertCtx = (PCCERT_CONTEXT)Certificate;

    if (CertCtx == NULL) {
        *SelectedSignature = SignatureAlgorithms[0];
        return TRUE;
    }

    BOOLEAN MatchFound = FALSE;
    for (size_t i = 0; i < SignatureAlgorithmsLength; ++i) {
        _Null_terminated_ const char* oid = OIDFromTLS(SignatureAlgorithms[i]);
        if (oid != NULL &&
            strcmp(CertCtx->pCertInfo->SignatureAlgorithm.pszObjId, oid) == 0) {
            *SelectedSignature = SignatureAlgorithms[i];
            MatchFound = TRUE;
            break;
        }
    }

    return MatchFound;
}

_Success_(return != NULL)
QUIC_CERTIFICATE*
CxPlatCertParseChain(
    _In_ size_t ChainBufferLength,
    _In_reads_(ChainBufferLength) const BYTE *ChainBuffer
    )
{
    PCCERT_CONTEXT LeafCertCtx = NULL;

    HCERTSTORE TempStore =
        CertOpenStore(
            CERT_STORE_PROV_MEMORY,
            0,
            0,
            CERT_STORE_DEFER_CLOSE_UNTIL_LAST_FREE_FLAG,
            0);
    if (TempStore == NULL) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "CertOpenStore failed");
        goto Error;
    }

    DWORD CertNumber;
    for (CertNumber = 0; ChainBufferLength >= 3; ++CertNumber) {

        DWORD CertLength =
            ((DWORD)(BYTE)ChainBuffer[0]) << 16 |
            ((DWORD)(BYTE)ChainBuffer[1]) << 8 |
            ((DWORD)(BYTE)ChainBuffer[2]);
        ChainBufferLength -= 3;
        ChainBuffer += 3;

        PCCERT_CONTEXT CertCtx = NULL;
        if (!CertAddEncodedCertificateToStore(
                TempStore,
                X509_ASN_ENCODING,
                ChainBuffer,
                CertLength,
                CERT_STORE_ADD_USE_EXISTING,
                &CertCtx)) {
            QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "CertAddEncodedCertificateToStore failed");
            goto Error;
        }

        ChainBufferLength -= CertLength;
        ChainBuffer += CertLength;

        if (LeafCertCtx == NULL) {
            LeafCertCtx = CertCtx;
        } else {
            CertFreeCertificateContext(CertCtx);
        }
    }

    if (ChainBufferLength != 0) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Not all cert bytes were processed");
        goto Error;
    }

    QuicTraceLogVerbose(
        CertCapiParsedChain,
        "[cert] Successfully parsed chain of %u certificate(s)",
        CertNumber);

    goto Exit;

Error:

    if (LeafCertCtx != NULL) {
        CertFreeCertificateContext(LeafCertCtx);
        LeafCertCtx = NULL;
    }

Exit:

    if (TempStore != NULL) {
        CertCloseStore(TempStore, 0);
    }

    return (QUIC_CERTIFICATE*)LeafCertCtx;
}

_Success_(return != 0)
QUIC_STATUS
CxPlatGetPortableCertificate(
    _In_ QUIC_CERTIFICATE* Certificate,
    _Out_ QUIC_PORTABLE_CERTIFICATE* PortableCertificate
    )
{
    QUIC_STATUS Status;
    DWORD LastError;
    CERT_CHAIN_PARA ChainPara;
    CERT_ENHKEY_USAGE EnhKeyUsage;
    CERT_USAGE_MATCH CertUsage;
    PCCERT_CHAIN_CONTEXT ChainContext;
    PCCERT_CONTEXT CertCtx = (PCCERT_CONTEXT)Certificate;
    PCCERT_CONTEXT DuplicateCtx;
    HCERTSTORE TempCertStore = NULL;
    CERT_BLOB Blob = {0};

    PortableCertificate->PlatformCertificate = NULL;

    EnhKeyUsage.cUsageIdentifier = 0;
    EnhKeyUsage.rgpszUsageIdentifier = NULL;
    CertUsage.dwType = USAGE_MATCH_TYPE_AND;
    CertUsage.Usage = EnhKeyUsage;
    ChainPara.cbSize = sizeof(CERT_CHAIN_PARA);
    ChainPara.RequestedUsage = CertUsage;

    if (!CertGetCertificateChain(
            NULL,  // default chain engine
            CertCtx,
            NULL,
            NULL,
            &ChainPara,
            0,
            NULL,
            &ChainContext)) {
        LastError = GetLastError();
        Status = LastError;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            LastError,
            "CertGetCertificateChain failed");
        goto Exit;
    }

    TempCertStore =
        CertOpenStore(
            CERT_STORE_PROV_MEMORY,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_STORE_ENUM_ARCHIVED_FLAG,
            NULL);
    if (NULL == TempCertStore) {
        LastError = GetLastError();
        Status = LastError;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            LastError,
            "CertOpenStore failed");
        goto Exit;
    }

    for (DWORD i = 0; i < ChainContext->cChain; ++i) {
        PCERT_SIMPLE_CHAIN SimpleChain = ChainContext->rgpChain[i];
        for (DWORD j = 0; j < SimpleChain->cElement; ++j) {
            PCERT_CHAIN_ELEMENT Element = SimpleChain->rgpElement[j];
            PCCERT_CONTEXT EncodedCert = Element->pCertContext;
            if (!CertAddCertificateLinkToStore(
                    TempCertStore,
                    EncodedCert,
                    CERT_STORE_ADD_ALWAYS,
                    NULL)) {
                LastError = GetLastError();
                Status = LastError;
                QuicTraceEvent(
                    LibraryErrorStatus,
                    "[ lib] ERROR, %u, %s.",
                    LastError,
                    "CertAddCertificateLinkToStore failed");
                goto Exit;
            }
        }
    }

    if (!CertSaveStore(
            TempCertStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            CERT_STORE_SAVE_AS_PKCS7,
            CERT_STORE_SAVE_TO_MEMORY,
            &Blob,
            0)) {
        LastError = GetLastError();
        Status = LastError;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            LastError,
            "CertSaveStore failed");
        goto Exit;
    }

    Blob.pbData = CXPLAT_ALLOC_NONPAGED(Blob.cbData, QUIC_POOL_TLS_PFX);
    if (Blob.pbData == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "PKCS7 data",
            Blob.cbData);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Exit;
    }

    if (!CertSaveStore(
            TempCertStore,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            CERT_STORE_SAVE_AS_PKCS7,
            CERT_STORE_SAVE_TO_MEMORY,
            &Blob,
            0)) {
        LastError = GetLastError();
        Status = LastError;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            LastError,
            "CertSaveStore failed");
        goto Exit;
    }

    DuplicateCtx = CertDuplicateCertificateContext(CertCtx);
    if (DuplicateCtx == NULL) {
        LastError = GetLastError();
        Status = LastError;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            LastError,
            "CertDuplicateCertificateContext failed");
        goto Exit;
    }

    PortableCertificate->PortableChain.Length = Blob.cbData;
    PortableCertificate->PortableChain.Buffer = Blob.pbData;
    Blob.pbData = NULL;

    PortableCertificate->PortableCertificate.Length =
        DuplicateCtx->cbCertEncoded;
    PortableCertificate->PortableCertificate.Buffer =
        DuplicateCtx->pbCertEncoded;

    PortableCertificate->PlatformCertificate =
        (QUIC_CERTIFICATE*)DuplicateCtx;

    Status = QUIC_STATUS_SUCCESS;

Exit:

    if (Blob.pbData != NULL) {
        CXPLAT_FREE(Blob.pbData, QUIC_POOL_TLS_PFX);
    }

    if (TempCertStore != NULL) {
        CertCloseStore(TempCertStore, 0);
    }

    if (ChainContext != NULL) {
        CertFreeCertificateChain(ChainContext);
    }

    return Status;
}

void
CxPlatFreePortableCertificate(
    _In_ QUIC_PORTABLE_CERTIFICATE* PortableCertificate
    )
{
    if (PortableCertificate->PlatformCertificate) {
        CertFreeCertificateContext(
            (PCCERT_CONTEXT)PortableCertificate->PlatformCertificate);

        CXPLAT_FREE(
            PortableCertificate->PortableChain.Buffer,
            QUIC_POOL_TLS_PFX);
    }
}

_Success_(return != 0)
size_t
CxPlatCertFormat(
    _In_opt_ QUIC_CERTIFICATE* Certificate,
    _In_ size_t BufferLength,
    _Out_writes_to_(BufferLength, return)
        BYTE* Buffer
    )
{
    CERT_CHAIN_PARA ChainPara;
    CERT_ENHKEY_USAGE EnhKeyUsage;
    CERT_USAGE_MATCH CertUsage;
    PCCERT_CHAIN_CONTEXT ChainContext;
    DWORD CertNumber = 0;
    BYTE *Offset = Buffer;

    PCCERT_CONTEXT CertCtx = (PCCERT_CONTEXT)Certificate;

    if (CertCtx == NULL) {
        if (BufferLength < SIZEOF_CERT_CHAIN_LIST_LENGTH) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "Insufficient buffer to store the empty formatted chain");
            return 0;
        }
        //
        // Just encode list of zero cert chains.
        //
        CxPlatZeroMemory(Offset, SIZEOF_CERT_CHAIN_LIST_LENGTH);
        Offset += SIZEOF_CERT_CHAIN_LIST_LENGTH;
        goto Exit;
    }

    EnhKeyUsage.cUsageIdentifier = 0;
    EnhKeyUsage.rgpszUsageIdentifier = NULL;
    CertUsage.dwType = USAGE_MATCH_TYPE_AND;
    CertUsage.Usage = EnhKeyUsage;
    ChainPara.cbSize = sizeof(CERT_CHAIN_PARA);
    ChainPara.RequestedUsage = CertUsage;

    if (!CertGetCertificateChain(
            NULL,  // default chain engine
            CertCtx,
            NULL,
            NULL,
            &ChainPara,
            0,
            NULL,
            &ChainContext)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "CertGetCertificateChain failed");
        return 0;
    }

    for (DWORD i = 0; i < ChainContext->cChain; ++i) {
        PCERT_SIMPLE_CHAIN SimpleChain = ChainContext->rgpChain[i];
        for (DWORD j = 0; j < SimpleChain->cElement; ++j) {
            PCERT_CHAIN_ELEMENT Element = SimpleChain->rgpElement[j];
            PCCERT_CONTEXT EncodedCert = Element->pCertContext;
            if (EncodedCert->cbCertEncoded + SIZEOF_CERT_CHAIN_LIST_LENGTH > BufferLength) {
                QuicTraceEvent(
                    LibraryError,
                    "[ lib] ERROR, %s.",
                    "Insufficient buffer to store the formatted chain");
                CertFreeCertificateChain(ChainContext);
                return 0;
            }
            Offset[0] = (BYTE)(EncodedCert->cbCertEncoded >> 16);
            Offset[1] = (BYTE)(EncodedCert->cbCertEncoded >> 8);
            Offset[2] = (BYTE)EncodedCert->cbCertEncoded;
            Offset += SIZEOF_CERT_CHAIN_LIST_LENGTH;
            memcpy(Offset, EncodedCert->pbCertEncoded, EncodedCert->cbCertEncoded);
            Offset += EncodedCert->cbCertEncoded;
            BufferLength -= (SIZEOF_CERT_CHAIN_LIST_LENGTH + EncodedCert->cbCertEncoded);
            ++CertNumber;
        }
    }

    CertFreeCertificateChain(ChainContext);

Exit:

    QuicTraceLogVerbose(
        CertCapiFormattedChain,
        "[cert] Successfully formatted chain of %u certificate(s)",
        CertNumber);

    return (size_t)(Offset - Buffer);
}

_Success_(return == NO_ERROR)
DWORD
CxPlatCertVerifyCertChainPolicy(
    _In_ PCCERT_CHAIN_CONTEXT ChainContext,
    _In_opt_ PWSTR ServerName,
    _In_ uint32_t CredFlags
    )
{
    DWORD Status = NO_ERROR;

    HTTPSPolicyCallbackData HttpsPolicy;
    CERT_CHAIN_POLICY_PARA PolicyPara;
    CERT_CHAIN_POLICY_STATUS PolicyStatus;

    memset(&HttpsPolicy, 0, sizeof(HTTPSPolicyCallbackData));
    HttpsPolicy.cbStruct = sizeof(HTTPSPolicyCallbackData);
    HttpsPolicy.dwAuthType =
        (CredFlags & QUIC_CREDENTIAL_FLAG_CLIENT) ? AUTHTYPE_SERVER : AUTHTYPE_CLIENT;
    HttpsPolicy.fdwChecks = 0;
    HttpsPolicy.pwszServerName = (CredFlags & QUIC_CREDENTIAL_FLAG_CLIENT) ? ServerName : NULL;

    memset(&PolicyPara, 0, sizeof(PolicyPara));
    PolicyPara.cbSize = sizeof(PolicyPara);
    PolicyPara.pvExtraPolicyPara = &HttpsPolicy;

    memset(&PolicyStatus, 0, sizeof(PolicyStatus));
    PolicyStatus.cbSize = sizeof(PolicyStatus);

    if (!CertVerifyCertificateChainPolicy(
            CERT_CHAIN_POLICY_SSL,
            ChainContext,
            &PolicyPara,
            &PolicyStatus)) {
        Status = GetLastError();
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CertVerifyCertificateChainPolicy failed");
        goto Exit;

    } else if (PolicyStatus.dwError == CRYPT_E_NO_REVOCATION_CHECK &&
        (CredFlags & QUIC_CREDENTIAL_FLAG_IGNORE_NO_REVOCATION_CHECK)) {
        Status = NO_ERROR;
    } else if (PolicyStatus.dwError == CRYPT_E_REVOCATION_OFFLINE &&
        (CredFlags & QUIC_CREDENTIAL_FLAG_IGNORE_REVOCATION_OFFLINE)) {
        Status = NO_ERROR;
    } else if (PolicyStatus.dwError != NO_ERROR) {

        Status = PolicyStatus.dwError;
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CertVerifyCertificateChainPolicy indicated a cert error");
        goto Exit;
    }

Exit:

    QuicTraceLogInfo(
        CertCapiVerifiedChain,
        "CertVerifyChain: %S 0x%x, result=0x%x",
        ServerName,
        CredFlags,
        Status);

    return Status;
}

_Success_(return != FALSE)
BOOLEAN
CxPlatCertValidateChain(
    _In_ const QUIC_CERTIFICATE* Certificate,
    _In_opt_z_ PCSTR Host,
    _In_ uint32_t CertFlags,
    _In_ uint32_t CredFlags,
    _Out_opt_ uint32_t* ValidationError
    )
{
    BOOLEAN Result = FALSE;
    PCCERT_CHAIN_CONTEXT ChainContext = NULL;
    LPWSTR ServerName = NULL;
    DWORD Error = NO_ERROR;

    PCCERT_CONTEXT LeafCertCtx = (PCCERT_CONTEXT)Certificate;

    CERT_CHAIN_PARA ChainPara;

    static const LPSTR ServerUsageOids[] = {
        szOID_PKIX_KP_SERVER_AUTH,
        szOID_SERVER_GATED_CRYPTO,
        szOID_SGC_NETSCAPE
    };

    static const LPSTR ClientUsageOids[] =  {
        szOID_PKIX_KP_CLIENT_AUTH
    };

    if (ValidationError != NULL) {
        *ValidationError = NO_ERROR;
    }

    memset(&ChainPara, 0, sizeof(ChainPara));
    ChainPara.cbSize = sizeof(ChainPara);
    ChainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    ChainPara.RequestedUsage.Usage.cUsageIdentifier =
        (CredFlags & QUIC_CREDENTIAL_FLAG_CLIENT) ? ARRAYSIZE(ServerUsageOids) : ARRAYSIZE(ClientUsageOids);
    ChainPara.RequestedUsage.Usage.rgpszUsageIdentifier =
        (CredFlags & QUIC_CREDENTIAL_FLAG_CLIENT) ? (LPSTR*)ServerUsageOids : (LPSTR*)ClientUsageOids;

    if (!CertGetCertificateChain(
            NULL,
            LeafCertCtx,
            NULL,
            LeafCertCtx->hCertStore,
            &ChainPara,
            CertFlags,
            NULL,
            &ChainContext)) {
        Error = GetLastError();
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Error,
            "CertGetCertificateChain failed");
        goto Exit;
    }

    if (Host != NULL) {
        QUIC_STATUS Status =
            CxPlatUtf8ToWideChar(
                Host,
                QUIC_POOL_PLATFORM_TMP_ALLOC,
                &ServerName);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "Convert Host to unicode");
            goto Exit;
        }
    }

    Error =
        CxPlatCertVerifyCertChainPolicy(
            ChainContext,
            ServerName,
            CredFlags);

    Result = NO_ERROR == Error;

Exit:

    if (ChainContext != NULL) {
        CertFreeCertificateChain(ChainContext);
    }
    if (ServerName != NULL) {
        CXPLAT_FREE(ServerName, QUIC_POOL_PLATFORM_TMP_ALLOC);
    }
    if (ValidationError != NULL && !Result) {
        *ValidationError = (uint32_t)Error;
    }

    return Result;
}

_Success_(return != NULL)
void*
CxPlatCertGetPrivateKey(
    _In_ QUIC_CERTIFICATE* Certificate
    )
{
    PCCERT_CONTEXT CertCtx = (PCCERT_CONTEXT)Certificate;
    NCRYPT_KEY_HANDLE KeyProv = (ULONG_PTR)NULL;

    BOOL FreeKey;
    DWORD KeySpec;
    if (!CryptAcquireCertificatePrivateKey(
            CertCtx,
            CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG,
            NULL,
            &KeyProv,
            &KeySpec,
            &FreeKey)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            GetLastError(),
            "CryptAcquireCertificatePrivateKey failed");
        goto Exit;
    }

    CXPLAT_DBG_ASSERT(FreeKey);

    if (KeySpec != CERT_NCRYPT_KEY_SPEC) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            KeySpec,
            "Cert KeySpec doesn't have CERT_NCRYPT_KEY_SPEC");
        NCryptFreeObject(KeyProv);
        KeyProv = (ULONG_PTR)NULL;
        goto Exit;
    }

Exit:

    return (void*)KeyProv;
}

void
CxPlatCertDeletePrivateKey(
    _In_ void* PrivateKey
    )
{
    NCRYPT_KEY_HANDLE KeyProv = (NCRYPT_KEY_HANDLE)PrivateKey;
    NCryptFreeObject(KeyProv);
}

_Success_(return != FALSE)
BOOLEAN
CxPlatCertSign(
    _In_ void* PrivateKey,
    _In_ const UINT16 SignatureAlgorithm,
    _In_reads_(CertListToSignLength)
        const BYTE *CertListToSign,
    _In_ size_t CertListToSignLength,
    _Out_writes_to_(*SignatureLength, *SignatureLength)
        BYTE *Signature,
    _Inout_ size_t *SignatureLength
    )
{
    NCRYPT_KEY_HANDLE KeyProv = (NCRYPT_KEY_HANDLE)PrivateKey;

    QuicTraceLogVerbose(
        CertCapiSign,
        "[cert] QuicCertSign alg=0x%4.4x",
        SignatureAlgorithm);

    _Null_terminated_ const wchar_t * HashAlg = HashAlgFromTLS(SignatureAlgorithm);
    if (HashAlg == NULL) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SignatureAlgorithm,
            "Unsupported hash algorithm (HashAlg)");
        return FALSE;
    }

    BCRYPT_ALG_HANDLE HashProv = HashHandleFromTLS(SignatureAlgorithm);
    if (HashProv == NULL) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SignatureAlgorithm,
            "Unsupported hash algorithm");
        return FALSE;
    }

    DWORD HashSize = HashSizeFromTLS(SignatureAlgorithm);
    if (HashSize == 0 || HashSize > CXPLAT_CERTIFICATE_MAX_HASH_SIZE) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SignatureAlgorithm,
            "Unsupported hash size");
        return FALSE;
    }

    DWORD PaddingScheme = PaddingTypeFromTLS(SignatureAlgorithm);
    if (PaddingScheme == ~0u) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SignatureAlgorithm,
            "Unsupported padding scheme");
        return FALSE;
    }

    BOOLEAN Result = FALSE;
    BYTE HashBuf[CXPLAT_CERTIFICATE_MAX_HASH_SIZE] = { 0 };
    CXPLAT_SIGN_PADDING Padding = { 0 };

    NTSTATUS Status =
        BCryptHash(
            HashProv,
            NULL,
            0,
            (PUCHAR)CertListToSign,
            (ULONG)CertListToSignLength,
            HashBuf,
            HashSize);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "BCryptHash failed");
        goto Exit;
    }

    DWORD SignFlags;
    if (PaddingScheme == BCRYPT_PAD_NONE) {
        SignFlags = 0;
    } else {
        PopulatePaddingParams(
            &Padding,
            PaddingScheme,
            HashAlg,
            HashSize);
        SignFlags = PaddingScheme;
    }

    DWORD NewSignatureLength = (DWORD)*SignatureLength;
    Status =
        NCryptSignHash(
            KeyProv,
            PaddingScheme == BCRYPT_PAD_NONE ? NULL : &Padding,
            HashBuf,
            HashSize,
            Signature,
            (ULONG)*SignatureLength,
            &NewSignatureLength,
            SignFlags);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "NCryptSignHash failed");
        goto Exit;
    }

    *SignatureLength = NewSignatureLength;

    Result = TRUE;

Exit:

    RtlSecureZeroMemory(HashBuf, sizeof(HashBuf));

    return Result;
}

_Success_(return != FALSE)
BOOLEAN
CxPlatCertVerify(
    _In_ QUIC_CERTIFICATE* Certificate,
    _In_ const UINT16 SignatureAlgorithm,
    _In_reads_(CertListToVerifyLength)
        const BYTE *CertListToVerify,
    _In_ size_t CertListToVerifyLength,
    _In_reads_(SignatureLength)
        const BYTE *Signature,
    _In_ size_t SignatureLength
    )
{
    PCCERT_CONTEXT CertCtx = (PCCERT_CONTEXT)Certificate;

    QuicTraceLogVerbose(
        CertCapiVerify,
        "[cert] QuicCertVerify alg=0x%4.4x",
        SignatureAlgorithm);

    if (CertListToVerifyLength > MAXUINT32 || SignatureLength > MAXUINT32) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "CertListToVerify or Signature too large");
        return FALSE;
    }

    _Null_terminated_ const wchar_t * HashAlg = HashAlgFromTLS(SignatureAlgorithm);
    if (HashAlg == NULL) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SignatureAlgorithm,
            "Unsupported hash algorithm (HashAlg)");
        return FALSE;
    }

    DWORD PaddingScheme = PaddingTypeFromTLS(SignatureAlgorithm);
    if (PaddingScheme == ~0u) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SignatureAlgorithm,
            "Unsupported padding scheme");
        return FALSE;
    }

    BCRYPT_ALG_HANDLE HashProv = HashHandleFromTLS(SignatureAlgorithm);
    if (HashProv == NULL) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SignatureAlgorithm,
            "Unsupported hash algorithm");
        return FALSE;
    }

    DWORD HashSize = HashSizeFromTLS(SignatureAlgorithm);
    if (HashSize == 0 || HashSize > CXPLAT_CERTIFICATE_MAX_HASH_SIZE) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SignatureAlgorithm,
            "Unsupported hash size");
        return FALSE;
    }

    BOOLEAN Result = FALSE;
    BYTE HashBuf[CXPLAT_CERTIFICATE_MAX_HASH_SIZE] = { 0 };
    BCRYPT_KEY_HANDLE PublicKey = (ULONG_PTR)NULL;
    CXPLAT_SIGN_PADDING Padding = { 0 };

    NTSTATUS Status =
        BCryptHash(
            HashProv,
            NULL,
            0,
            (PUCHAR)CertListToVerify,
            (ULONG)CertListToVerifyLength,
            HashBuf,
            HashSize);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "BCryptHash failed");
        goto Exit;
    }

    if (!CryptImportPublicKeyInfoEx2(
            X509_ASN_ENCODING,
            &CertCtx->pCertInfo->SubjectPublicKeyInfo,
            0,
            NULL,
            &PublicKey)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "CryptImportPublicKeyInfoEx2 failed");
        goto Exit;
    }

    DWORD SignFlags;
    if (PaddingScheme == BCRYPT_PAD_NONE) {
        SignFlags = 0;
    } else {
        PopulatePaddingParams(
            &Padding,
            PaddingScheme,
            HashAlg,
            HashSize); // OpenSSL uses HashSize as the salt size.
                       // Others might use SignatureSize - HashSize - 2.
        SignFlags = PaddingScheme;
    }

    Status =
        BCryptVerifySignature(
            PublicKey,
            PaddingScheme == BCRYPT_PAD_NONE ? NULL : &Padding,
            HashBuf,
            HashSize,
            (PUCHAR)Signature,
            (ULONG)SignatureLength,
            SignFlags);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "BCryptVerifySignature failed");
        goto Exit;
    }

    Result = TRUE;

Exit:

    if (PublicKey) {
        BCryptDestroyKey(PublicKey);
    }

    return Result;
}
