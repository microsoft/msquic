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

#if defined(QUIC_LOGS_WPP) || defined(QUIC_LOGS_CLOG)
; //<-- WPP line was here
#include "cert_capi.c.clog"

#endif

#include <wincrypt.h>
#include <msquic.h>

typedef union QUIC_SIGN_PADDING {
    BCRYPT_PKCS1_PADDING_INFO Pkcs1;
    BCRYPT_PSS_PADDING_INFO Pss;
} QUIC_SIGN_PADDING;

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

#define QUIC_CERTIFICATE_MAX_HASH_SIZE 64

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
    _Inout_ QUIC_SIGN_PADDING* Padding,
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
        QUIC_DBG_ASSERT(FALSE);
    }
}

BOOLEAN
QuicCertMatchHash(
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
        QuicTraceLogError("[cert] Get CERT_HASH_PROP_ID failed, 0x%x.", GetLastError());
        return FALSE;
    }
    if (CertHashLength != sizeof(CertHash)) {
        QuicTraceLogError("[cert] CERT_HASH_PROP_ID incorrect size, %u.", CertHashLength);
        return FALSE;
    }
    return memcmp(InputCertHash, CertHash, CertHashLength) == 0;
}

BOOLEAN
QuicCertMatchPrincipal(
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

    CertificateNames = QUIC_ALLOC_PAGED(Length);
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
        QUIC_FREE(CertificateNames);
    }

    return MatchFound;
}

PCCERT_CONTEXT
QuicCertStoreFind(
    _In_ HCERTSTORE CertStore,
    _In_reads_opt_(20) const UINT8 CertHash[20],
    _In_opt_z_ const char* Principal
    )
{
    PCSTR OID_SERVER_AUTH = szOID_PKIX_KP_SERVER_AUTH;
    CERT_ENHKEY_USAGE Usage;
    Usage.cUsageIdentifier = 1;
    Usage.rgpszUsageIdentifier = (LPSTR*)&OID_SERVER_AUTH;

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

        if (CertHash != NULL && !QuicCertMatchHash(CertCtx, CertHash)) {
            continue;
        }

        if (Principal != NULL && !QuicCertMatchPrincipal(CertCtx, Principal)) {
            continue;
        }

        return CertCtx;
    }

    return NULL;
}

QUIC_STATUS
QuicCertLookupHash(
    _In_opt_ const QUIC_CERTIFICATE_HASH* CertHash,
    _In_opt_z_ const char* Principal,
    _Out_ QUIC_CERT** NewCertificate
    )
{
    QUIC_STATUS Status;
    HCERTSTORE CertStore;

    QUIC_DBG_ASSERT(CertHash != NULL || Principal != NULL);

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
        QuicCertStoreFind(
            CertStore,
            CertHash == NULL ? NULL : CertHash->ShaHash,
            Principal);
    if (CertCtx == NULL) {
        Status = QUIC_STATUS_NOT_FOUND;
        goto Exit;
    }

    Status = QUIC_STATUS_SUCCESS;
    *NewCertificate = (QUIC_CERT*)CertCtx;

Exit:

    if (CertStore != NULL) {
        CertCloseStore(CertStore, 0);
    }

    return Status;
}

QUIC_STATUS
QuicCertLookupHashStore(
    _In_ const QUIC_CERTIFICATE_HASH_STORE* CertHashStore,
    _In_opt_z_ const char* Principal,
    _Out_ QUIC_CERT** NewCertificate
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
        QuicTraceLogError("[cert] CertOpenStore failed '%s', 0x%x.", CertHashStore->StoreName, Status);
        goto Exit;
    }

    PCCERT_CONTEXT CertCtx =
        QuicCertStoreFind(
            CertStore,
            CertHashStore->ShaHash,
            Principal);
    if (CertCtx == NULL) {
        Status = QUIC_STATUS_NOT_FOUND;
        goto Exit;
    }

    Status = QUIC_STATUS_SUCCESS;
    *NewCertificate = (QUIC_CERT*)CertCtx;

Exit:

    if (CertStore != NULL) {
        CertCloseStore(CertStore, 0);
    }

    return Status;
}

QUIC_STATUS
QuicCertCreate(
    _In_ uint32_t Flags,
    _In_opt_ void* CertConfig,
    _In_opt_z_ const char* Principal,
    _Out_ QUIC_CERT** NewCertificate
    )
{
    QUIC_STATUS Status;

    if (CertConfig == NULL) {
        Flags &= ~(QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH | QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH_STORE);
    }

    if (Flags & QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH_STORE) {
        if (CertConfig == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        Status =
            QuicCertLookupHashStore(
                (const QUIC_CERTIFICATE_HASH_STORE*)CertConfig,
                Principal,
                NewCertificate);

    } else {
        if (CertConfig == NULL && Principal == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Exit;
        }

        Status =
            QuicCertLookupHash(
                (const QUIC_CERTIFICATE_HASH*)CertConfig,
                Principal,
                NewCertificate);
    }

Exit:

    return Status;
}

void
QuicCertFree(
    _In_ QUIC_CERT* Certificate
    )
{
    (void)CertFreeCertificateContext((PCERT_CONTEXT)Certificate);
}

_Success_(return != FALSE)
BOOLEAN
QuicCertSelect(
    _In_opt_ PCCERT_CONTEXT CertCtx,
    _In_reads_(SignatureAlgorithmsLength)
        const UINT16 *SignatureAlgorithms,
    _In_ size_t SignatureAlgorithmsLength,
    _Out_ UINT16 *SelectedSignature
    )
{
    //
    // High byte of SignatureAlgorithms[] is the TLS HashAlgorithm:
    //  none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5), sha512(6)
    // Low byte of SignatureAlgorithms[] is the TLS SignatureAlgorithm:
    //  anonymous(0), rsa(1), dsa(2), ecdsa(3)
    //

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
QUIC_CERT*
QuicCertParseChain(
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
        QuicTraceLogError("[cert] CertOpenStore failed, 0x%x.", GetLastError());
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
            QuicTraceLogError("[cert] CertAddEncodedCertificateToStore failed for cert #%u, 0x%x.",
                CertNumber, GetLastError());
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
        QuicTraceLogError("[cert] Not all bytes were processed.");
        goto Error;
    }

    QuicTraceLogVerbose("[cert] Successfully parsed chain of %u certificate(s).", CertNumber);

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

    return (QUIC_CERT*)LeafCertCtx;
}

_Success_(return != 0)
size_t
QuicCertFormat(
    _In_opt_ QUIC_CERT* Certificate,
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
            QuicTraceLogError("[cert] Insufficient buffer to store the empty formatted chain.");
            return 0;
        }
        //
        // Just encode list of zero cert chains.
        //
        QuicZeroMemory(Offset, SIZEOF_CERT_CHAIN_LIST_LENGTH);
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
            NULL,   // default chain engine
            CertCtx,
            NULL,
            NULL,
            &ChainPara,
            0,
            NULL,
            &ChainContext)) {
        QuicTraceLogError("[cert] CertGetCertificateChain failed, 0x%x.", GetLastError());
        return 0;
    }

    for (DWORD i = 0; i < ChainContext->cChain; ++i) {
        PCERT_SIMPLE_CHAIN SimpleChain = ChainContext->rgpChain[i];
        for (DWORD j = 0; j < SimpleChain->cElement; ++j) {
            PCERT_CHAIN_ELEMENT Element = SimpleChain->rgpElement[j];
            PCCERT_CONTEXT EncodedCert = Element->pCertContext;
            if (EncodedCert->cbCertEncoded + SIZEOF_CERT_CHAIN_LIST_LENGTH > BufferLength) {
                QuicTraceLogError("[cert] Insufficient buffer to store the formatted chain.");
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

    QuicTraceLogVerbose("[cert] Successfully formatted chain of %u certificate(s).", CertNumber);

    return (size_t)(Offset - Buffer);
}

_Success_(return == NO_ERROR)
DWORD
QuicCertVerifyCertChainPolicy(
    _In_ PCCERT_CHAIN_CONTEXT ChainContext,
    _In_opt_ PWSTR ServerName,
    _In_ ULONG IgnoreFlags
    )
{
    DWORD Status = NO_ERROR;

    HTTPSPolicyCallbackData HttpsPolicy;
    CERT_CHAIN_POLICY_PARA PolicyPara;
    CERT_CHAIN_POLICY_STATUS PolicyStatus;

    memset(&HttpsPolicy, 0, sizeof(HTTPSPolicyCallbackData));
    HttpsPolicy.cbStruct = sizeof(HTTPSPolicyCallbackData);
    HttpsPolicy.dwAuthType = AUTHTYPE_SERVER;
    HttpsPolicy.fdwChecks = IgnoreFlags;
    HttpsPolicy.pwszServerName = ServerName;

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
        QuicTraceLogError("[cert] CertVerifyCertificateChainPolicy failed, 0x%x.", Status);
        goto Exit;

    } else if (PolicyStatus.dwError != NO_ERROR) {

        Status = PolicyStatus.dwError;
        QuicTraceLogError("[cert] CertVerifyCertificateChainPolicy indicated a cert error, 0x%x.", Status);
        goto Exit;
    }

Exit:

    QuicTraceLogInfo("CertVerifyChain: %S 0x%x, result=0x%x", ServerName, IgnoreFlags, Status);

    return Status;
}

_Success_(return != FALSE)
BOOLEAN
QuicCertValidateChain(
    _In_ QUIC_CERT* Certificate,
    _In_opt_z_ PCSTR Host,
    _In_ uint32_t IgnoreFlags
    )
{
    BOOLEAN Result = FALSE;
    PCCERT_CHAIN_CONTEXT ChainContext = NULL;
    LPWSTR ServerName = NULL;

    PCCERT_CONTEXT LeafCertCtx = (PCCERT_CONTEXT)Certificate;

    CERT_CHAIN_PARA ChainPara;

    static const LPSTR UsageOids[] = {
        szOID_PKIX_KP_SERVER_AUTH,
        szOID_SERVER_GATED_CRYPTO,
        szOID_SGC_NETSCAPE
    };

    memset(&ChainPara, 0, sizeof(ChainPara));
    ChainPara.cbSize = sizeof(ChainPara);
    ChainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
    ChainPara.RequestedUsage.Usage.cUsageIdentifier = ARRAYSIZE(UsageOids);
    ChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = (LPSTR*)UsageOids;

    if (!CertGetCertificateChain(
            NULL,
            LeafCertCtx,
            NULL,
            LeafCertCtx->hCertStore,
            &ChainPara,
            0,
            NULL,
            &ChainContext)) {
        QuicTraceLogError("[cert] CertGetCertificateChain failed, 0x%x.", GetLastError());
        goto Exit;
    }

    if (Host != NULL) {
        int ServerNameLength = MultiByteToWideChar(CP_UTF8, 0, Host, -1, NULL, 0);
        if (ServerNameLength == 0) {
            QuicTraceLogError("[cert] MultiByteToWideChar(1) failed, 0x%x.", GetLastError());
            goto Exit;
        }

        ServerName = (LPWSTR)QUIC_ALLOC_PAGED(ServerNameLength * sizeof(WCHAR));
        if (ServerName == NULL) {
            QuicTraceLogWarning("[cert] Failed to alloc %u bytes for ServerName.", (uint32_t)(ServerNameLength * sizeof(WCHAR)));
            goto Exit;
        }

        ServerNameLength = MultiByteToWideChar(CP_UTF8, 0, Host, -1, ServerName, ServerNameLength);
        if (ServerNameLength == 0) {
            QuicTraceLogError("[cert] MultiByteToWideChar(2) failed, 0x%x.", GetLastError());
            goto Exit;
        }
    }

    Result =
        NO_ERROR ==
        QuicCertVerifyCertChainPolicy(
            ChainContext,
            ServerName,
            IgnoreFlags);

Exit:

    if (ChainContext != NULL) {
        CertFreeCertificateChain(ChainContext);
    }
    if (ServerName != NULL) {
        QUIC_FREE(ServerName);
    }

    return Result;
}

_Success_(return != NULL)
void*
QuicCertGetPrivateKey(
    _In_ QUIC_CERT* Certificate
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
        QuicTraceLogError("[cert] CryptAcquireCertificatePrivateKey failed, 0x%x.", GetLastError());
        goto Exit;
    }

    QUIC_DBG_ASSERT(FreeKey);

    if (KeySpec != CERT_NCRYPT_KEY_SPEC) {
        QuicTraceLogError("[cert] Cert KeySpec doesn't have CERT_NCRYPT_KEY_SPEC, 0x%x.", KeySpec);
        NCryptFreeObject(KeyProv);
        KeyProv = (ULONG_PTR)NULL;
        goto Exit;
    }

Exit:

    return (void*)KeyProv;
}

void
QuicCertDeletePrivateKey(
    _In_ void* PrivateKey
    )
{
    NCRYPT_KEY_HANDLE KeyProv = (NCRYPT_KEY_HANDLE)PrivateKey;
    NCryptFreeObject(KeyProv);
}

_Success_(return != FALSE)
BOOLEAN
QuicCertSign(
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

    QuicTraceLogVerbose("[cert] QuicCertSign alg=0x%4.4x", SignatureAlgorithm);

    _Null_terminated_ const wchar_t * HashAlg = HashAlgFromTLS(SignatureAlgorithm);
    if (HashAlg == NULL) {
        QuicTraceLogError("[cert] Unsupported hash algorithm 0x%x (HashAlg).", SignatureAlgorithm);
        return FALSE;
    }

    BCRYPT_ALG_HANDLE HashProv = HashHandleFromTLS(SignatureAlgorithm);
    if (HashProv == NULL) {
        QuicTraceLogError("[cert] Unsupported hash algorithm 0x%x.", SignatureAlgorithm);
        return FALSE;
    }

    DWORD HashSize = HashSizeFromTLS(SignatureAlgorithm);
    if (HashSize == 0 || HashSize > QUIC_CERTIFICATE_MAX_HASH_SIZE) {
        QuicTraceLogError("[cert] Unsupported hash size 0x%x.", SignatureAlgorithm);
        return FALSE;
    }

    DWORD PaddingScheme = PaddingTypeFromTLS(SignatureAlgorithm);
    if (PaddingScheme == ~0u) {
        QuicTraceLogError("[cert] Unsupported padding scheme 0x%x.", SignatureAlgorithm);
        return FALSE;
    }

    BOOLEAN Result = FALSE;
    BYTE HashBuf[QUIC_CERTIFICATE_MAX_HASH_SIZE] = { 0 };
    QUIC_SIGN_PADDING Padding = { 0 };

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
        QuicTraceLogError("[cert] BCryptHash failed, 0x%x.", Status);
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
        QuicTraceLogError("[cert] NCryptSignHash failed, 0x%x.", Status);
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
QuicCertVerify(
    _In_ QUIC_CERT* Certificate,
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

    QuicTraceLogVerbose("[cert] QuicCertVerify alg=0x%4.4x", SignatureAlgorithm);

    if (CertListToVerifyLength > MAXUINT32 || SignatureLength > MAXUINT32) {
        QuicTraceLogError("[cert] CertListToVerify or Signature too large.");
        return FALSE;
    }

    _Null_terminated_ const wchar_t * HashAlg = HashAlgFromTLS(SignatureAlgorithm);
    if (HashAlg == NULL) {
        QuicTraceLogError("[cert] Unsupported signature algorithm 0x%x (HashAlg).", SignatureAlgorithm);
        return FALSE;
    }

    DWORD PaddingScheme = PaddingTypeFromTLS(SignatureAlgorithm);
    if (PaddingScheme == ~0u) {
        QuicTraceLogError("[cert] Unsupported padding scheme 0x%x.", SignatureAlgorithm);
        return FALSE;
    }

    BCRYPT_ALG_HANDLE HashProv = HashHandleFromTLS(SignatureAlgorithm);
    if (HashProv == NULL) {
        QuicTraceLogError("[cert] Unsupported hash algorithm 0x%x.", SignatureAlgorithm);
        return FALSE;
    }

    DWORD HashSize = HashSizeFromTLS(SignatureAlgorithm);
    if (HashSize == 0 || HashSize > QUIC_CERTIFICATE_MAX_HASH_SIZE) {
        QuicTraceLogError("[cert] Unsupported hash size 0x%x.", SignatureAlgorithm);
        return FALSE;
    }

    BOOLEAN Result = FALSE;
    BYTE HashBuf[QUIC_CERTIFICATE_MAX_HASH_SIZE] = { 0 };
    BCRYPT_KEY_HANDLE PublicKey = (ULONG_PTR)NULL;
    QUIC_SIGN_PADDING Padding = { 0 };

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
        QuicTraceLogError("[cert] BCryptHash failed, 0x%x.", Status);
        goto Exit;
    }

    if (!CryptImportPublicKeyInfoEx2(
            X509_ASN_ENCODING,
            &CertCtx->pCertInfo->SubjectPublicKeyInfo,
            0,
            NULL,
            &PublicKey)) {
        QuicTraceLogError("[cert] CryptImportPublicKeyInfoEx2 failed, 0x%x.", GetLastError());
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
        QuicTraceLogError("[cert] BCryptVerifySignature failed, 0x%x.", Status);
        goto Exit;
    }

    Result = TRUE;

Exit:

    if (PublicKey) {
        BCryptDestroyKey(PublicKey);
    }

    return Result;
}
