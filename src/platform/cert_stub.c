/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Certificate Platform Functions

--*/

#include "platform_internal.h"
#ifdef QUIC_CLOG
#include "cert_stub.c.clog.h"
#endif

QUIC_STATUS
CxPlatCertCreate(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _Out_ QUIC_CERTIFICATE** NewCertificate
    )
{
    if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH) {
        if (CredConfig->CertificateHash == NULL && CredConfig->Principal == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    } else if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE) {
        if (CredConfig->CertificateHashStore == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    } else if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT) {
        if (CredConfig->CertificateContext == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    } else if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE) {
        if (CredConfig->CertificateFile == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    } else {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    *NewCertificate = (QUIC_CERTIFICATE*)1;
    return QUIC_STATUS_SUCCESS;
}

void
CxPlatCertFree(
    _In_ QUIC_CERTIFICATE* Certificate
    )
{
    UNREFERENCED_PARAMETER(Certificate);
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
    UNREFERENCED_PARAMETER(Certificate);
    UNREFERENCED_PARAMETER(SignatureAlgorithmsLength);
    *SelectedSignature = SignatureAlgorithms[0];
    return TRUE;
}

_Success_(return != NULL)
QUIC_CERTIFICATE*
CxPlatCertParseChain(
    _In_ size_t ChainBufferLength,
    _In_reads_(ChainBufferLength)
        const uint8_t *ChainBuffer
    )
{
    if (ChainBufferLength < SIZEOF_CERT_CHAIN_LIST_LENGTH) {
        return NULL;
    }
    uint32_t CertLength =
        ((uint32_t)ChainBuffer[0]) << 16 |
        ((uint32_t)ChainBuffer[1]) << 8 |
        ((uint32_t)ChainBuffer[2]);
    if (ChainBufferLength < SIZEOF_CERT_CHAIN_LIST_LENGTH + CertLength) {
        return NULL;
    }
    return (QUIC_CERTIFICATE*)1;
}

_Success_(return != 0)
size_t
CxPlatCertFormat(
    _In_opt_ QUIC_CERTIFICATE* Certificate,
    _In_ size_t BufferLength,
    _Out_writes_to_(BufferLength, return)
        uint8_t* Buffer
    )
{
    UNREFERENCED_PARAMETER(Certificate);
    UNREFERENCED_PARAMETER(BufferLength);
    if (BufferLength < SIZEOF_CERT_CHAIN_LIST_LENGTH) {
        return 0;
    }
    CxPlatZeroMemory(Buffer, SIZEOF_CERT_CHAIN_LIST_LENGTH); // Encode 0 length cert chain.
    return SIZEOF_CERT_CHAIN_LIST_LENGTH;
}

_Success_(return != FALSE)
BOOLEAN
CxPlatCertValidateChain(
    _In_ QUIC_CERTIFICATE* Certificate,
    _In_opt_z_ const char* Host,
    _In_ uint32_t IgnoreFlags
    )
{
    UNREFERENCED_PARAMETER(Certificate);
    UNREFERENCED_PARAMETER(Host);
    UNREFERENCED_PARAMETER(IgnoreFlags);
    return TRUE;
}

_Success_(return != NULL)
void*
CxPlatCertGetPrivateKey(
    _In_ QUIC_CERTIFICATE* Certificate
    )
{
    UNREFERENCED_PARAMETER(Certificate);
    return (void*)1;
}

void
CxPlatCertDeletePrivateKey(
    _In_ void* PrivateKey
    )
{
    UNREFERENCED_PARAMETER(PrivateKey);
}

_Success_(return != FALSE)
BOOLEAN
CxPlatCertSign(
    _In_ void* PrivateKey,
    _In_ const uint16_t SignatureAlgorithm,
    _In_reads_(CertListToBeSignedLength)
        const uint8_t *CertListToBeSigned,
    _In_ size_t CertListToBeSignedLength,
    _Out_writes_to_(*SignatureLength, *SignatureLength)
        uint8_t *Signature,
    _Inout_ size_t *SignatureLength
    )
{
    UNREFERENCED_PARAMETER(PrivateKey);
    UNREFERENCED_PARAMETER(SignatureAlgorithm);
    UNREFERENCED_PARAMETER(CertListToBeSigned);
    UNREFERENCED_PARAMETER(CertListToBeSignedLength);
    UNREFERENCED_PARAMETER(Signature);
    if (*SignatureLength >= 16) {
        *SignatureLength = 16;
        return TRUE;
    } else {
        return FALSE;
    }
}

_Success_(return != FALSE)
BOOLEAN
CxPlatCertVerify(
    _In_ QUIC_CERTIFICATE* Certificate,
    _In_ const uint16_t SignatureAlgorithm,
    _In_reads_(CertListToBeSignedLength)
        const uint8_t *CertListToBeSigned,
    _In_ size_t CertListToBeSignedLength,
    _In_reads_(SignatureLength)
        const uint8_t *Signature,
    _In_ size_t SignatureLength
    )
{
    UNREFERENCED_PARAMETER(Certificate);
    UNREFERENCED_PARAMETER(SignatureAlgorithm);
    UNREFERENCED_PARAMETER(CertListToBeSigned);
    UNREFERENCED_PARAMETER(CertListToBeSignedLength);
    UNREFERENCED_PARAMETER(Signature);
    UNREFERENCED_PARAMETER(SignatureLength);
    return TRUE;
}
