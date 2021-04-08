/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    This file contains the definitions for certificate processing functionality.

Environment:

    user mode or kernel mode

--*/

#define SIZEOF_CERT_CHAIN_LIST_LENGTH 3

typedef struct QUIC_CREDENTIAL_CONFIG QUIC_CREDENTIAL_CONFIG;
typedef void QUIC_CERTIFICATE;
typedef void QUIC_CERTIFICATE_CHAIN;
#ifndef _MSQUIC_
typedef struct QUIC_BUFFER QUIC_BUFFER;
#endif

typedef enum QUIC_CERTIFICATE_FORMAT {
    QUIC_CERTIFICATE_FORMAT_DER   = 0,
    QUIC_CERTIFICATE_FORMAT_PKCS7 = 1,
} QUIC_CERTIFICATE_FORMAT;


//
// Gets the certificate from the input configuration.
//
QUIC_STATUS
CxPlatCertCreate(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _Out_ QUIC_CERTIFICATE** NewCertificate
    );

//
// Frees a certificate returned from QuicCertCreate.
//
void
CxPlatCertFree(
    _In_ QUIC_CERTIFICATE* Certificate
    );

//
// Given a certificate and a set of signature algorithms, this function returns
// an appropriate signature algorithm.
//
_Success_(return != FALSE)
BOOLEAN
CxPlatCertSelect(
    _In_opt_ QUIC_CERTIFICATE* Certificate,
    _In_reads_(SignatureAlgorithmsLength)
        const uint16_t *SignatureAlgorithms,
    _In_ size_t SignatureAlgorithmsLength,
    _Out_ uint16_t *SelectedSignature
    );

//
// Parses the wireframe format of an X509 certificate and returns a pointer
// to a certificate object.
//
_Success_(return != NULL)
QUIC_CERTIFICATE*
CxPlatCertParseChain(
    _In_ size_t ChainBufferLength,
    _In_reads_(ChainBufferLength) const uint8_t *ChainBuffer
    );

//
// Converts a certificate to the wireformat. Returns the length of the encoded
// data.
//
_Success_(return != 0)
size_t
CxPlatCertFormat(
    _In_opt_ QUIC_CERTIFICATE* Certificate,
    _In_ size_t BufferLength,
    _Out_writes_to_(BufferLength, return)
        uint8_t* Buffer
    );

//
// Validates the certificate change.
//
_Success_(return != FALSE)
BOOLEAN
CxPlatCertValidateChain(
    _In_ const QUIC_CERTIFICATE* Certificate,
    _In_opt_z_ const char* Host,
    _In_ uint32_t IgnoreFlags
    );

//
// Gets the private key for signing.
//
_Success_(return != NULL)
void*
CxPlatCertGetPrivateKey(
    _In_ QUIC_CERTIFICATE* Certificate
    );

//
// Frees the private key retrieved from QuicCertGetPrivateKey.
//
void
CxPlatCertDeletePrivateKey(
    _In_ void* PrivateKey
    );

//
// Uses the certificate to sign the cert list.
//
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
    );

//
// Validates the signature of the cert list for the given certificate.
//
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
    );


//
// Convert platform specific certificate to requested format.
// OutputBuffer is allocated and needs to be freed with CxPlatQuicBufferFree.
//
_Success_(return != FALSE)
BOOLEAN
CxPlatCertConvert(
    _In_ QUIC_CERTIFICATE* Certificate,
    _In_ QUIC_CERTIFICATE_FORMAT OutputFormat,
    _Inout_ QUIC_BUFFER* OutputBuffer);

//
// Convert platform specific certificate chain to requested format.
// OutputBuffer is allocated and needs to be freed with CxPlatQuicBufferFree.
//
_Success_(return != FALSE)
BOOLEAN
CxPlatCertChainConvert(
    _In_ QUIC_CERTIFICATE_CHAIN* CertificateChain,
    _In_ QUIC_CERTIFICATE_FORMAT OutputFormat,
    _Inout_ QUIC_BUFFER* OutputBuffer);


//
// This will free QUIC_BUFFER resources if allocated by MsQiuc.
// This has undefined and possibly dangerous behavior if Buffer was not allocated by MsQuic.
//
void CxPlatQuicBufferFree(_In_ QUIC_BUFFER* Buffer);
