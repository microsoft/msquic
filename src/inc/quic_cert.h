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

typedef struct QUIC_PORTABLE_CERTIFICATE {
    QUIC_CERTIFICATE* PlatformCertificate;
    QUIC_BUFFER PortableCertificate;
    QUIC_BUFFER PortableChain;
} QUIC_PORTABLE_CERTIFICATE;

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
// Gets a portable certificate and chain in PKCS7 format.
//
_Success_(return != 0)
QUIC_STATUS
CxPlatGetPortableCertificate(
    _In_ QUIC_CERTIFICATE* Certificate,
    _Out_ QUIC_PORTABLE_CERTIFICATE* PortableCertificate
    );

//
// Gets a portable certificate and chain in PKCS7 format from
// a serialized certificate store.
//
_Success_(return != 0)
QUIC_STATUS
CxPlatGetPortableCertificateFromSerialized(
    _In_ QUIC_CERTIFICATE* SerializedCertificate,
    _Out_ QUIC_PORTABLE_CERTIFICATE* PortableCertificate
    );

//
// Frees a portable certificate and chain returned from CxPlatGetPortableCertificate
//
void
CxPlatFreePortableCertificate(
    _In_ QUIC_PORTABLE_CERTIFICATE* PortableCertificate
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
    _In_ uint32_t CertFlags,
    _In_ uint32_t CredFlags,
    _Out_opt_ uint32_t* ValidationError
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

QUIC_STATUS
CxPlatCertExtractPrivateKey(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _In_z_ const char* Password,
    _Outptr_result_buffer_(*PfxSize) uint8_t** PfxBytes,
    _Out_ uint32_t* PfxSize
    );

_Success_(return != FALSE)
BOOLEAN
CxPlatCertVerifyRawCertificate(
    _In_reads_bytes_(X509CertLength) unsigned char* X509Cert,
    _In_ int X509CertLength,
    _In_opt_ const char* SNI,
    _In_ QUIC_CREDENTIAL_FLAGS CredFlags,
    _Out_opt_ uint32_t* PlatformVerificationError
    );
