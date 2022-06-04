/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    SCHANNEL TLS Implementation for QUIC

Environment:

    Windows user mode or kernel mode

--*/

#ifdef QUIC_UWP_BUILD
#undef WINAPI_FAMILY
#define WINAPI_FAMILY WINAPI_FAMILY_DESKTOP_APP
#endif

#include "platform_internal.h"
#include <security.h>
#ifdef QUIC_CLOG
#include "tls_schannel.c.clog.h"
#endif

#ifdef _KERNEL_MODE

#include <winerror.h>

typedef enum _SEC_APPLICATION_PROTOCOL_NEGOTIATION_STATUS
{
    SecApplicationProtocolNegotiationStatus_None,
    SecApplicationProtocolNegotiationStatus_Success,
    SecApplicationProtocolNegotiationStatus_SelectedClientOnly
} SEC_APPLICATION_PROTOCOL_NEGOTIATION_STATUS, *PSEC_APPLICATION_PROTOCOL_NEGOTIATION_STATUS;

#define MAX_PROTOCOL_ID_SIZE 0xff

typedef struct _SecPkgContext_ApplicationProtocol
{
    SEC_APPLICATION_PROTOCOL_NEGOTIATION_STATUS ProtoNegoStatus; // Application  protocol negotiation status
    SEC_APPLICATION_PROTOCOL_NEGOTIATION_EXT ProtoNegoExt;       // Protocol negotiation extension type corresponding to this protocol ID
    unsigned char ProtocolIdSize;                                // Size in bytes of the application protocol ID
    unsigned char ProtocolId[MAX_PROTOCOL_ID_SIZE];              // Byte string representing the negotiated application protocol ID
} SecPkgContext_ApplicationProtocol, *PSecPkgContext_ApplicationProtocol;

typedef struct _SecPkgContext_CertificateValidationResult
{
    DWORD dwChainErrorStatus;    // Contains chain build error flags set by CertGetCertificateChain.
    HRESULT hrVerifyChainStatus; // Certificate validation policy error returned by CertVerifyCertificateChainPolicy.
} SecPkgContext_CertificateValidationResult, *PSecPkgContext_CertificateValidationResult;

// Session ticket protection version definitions.
#define SESSION_TICKET_INFO_V0 0
#define SESSION_TICKET_INFO_VERSION SESSION_TICKET_INFO_V0

typedef struct _SecPkgCred_SessionTicketKey
{
    DWORD   TicketInfoVersion;      // Set to SESSION_TICKET_INFO_VERSION for the current session ticket protection method.
    BYTE    KeyId[16];              // Uniquely identifies each session ticket key issued by a TLS server.
    BYTE    KeyingMaterial[64];     // Must be generated using a cryptographic RNG.
    BYTE    KeyingMaterialSize;     // Size in bytes of the keying material in the KeyingMaterial array. Must be between 32 and 64.
} SecPkgCred_SessionTicketKey, *PSecPkgCred_SessionTicketKey;

typedef struct _SecPkgCred_SessionTicketKeys
{
    DWORD                           cSessionTicketKeys; // Up to 16 keys.
    PSecPkgCred_SessionTicketKey    pSessionTicketKeys;
} SecPkgCred_SessionTicketKeys, *PSecPkgCred_SessionTicketKeys;

typedef struct _SEND_GENERIC_TLS_EXTENSION
{
    WORD  ExtensionType;            // Code point of extension.
    WORD  HandshakeType;            // Message type used to transport extension.
    DWORD Flags;                    // Flags used to modify behavior. Must be zero.
    WORD  BufferSize;               // Size in bytes of the extension data.
    UCHAR Buffer[ANYSIZE_ARRAY];    // Extension data.
} SEND_GENERIC_TLS_EXTENSION, * PSEND_GENERIC_TLS_EXTENSION;

//
// This property returns the raw binary certificates that were received
// from the remote party. The format of the buffer that's returned is as
// follows.
//
//     <4 bytes> length of certificate #1
//     <n bytes> certificate #1
//     <4 bytes> length of certificate #2
//     <n bytes> certificate #2
//     ...
//
typedef struct _SecPkgContext_Certificates
{
    DWORD   cCertificates;
    DWORD   cbCertificateChain;
    PBYTE   pbCertificateChain;
} SecPkgContext_Certificates, *PSecPkgContext_Certificates;

typedef struct _SecPkgCred_ClientCertPolicy
{
    DWORD   dwFlags;
    GUID    guidPolicyId;
    DWORD   dwCertFlags;
    DWORD   dwUrlRetrievalTimeout;
    BOOL    fCheckRevocationFreshnessTime;
    DWORD   dwRevocationFreshnessTime;
    BOOL    fOmitUsageCheck;
    LPWSTR  pwszSslCtlStoreName;
    LPWSTR  pwszSslCtlIdentifier;
} SecPkgCred_ClientCertPolicy, *PSecPkgCred_ClientCertPolicy;

// CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL - don't hit the wire to get URL based objects
#define CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL            0x00000004

// CERT_CHAIN_CACHE_END_CERT can be used here as well
// Revocation flags are in the high nibble
#define CERT_CHAIN_REVOCATION_CHECK_END_CERT           0x10000000
#define CERT_CHAIN_REVOCATION_CHECK_CHAIN              0x20000000
#define CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT 0x40000000
#define CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY         0x80000000

#define SECPKG_ATTR_REMOTE_CERTIFICATES  0x5F   // returns SecPkgContext_Certificates

#define SP_PROT_TLS1_3_SERVER           0x00001000
#define SP_PROT_TLS1_3_CLIENT           0x00002000
#define SP_PROT_TLS1_3                  (SP_PROT_TLS1_3_SERVER | \
                                         SP_PROT_TLS1_3_CLIENT)

#define SCH_CRED_NO_SYSTEM_MAPPER                    0x00000002
#define SCH_CRED_NO_SERVERNAME_CHECK                 0x00000004
#define SCH_CRED_MANUAL_CRED_VALIDATION              0x00000008
#define SCH_CRED_NO_DEFAULT_CREDS                    0x00000010
#define SCH_CRED_AUTO_CRED_VALIDATION                0x00000020
#define SCH_CRED_USE_DEFAULT_CREDS                   0x00000040
#define SCH_CRED_DISABLE_RECONNECTS                  0x00000080

#define SCH_CRED_REVOCATION_CHECK_END_CERT           0x00000100
#define SCH_CRED_REVOCATION_CHECK_CHAIN              0x00000200
#define SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT 0x00000400
#define SCH_CRED_IGNORE_NO_REVOCATION_CHECK          0x00000800
#define SCH_CRED_IGNORE_REVOCATION_OFFLINE           0x00001000

#define SCH_CRED_RESTRICTED_ROOTS                    0x00002000
#define SCH_CRED_REVOCATION_CHECK_CACHE_ONLY         0x00004000
#define SCH_CRED_CACHE_ONLY_URL_RETRIEVAL            0x00008000

#define SCH_CRED_MEMORY_STORE_CERT                   0x00010000

#define SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE  0x00020000

#define SCH_SEND_ROOT_CERT                           0x00040000
#define SCH_CRED_SNI_CREDENTIAL                      0x00080000
#define SCH_CRED_SNI_ENABLE_OCSP                     0x00100000
#define SCH_SEND_AUX_RECORD                          0x00200000
#define SCH_USE_STRONG_CRYPTO                        0x00400000
#define SCH_USE_PRESHAREDKEY_ONLY                    0x00800000
#define SCH_USE_DTLS_ONLY                            0x01000000
#define SCH_ALLOW_NULL_ENCRYPTION                    0x02000000
#define SCH_CRED_DEFERRED_CRED_VALIDATION            0x04000000

// Values for SCHANNEL_CRED dwCredFormat field.
#define SCH_CRED_FORMAT_CERT_CONTEXT    0x00000000
#define SCH_CRED_FORMAT_CERT_HASH       0x00000001
#define SCH_CRED_FORMAT_CERT_HASH_STORE 0x00000002

#define SCH_CRED_MAX_STORE_NAME_SIZE    128
#define SCH_CRED_MAX_SUPPORTED_ALGS     256
#define SCH_CRED_MAX_SUPPORTED_CERTS    100

typedef ULONG_PTR HCRYPTPROV;

typedef struct _SCHANNEL_CERT_HASH
{
    DWORD           dwLength;
    DWORD           dwFlags;
    HCRYPTPROV      hProv;
    BYTE            ShaHash[20];
} SCHANNEL_CERT_HASH, * PSCHANNEL_CERT_HASH;

typedef struct _SCHANNEL_CERT_HASH_STORE
{
    DWORD           dwLength;
    DWORD           dwFlags;
    HCRYPTPROV      hProv;
    BYTE            ShaHash[20];
    WCHAR           pwszStoreName[SCH_CRED_MAX_STORE_NAME_SIZE];
} SCHANNEL_CERT_HASH_STORE, * PSCHANNEL_CERT_HASH_STORE;

// Values for SCHANNEL_CERT_HASH dwFlags field.
#define SCH_MACHINE_CERT_HASH           0x00000001

//
// Schannel credentials data structure.
//

#define SCH_CRED_V1              0x00000001
#define SCH_CRED_V2              0x00000002  // for legacy code
#define SCH_CRED_VERSION         0x00000002  // for legacy code
#define SCH_CRED_V3              0x00000003  // for legacy code
#define SCHANNEL_CRED_VERSION    0x00000004  // for legacy code
#define SCH_CREDENTIALS_VERSION  0x00000005

struct _HMAPPER;

typedef const struct _CERT_CONTEXT* PCCERT_CONTEXT;

typedef void* HCERTSTORE;

typedef enum _eTlsAlgorithmUsage
{
    TlsParametersCngAlgUsageKeyExchange,          // Key exchange algorithm. RSA, ECHDE, DHE, etc.
    TlsParametersCngAlgUsageSignature,            // Signature algorithm. RSA, DSA, ECDSA, etc.
    TlsParametersCngAlgUsageCipher,               // Encryption algorithm. AES, DES, RC4, etc.
    TlsParametersCngAlgUsageDigest,               // Digest of cipher suite. SHA1, SHA256, SHA384, etc.
    TlsParametersCngAlgUsageCertSig               // Signature and/or hash used to sign certificate. RSA, DSA, ECDSA, SHA1, SHA256, etc.
} eTlsAlgorithmUsage;

//
// SCH_CREDENTIALS structures
//
typedef struct _CRYPTO_SETTINGS
{
    eTlsAlgorithmUsage  eAlgorithmUsage;         // How this algorithm is being used.
    UNICODE_STRING      strCngAlgId;             // CNG algorithm identifier.
    DWORD               cChainingModes;          // Set to 0 if CNG algorithm does not have a chaining mode.
    PUNICODE_STRING     rgstrChainingModes;      // Set to NULL if CNG algorithm does not have a chaining mode.
    DWORD               dwMinBitLength;          // Blacklist key sizes less than this. Set to 0 if not defined or CNG algorithm implies bit length.
    DWORD               dwMaxBitLength;          // Blacklist key sizes greater than this. Set to 0 if not defined or CNG algorithm implies bit length.
} CRYPTO_SETTINGS, * PCRYPTO_SETTINGS;

typedef struct _TLS_PARAMETERS
{
    DWORD               cAlpnIds;                // Valid for server applications only. Must be zero otherwise. Number of ALPN IDs in rgstrAlpnIds; set to 0 if applies to all.
    PUNICODE_STRING     rgstrAlpnIds;            // Valid for server applications only. Must be NULL otherwise. Array of ALPN IDs that the following settings apply to; set to NULL if applies to all.
    DWORD               grbitDisabledProtocols;  // List protocols you DO NOT want negotiated.
    DWORD               cDisabledCrypto;         // Number of CRYPTO_SETTINGS structures; set to 0 if there are none.
    PCRYPTO_SETTINGS    pDisabledCrypto;         // Array of CRYPTO_SETTINGS structures; set to NULL if there are none;
    DWORD               dwFlags;                 // Optional flags to pass; set to 0 if there are none.
} TLS_PARAMETERS, * PTLS_PARAMETERS;

typedef struct _SCH_CREDENTIALS
{
    DWORD               dwVersion;               // Always SCH_CREDENTIALS_VERSION.
    DWORD               dwCredFormat;
    DWORD               cCreds;
    PCCERT_CONTEXT*     paCred;
    HCERTSTORE          hRootStore;

    DWORD               cMappers;
    struct _HMAPPER** aphMappers;

    DWORD               dwSessionLifespan;
    DWORD               dwFlags;
    DWORD               cTlsParameters;
    PTLS_PARAMETERS     pTlsParameters;
} SCH_CREDENTIALS, * PSCH_CREDENTIALS;

typedef struct _TLS_EXTENSION_SUBSCRIPTION
{
    WORD ExtensionType; // Code point of extension.
    WORD HandshakeType; // Message type used to transport extension.
} TLS_EXTENSION_SUBSCRIPTION, * PTLS_EXTENSION_SUBSCRIPTION;

typedef struct _SUBSCRIBE_GENERIC_TLS_EXTENSION
{
    DWORD Flags;                                                // Flags used to modify behavior. Must be zero.
    DWORD SubscriptionsCount;                                   // Number of elements in the Subscriptions array.
    TLS_EXTENSION_SUBSCRIPTION Subscriptions[ANYSIZE_ARRAY];    // Array of TLS_EXTENSION_SUBSCRIPTION structures.
} SUBSCRIBE_GENERIC_TLS_EXTENSION, * PSUBSCRIBE_GENERIC_TLS_EXTENSION;

// Flag values for SecPkgContext_SessionInfo
#define SSL_SESSION_RECONNECT   1

typedef struct _SecPkgContext_SessionInfo
{
    DWORD dwFlags;
    DWORD cbSessionId;
    BYTE  rgbSessionId[32];
} SecPkgContext_SessionInfo, * PSecPkgContext_SessionInfo;

#define SECPKG_ATTR_SESSION_INFO         0x5d   // returns SecPkgContext_SessionInfo
#define SECPKG_ATTR_CERT_CHECK_RESULT_INPROC 0x72 // returns SecPkgContext_CertificateValidationResult, use only after SSPI handshake loop
#define SECPKG_ATTR_SESSION_TICKET_KEYS      0x73 // sets    SecPkgCred_SessionTicketKeys

typedef unsigned int ALG_ID;

typedef struct _SecPkgContext_CipherInfo
{
    DWORD dwVersion;
    DWORD dwProtocol;
    DWORD dwCipherSuite;
    DWORD dwBaseCipherSuite;
    WCHAR szCipherSuite[SZ_ALG_MAX_SIZE];
    WCHAR szCipher[SZ_ALG_MAX_SIZE];
    DWORD dwCipherLen;
    DWORD dwCipherBlockLen;    // in bytes
    WCHAR szHash[SZ_ALG_MAX_SIZE];
    DWORD dwHashLen;
    WCHAR szExchange[SZ_ALG_MAX_SIZE];
    DWORD dwMinExchangeLen;
    DWORD dwMaxExchangeLen;
    WCHAR szCertificate[SZ_ALG_MAX_SIZE];
    DWORD dwKeyType;
} SecPkgContext_CipherInfo, * PSecPkgContext_CipherInfo;

typedef struct _SecPkgContext_ConnectionInfo
{
    DWORD   dwProtocol;
    ALG_ID  aiCipher;
    DWORD   dwCipherStrength;
    ALG_ID  aiHash;
    DWORD   dwHashStrength;
    ALG_ID  aiExch;
    DWORD   dwExchStrength;
} SecPkgContext_ConnectionInfo, * PSecPkgContext_ConnectionInfo;

#define SECPKG_ATTR_CIPHER_INFO          0x64   // returns new CNG SecPkgContext_CipherInfo
#define SECPKG_ATTR_CONNECTION_INFO      0x5a   // returns SecPkgContext_ConnectionInfo

#else

#define SCHANNEL_USE_BLACKLISTS

#if (defined(QUIC_GAMECORE_BUILD))
#include <sdkddkver.h>
#ifdef NTDDI_WIN10_CO
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
#endif
#endif

#include <schannel.h>

#ifndef SCH_CRED_DEFERRED_CRED_VALIDATION
#define SCH_CRED_DEFERRED_CRED_VALIDATION            0x04000000
typedef struct _SecPkgContext_CertificateValidationResult
{
    DWORD dwChainErrorStatus;    // Contains chain build error flags set by CertGetCertificateChain.
    HRESULT hrVerifyChainStatus; // Certificate validation policy error returned by CertVerifyCertificateChainPolicy.
} SecPkgContext_CertificateValidationResult, *PSecPkgContext_CertificateValidationResult;
#define SECPKG_ATTR_CERT_CHECK_RESULT_INPROC 0x72 // returns SecPkgContext_CertificateValidationResult, use only after SSPI handshake loop
#endif // SCH_CRED_DEFERRED_CRED_VALIDATION

#ifndef SECPKG_ATTR_SESSION_TICKET_KEYS
#define SECPKG_ATTR_SESSION_TICKET_KEYS      0x73 // sets    SecPkgCred_SessionTicketKeys
// Session ticket protection version definitions.
#define SESSION_TICKET_INFO_V0 0
#define SESSION_TICKET_INFO_VERSION SESSION_TICKET_INFO_V0
typedef struct _SecPkgCred_SessionTicketKey
{
    DWORD   TicketInfoVersion;      // Set to SESSION_TICKET_INFO_VERSION for the current session ticket protection method.
    BYTE    KeyId[16];              // Uniquely identifies each session ticket key issued by a TLS server.
    BYTE    KeyingMaterial[64];     // Must be generated using a cryptographic RNG.
    BYTE    KeyingMaterialSize;     // Size in bytes of the keying material in the KeyingMaterial array. Must be between 32 and 64.
} SecPkgCred_SessionTicketKey, *PSecPkgCred_SessionTicketKey;
typedef struct _SecPkgCred_SessionTicketKeys
{
    DWORD                           cSessionTicketKeys; // Up to 16 keys.
    PSecPkgCred_SessionTicketKey    pSessionTicketKeys;
} SecPkgCred_SessionTicketKeys, *PSecPkgCred_SessionTicketKeys;
#endif // SECPKG_ATTR_SESSION_TICKET_KEYS

#endif

#ifndef SECPKG_ATTR_CLIENT_CERT_POLICY
#define SECPKG_ATTR_CLIENT_CERT_POLICY   0x60   // sets    SecPkgCred_ClientCertCtlPolicy
#endif

//
// Defines until BCrypt.h updates
//
#ifndef BCRYPT_CHACHA20_POLY1305_ALGORITHM
#define BCRYPT_CHACHA20_POLY1305_ALGORITHM L"CHACHA20_POLY1305"
#endif

extern BCRYPT_ALG_HANDLE CXPLAT_CHACHA20_POLY1305_ALG_HANDLE;

uint16_t CxPlatTlsTPHeaderSize = FIELD_OFFSET(SEND_GENERIC_TLS_EXTENSION, Buffer);

#define SecTrafficSecret_ClientEarlyData (SecTrafficSecret_Server + 1) // Hack to have my layer support 0-RTT

#define SEC_TRAFFIC_SECRETS_COUNT       4
#define MAX_SEC_TRAFFIC_SECRET_SIZE     0x40 // Fits all known current and future algorithms

#define MAX_SEC_TRAFFIC_SECRETS_SIZE \
    (sizeof(SEC_TRAFFIC_SECRETS) + MAX_SEC_TRAFFIC_SECRET_SIZE)

const WORD TlsHandshake_ClientHello = 0x01;
const WORD TlsHandshake_EncryptedExtensions = 0x08;

// {791A59D6-34C8-4ADE-9B53-D13EEA4E9F0B}
static const GUID CxPlatTlsClientCertPolicyGuid =
{
    0x791a59d6,
    0x34c8,
    0x4ade,
    { 0x9b, 0x53, 0xd1, 0x3e, 0xea, 0x4e, 0x9f, 0xb }
};

#ifndef TLS1_ALERT_CLOSE_NOTIFY
#define TLS1_ALERT_CLOSE_NOTIFY 0
#endif

#ifndef TLS1_ALERT_CERTIFICATE_REQUIRED
#define TLS1_ALERT_CERTIFICATE_REQUIRED 116
#endif

typedef struct CXPLAT_SEC_CONFIG {

    //
    // Acquired credential handle.
    //
    CredHandle CredentialHandle;

    //
    // Credential flags used to acquire the handle.
    //
    QUIC_CREDENTIAL_FLAGS Flags;

    //
    // Callbacks for TLS.
    //
    CXPLAT_TLS_CALLBACKS Callbacks;

#ifdef _KERNEL_MODE
    //
    // Impersonation token from the original call to initialize.
    //
    PACCESS_TOKEN ImpersonationToken;
    BOOLEAN IsPrimaryToken;
    BOOLEAN CopyOnOpen;
    BOOLEAN EffectiveOnly;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
#endif // _KERNEL_MODE

} CXPLAT_SEC_CONFIG;

typedef struct QUIC_ACH_CONTEXT {

    //
    // Credential flags used to acquire the handle.
    //
    QUIC_CREDENTIAL_CONFIG CredConfig;

    //
    // Context for the completion callback.
    //
    void* CompletionContext;

    //
    // Caller-registered callback to signal credential acquisition is complete.
    //
    CXPLAT_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionCallback;

#ifdef _KERNEL_MODE
    //
    // Async call context.
    //
    SspiAsyncContext* SspiContext;

    //
    // Principal string, stored here to ensure it's alive as long as the async
    // call needs it.
    //
    UNICODE_STRING Principal;

    //
    // Used to wait on the async callback, when in synchronous mode.
    //
    KEVENT CompletionEvent;

    //
    // The status received from the completion callback.
    //
    NTSTATUS CompletionStatus;
#endif

    //
    // CredConfig certificate hash used to find the server certificate.
    //
    SCHANNEL_CERT_HASH_STORE CertHash;

    //
    // Security config to pass back to the caller.
    //
    CXPLAT_SEC_CONFIG* SecConfig;

    //
    // Holds the credentials configuration for the lifetime of the ACH call.
    //
    SCH_CREDENTIALS Credentials;

    //
    // Holds TLS configuration for the lifetime of the ACH call.
    //
    TLS_PARAMETERS TlsParameters;

    //
    // Holds the blocked algorithms for the lifetime of the ACH call.
    //
    CRYPTO_SETTINGS CryptoSettings[4];

    //
    // Holds the list of blocked chaining modes for the lifetime of the ACH call.
    //
    UNICODE_STRING BlockedChainingModes[1];

} QUIC_ACH_CONTEXT;

typedef struct _SEC_BUFFER_WORKSPACE {

    //
    // Used to pass additional flags to Schannel.
    //
    SEC_FLAGS InSecFlags;

    //
    // Space for the output traffic secrets generated by Schannel.
    //
    uint8_t OutTrafSecBuf[SEC_TRAFFIC_SECRETS_COUNT*MAX_SEC_TRAFFIC_SECRETS_SIZE];

    //
    // Input sec buffers to pass to Schannel.
    //
    SecBuffer InSecBuffers[7];

    //
    // Output sec buffers to get data produced by Schannel.
    //
    SecBuffer OutSecBuffers[7];

} SEC_BUFFER_WORKSPACE;

typedef struct CXPLAT_TLS {

    BOOLEAN IsServer : 1;
    BOOLEAN GeneratedFirstPayload : 1;
    BOOLEAN PeerTransportParamsReceived : 1;
    BOOLEAN HandshakeKeyRead : 1;
    BOOLEAN ApplicationKeyRead : 1;

    //
    // The TLS extension type for the QUIC transport parameters.
    //
    uint16_t QuicTpExtType;

    //
    // Cached server name indication.
    //
    const char* SNI;

    //
    // Schannel-allocated context for use between calls.
    //
    CtxtHandle SchannelContext;

    //
    // SecurityConfig information for this TLS stream.
    //
    CXPLAT_SEC_CONFIG* SecConfig;

    //
    // Labels for deriving key material.
    //
    const QUIC_HKDF_LABELS* HkdfLabels;

    SEC_APPLICATION_PROTOCOLS* ApplicationProtocols;

    ULONG AppProtocolsSize;

    //
    // Schannel encoded TLS extension buffer for QUIC TP.
    //
    SEND_GENERIC_TLS_EXTENSION* TransportParams;

    //
    // Callback context and handler for QUIC TP.
    //
    QUIC_CONNECTION* Connection;

    //
    // Workspace for sec buffers pass into ISC/ASC.
    //
    SEC_BUFFER_WORKSPACE Workspace;

    //
    // Peer Transport parameters length.
    //
    uint32_t PeerTransportParamsLength;

    //
    // Peer transport parameters for when heavy fragmentation doesn't
    // provide enough storage for the peer transport parameters.
    //
    uint8_t* PeerTransportParams;

    //
    // Optional struct to log TLS traffic secrets.
    // Only non-null when the connection is configured to log these.
    //
    QUIC_TLS_SECRETS* TlsSecrets;

} CXPLAT_TLS;

_Success_(return==TRUE)
BOOLEAN
QuicPacketKeyCreate(
    _Inout_ CXPLAT_TLS* TlsContext,
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _In_z_ const char* const SecretName,
    _In_ const SEC_TRAFFIC_SECRETS* TrafficSecrets,
    _Out_ QUIC_PACKET_KEY** Key
    );

#define SecStatusToQuicStatus(x) (QUIC_STATUS)(x)

#ifdef _KERNEL_MODE

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsUtf8ToUnicodeString(
    _In_z_ const char* Input,
    _Inout_ PUNICODE_STRING Output,
    _In_ uint32_t Tag
    )
{
    CXPLAT_DBG_ASSERT(Input != NULL);
    CXPLAT_DBG_ASSERT(Output != NULL);

    QUIC_STATUS Status;
    ULONG RequiredSize = 0;
    PWSTR UnicodeString = NULL;

    size_t InputLength = strnlen_s(Input, QUIC_MAX_SNI_LENGTH + 1);
    if (InputLength == QUIC_MAX_SNI_LENGTH + 1) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }
    InputLength++;

    Status =
        RtlUTF8ToUnicodeN(
            UnicodeString,
            RequiredSize,
            &RequiredSize,
            Input,
            (ULONG) InputLength);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Get unicode string size");
        goto Error;
    }

    UnicodeString = CXPLAT_ALLOC_NONPAGED(RequiredSize, Tag);
    if (UnicodeString == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "unicode string",
            RequiredSize);
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    Status =
        RtlUTF8ToUnicodeN(
            UnicodeString,
            RequiredSize,
            &RequiredSize,
            Input,
            (ULONG) InputLength);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Convert string to unicode");
        goto Error;
    }

    CXPLAT_DBG_ASSERT(Output->Buffer == NULL);
    Output->Buffer = UnicodeString;
    UnicodeString = NULL;

    Output->MaximumLength = (USHORT)RequiredSize;
    Output->Length = Output->MaximumLength - sizeof(WCHAR);

Error:
    if (UnicodeString != NULL) {
        CXPLAT_FREE(UnicodeString, Tag);
        UnicodeString = NULL;
    }
    return Status;
}

#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsSetClientCertPolicy(
    _In_ CXPLAT_SEC_CONFIG* SecConfig
    )
{
    SECURITY_STATUS SecStatus = SEC_E_OK;
    SecPkgCred_ClientCertPolicy ClientCertPolicy;
    CXPLAT_DBG_ASSERT(!(SecConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT));

    CxPlatZeroMemory(&ClientCertPolicy, sizeof(ClientCertPolicy));

    ClientCertPolicy.guidPolicyId = CxPlatTlsClientCertPolicyGuid;

    if (SecConfig->Flags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_END_CERT) {
        ClientCertPolicy.dwCertFlags |= CERT_CHAIN_REVOCATION_CHECK_END_CERT;
    }
    if (SecConfig->Flags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN) {
        ClientCertPolicy.dwCertFlags |= CERT_CHAIN_REVOCATION_CHECK_CHAIN;
    }
    if (SecConfig->Flags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT) {
        ClientCertPolicy.dwCertFlags |= CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
    }
    if (SecConfig->Flags & QUIC_CREDENTIAL_FLAG_CACHE_ONLY_URL_RETRIEVAL) {
        ClientCertPolicy.dwCertFlags |= CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL;
    }
    if (SecConfig->Flags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CACHE_ONLY) {
        ClientCertPolicy.dwCertFlags |= CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY;
    }

    SecStatus =
        SetCredentialsAttributesW(
            &SecConfig->CredentialHandle,
            SECPKG_ATTR_CLIENT_CERT_POLICY,
            &ClientCertPolicy,
            sizeof(ClientCertPolicy));

    if (SecStatus != SEC_E_OK) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SecStatus,
            "SetCredentialsAttributesW(SECPKG_ATTR_CLIENT_CERT_POLICY) failed");
    }

    return SecStatusToQuicStatus(SecStatus);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
__drv_allocatesMem(Mem)
_Must_inspect_result_
_Success_(return != NULL)
QUIC_ACH_CONTEXT*
CxPlatTlsAllocateAchContext(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _In_opt_ void* Context,
    _In_ CXPLAT_SEC_CONFIG_CREATE_COMPLETE_HANDLER Callback
    )
{
    QUIC_ACH_CONTEXT* AchContext = CXPLAT_ALLOC_NONPAGED(sizeof(QUIC_ACH_CONTEXT), QUIC_POOL_TLS_ACHCTX);
    if (AchContext == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_ACH_CONTEXT",
            sizeof(QUIC_ACH_CONTEXT));
    } else {
        RtlZeroMemory(AchContext, sizeof(*AchContext));
        AchContext->CredConfig = *CredConfig;
        AchContext->CompletionContext = Context;
        AchContext->CompletionCallback = Callback;
        AchContext->TlsParameters.pDisabledCrypto = AchContext->CryptoSettings;
        AchContext->TlsParameters.cDisabledCrypto = 2; // initialized to the basic blocked cipher suites.
        AchContext->Credentials.pTlsParameters = &AchContext->TlsParameters;
        AchContext->Credentials.cTlsParameters = 1;
#ifdef _KERNEL_MODE
        if (!(AchContext->CredConfig.Flags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS)) {
            KeInitializeEvent(&AchContext->CompletionEvent, NotificationEvent, FALSE);
        }
#endif
    }

    return AchContext;
}

void
CxPlatTlsFreeAchContext(
    _In_ QUIC_ACH_CONTEXT* AchContext
    )
{
#ifdef _KERNEL_MODE
    if (AchContext->Principal.Buffer != NULL) {
        CXPLAT_FREE(AchContext->Principal.Buffer, QUIC_POOL_TLS_PRINCIPAL);
        RtlZeroMemory(&AchContext->Principal, sizeof(AchContext->Principal));
    }
    if (AchContext->SspiContext != NULL) {
        SspiFreeAsyncContext(AchContext->SspiContext);
    }
#endif
    if (AchContext->SecConfig != NULL) {
        CxPlatTlsSecConfigDelete(AchContext->SecConfig);
    }
    CXPLAT_FREE(AchContext, QUIC_POOL_TLS_ACHCTX);
}

#ifdef _KERNEL_MODE

void
CxPlatTlsSspiNotifyCallback(
    _In_ SspiAsyncContext* Handle,
    _In_opt_ void* CallbackData
    )
{
    if (CallbackData == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "NULL CallbackData to CxPlatTlsSspiNotifyCallback");
        return;
    }
    QUIC_ACH_CONTEXT* AchContext = CallbackData;
    BOOLEAN IsAsync = !!(AchContext->CredConfig.Flags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS);
    CXPLAT_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionCallback = AchContext->CompletionCallback;
    void* CompletionContext = AchContext->CompletionContext;
    CXPLAT_SEC_CONFIG* SecConfig = AchContext->SecConfig;
    AchContext->SecConfig = NULL;
    SECURITY_STATUS Status = SspiGetAsyncCallStatus(Handle);
    AchContext->CompletionStatus = SecStatusToQuicStatus(Status);
    QUIC_CREDENTIAL_CONFIG CredConfig = AchContext->CredConfig;
    if (IsAsync) {
        CxPlatTlsFreeAchContext(AchContext);
    }
    if (Status != SEC_E_OK) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Completion for SspiAcquireCredentialsHandleAsyncW");
        CompletionCallback(&CredConfig, CompletionContext, SecStatusToQuicStatus(Status), NULL);
        CxPlatTlsSecConfigDelete(SecConfig); // *MUST* be last call to prevent crash in platform cleanup.
    } else {
        Status = (SECURITY_STATUS)QUIC_STATUS_SUCCESS;
        if (SecConfig->Flags & QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION) {
            Status = (SECURITY_STATUS)CxPlatTlsSetClientCertPolicy(SecConfig);
        }
        CompletionCallback(&CredConfig, CompletionContext, (QUIC_STATUS)Status, SecConfig);
    }
    if (!IsAsync) {
        KeSetEvent(&AchContext->CompletionEvent, IO_NO_INCREMENT, FALSE);
    }
}

const static UNICODE_STRING CxPlatTlsPackageName = RTL_CONSTANT_STRING(L"Schannel");

typedef struct TLS_WORKER_CONTEXT {
    NTSTATUS CompletionStatus;
    QUIC_ACH_CONTEXT* AchContext;
} TLS_WORKER_CONTEXT;

_IRQL_requires_same_
void
CxPlatTlsAchHelper(
    _In_ TLS_WORKER_CONTEXT* ThreadContext
    )
{
    QUIC_ACH_CONTEXT* AchContext = ThreadContext->AchContext;
    BOOLEAN IsClient = !!(AchContext->CredConfig.Flags & QUIC_CREDENTIAL_FLAG_CLIENT);
    BOOLEAN IsAsync = !!(AchContext->CredConfig.Flags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS);

    QuicTraceLogVerbose(
        SchannelAchAsync,
        "[ tls] Calling SspiAcquireCredentialsHandleAsyncW");

    SECURITY_STATUS SecStatus =
        SspiAcquireCredentialsHandleAsyncW(
            AchContext->SspiContext,
            IsClient ? NULL : &AchContext->Principal,
            (PSECURITY_STRING)&CxPlatTlsPackageName,
            IsClient ? SECPKG_CRED_OUTBOUND : SECPKG_CRED_INBOUND,
            NULL,
            &AchContext->Credentials,
            NULL,
            NULL,
            &AchContext->SecConfig->CredentialHandle,
            NULL);
    if (SecStatus != SEC_E_OK) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SecStatus,
            "SspiAcquireCredentialsHandleAsyncW");
        ThreadContext->CompletionStatus = SecStatusToQuicStatus(SecStatus);

    } else {
        if (IsAsync) {
            ThreadContext->CompletionStatus = QUIC_STATUS_PENDING;
            ThreadContext->AchContext = NULL;
        } else {
            KeWaitForSingleObject(&AchContext->CompletionEvent, Executive, KernelMode, FALSE, NULL);
            ThreadContext->CompletionStatus = AchContext->CompletionStatus;
        }
    }
}

_Function_class_(KSTART_ROUTINE)
_IRQL_requires_same_
void
CxPlatTlsAchWorker(
    _In_ void* Context
    )
{
    TLS_WORKER_CONTEXT* ThreadContext = Context;
    CxPlatTlsAchHelper(ThreadContext);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsSecConfigCreate(
    _In_ const QUIC_CREDENTIAL_CONFIG* CredConfig,
    _In_ CXPLAT_TLS_CREDENTIAL_FLAGS TlsCredFlags,
    _In_ const CXPLAT_TLS_CALLBACKS* TlsCallbacks,
    _In_opt_ void* Context,
    _In_ CXPLAT_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler
    )
{
    CXPLAT_DBG_ASSERT(CredConfig && CompletionHandler);

    SECURITY_STATUS SecStatus;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    BOOLEAN IsClient = !!(CredConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT);

    if (CredConfig->Reserved != NULL) {
        return QUIC_STATUS_INVALID_PARAMETER; // Not currently used and should be NULL.
    }

#ifndef _KERNEL_MODE
    PCERT_CONTEXT CertContext = NULL;

    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }
#endif

    if ((CredConfig->Flags & QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION) &&
        !(CredConfig->Flags & QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED)) {
        return QUIC_STATUS_INVALID_PARAMETER; // Defer validation without indication doesn't make sense.
    }

    if (IsClient) {
        if ((CredConfig->Flags & QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION) ||
            (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_SYSTEM_MAPPER)) {
            return QUIC_STATUS_INVALID_PARAMETER; // Client authentication is a server-only flag.
        }
    } else {
        if ((CredConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_SUPPLIED_CREDENTIALS)) {
            return QUIC_STATUS_INVALID_PARAMETER; // Using supplied credentials is a client-only flag.
        }
    }

    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_TLS_BUILTIN_CERTIFICATE_VALIDATION) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

#ifdef _KERNEL_MODE
    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES) {
       return QUIC_STATUS_NOT_SUPPORTED;    // Not supported in kernel mode.
    }
#endif

    switch (CredConfig->Type) {
    case QUIC_CREDENTIAL_TYPE_NONE:
        if (!IsClient) {
            return QUIC_STATUS_INVALID_PARAMETER; // Server requires a certificate.
        }
        break;
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH:
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE:
#ifndef _KERNEL_MODE
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT:
#endif
        if (CredConfig->CertificateContext == NULL && CredConfig->Principal == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        break;
#ifdef _KERNEL_MODE
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT:
#endif
    case QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE:
    default:
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES &&
        ((CredConfig->AllowedCipherSuites &
            (QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256 |
            QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384)) == 0 ||
        (CredConfig->AllowedCipherSuites & QUIC_ALLOWED_CIPHER_SUITE_CHACHA20_POLY1305_SHA256))) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            CredConfig->AllowedCipherSuites,
            "No valid cipher suites presented");
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    QUIC_ACH_CONTEXT* AchContext =
        CxPlatTlsAllocateAchContext(
            CredConfig,
            Context,
            CompletionHandler);
    if (AchContext == NULL) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

#pragma prefast(suppress: __WARNING_6014, "Memory is correctly freed (CxPlatTlsSecConfigDelete)")
    AchContext->SecConfig = CXPLAT_ALLOC_NONPAGED(sizeof(CXPLAT_SEC_CONFIG), QUIC_POOL_TLS_SECCONF);
    if (AchContext->SecConfig == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_SEC_CONFIG",
            sizeof(CXPLAT_SEC_CONFIG));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    RtlZeroMemory(AchContext->SecConfig, sizeof(CXPLAT_SEC_CONFIG));
    SecInvalidateHandle(&AchContext->SecConfig->CredentialHandle);
    AchContext->SecConfig->Flags = CredConfig->Flags;
    AchContext->SecConfig->Callbacks = *TlsCallbacks;

    PSCH_CREDENTIALS Credentials = &AchContext->Credentials;

    Credentials->dwVersion = SCH_CREDENTIALS_VERSION;
    Credentials->dwFlags |= SCH_USE_STRONG_CRYPTO;
    if (CredConfig->Flags & (QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION)) {
        Credentials->dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
    }
    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_ENABLE_OCSP) {
        Credentials->dwFlags |= SCH_CRED_SNI_ENABLE_OCSP;
    }
    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION && IsClient) {
        Credentials->dwFlags |= SCH_CRED_DEFERRED_CRED_VALIDATION;
    }
    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_END_CERT) {
        Credentials->dwFlags |= SCH_CRED_REVOCATION_CHECK_END_CERT;
    }
    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN) {
        Credentials->dwFlags |= SCH_CRED_REVOCATION_CHECK_CHAIN;
    }
    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT) {
        Credentials->dwFlags |= SCH_CRED_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;
    }
    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_IGNORE_NO_REVOCATION_CHECK) {
        Credentials->dwFlags |= SCH_CRED_IGNORE_NO_REVOCATION_CHECK;
    }
    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_IGNORE_REVOCATION_OFFLINE) {
        Credentials->dwFlags |= SCH_CRED_IGNORE_REVOCATION_OFFLINE;
    }
    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_CACHE_ONLY_URL_RETRIEVAL) {
        Credentials->dwFlags |= SCH_CRED_CACHE_ONLY_URL_RETRIEVAL;
    }
    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_REVOCATION_CHECK_CACHE_ONLY) {
        Credentials->dwFlags |= SCH_CRED_REVOCATION_CHECK_CACHE_ONLY;
    }
    if (IsClient) {
        Credentials->dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
        Credentials->pTlsParameters->grbitDisabledProtocols = (DWORD)~SP_PROT_TLS1_3_CLIENT;
    } else {
        if (!(CredConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_SYSTEM_MAPPER)) {
            Credentials->dwFlags |= SCH_CRED_NO_SYSTEM_MAPPER;
        }
        Credentials->pTlsParameters->grbitDisabledProtocols = (DWORD)~SP_PROT_TLS1_3_SERVER;
        if (TlsCredFlags & CXPLAT_TLS_CREDENTIAL_FLAG_DISABLE_RESUMPTION) {
            Credentials->dwFlags |= SCH_CRED_DISABLE_RECONNECTS;
        }
    }
    //
    //  Disallow ChaCha20-Poly1305 until full support is possible.
    //
    uint8_t CryptoSettingsIdx = 0;
    AchContext->CryptoSettings[CryptoSettingsIdx].eAlgorithmUsage = TlsParametersCngAlgUsageCipher;
    AchContext->CryptoSettings[CryptoSettingsIdx].strCngAlgId = (UNICODE_STRING){
        sizeof(BCRYPT_CHACHA20_POLY1305_ALGORITHM),
        sizeof(BCRYPT_CHACHA20_POLY1305_ALGORITHM),
        BCRYPT_CHACHA20_POLY1305_ALGORITHM};
    CryptoSettingsIdx++;

    //
    // Disallow AES_CCM algorithm, since there's no support for it yet.
    // and also disallows AES_CCM_8, which is undefined per QUIC spec.
    //
    AchContext->BlockedChainingModes[0] = (UNICODE_STRING){
        sizeof(BCRYPT_CHAIN_MODE_CCM),
        sizeof(BCRYPT_CHAIN_MODE_CCM),
        BCRYPT_CHAIN_MODE_CCM};

    AchContext->CryptoSettings[CryptoSettingsIdx].eAlgorithmUsage = TlsParametersCngAlgUsageCipher;
    AchContext->CryptoSettings[CryptoSettingsIdx].rgstrChainingModes = AchContext->BlockedChainingModes;
    AchContext->CryptoSettings[CryptoSettingsIdx].cChainingModes = ARRAYSIZE(AchContext->BlockedChainingModes);
    AchContext->CryptoSettings[CryptoSettingsIdx].strCngAlgId = (UNICODE_STRING){
        sizeof(BCRYPT_AES_ALGORITHM),
        sizeof(BCRYPT_AES_ALGORITHM),
        BCRYPT_AES_ALGORITHM};
    CryptoSettingsIdx++;

    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES) {
        QUIC_ALLOWED_CIPHER_SUITE_FLAGS DisallowedCipherSuites = ~CredConfig->AllowedCipherSuites;

        if (DisallowedCipherSuites & QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384 &&
            DisallowedCipherSuites & QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256) {
            QuicTraceEvent(
                LibraryError,
                "[ lib] ERROR, %s.",
                "No Allowed TLS Cipher Suites");
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Error;
        }

        if (DisallowedCipherSuites & QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384) {
            AchContext->CryptoSettings[CryptoSettingsIdx].eAlgorithmUsage = TlsParametersCngAlgUsageCipher;
            AchContext->CryptoSettings[CryptoSettingsIdx].strCngAlgId = (UNICODE_STRING){
                sizeof(BCRYPT_AES_ALGORITHM),
                sizeof(BCRYPT_AES_ALGORITHM),
                BCRYPT_AES_ALGORITHM};
            AchContext->CryptoSettings[CryptoSettingsIdx].dwMaxBitLength = 128;
            AchContext->CryptoSettings[CryptoSettingsIdx].dwMinBitLength = 128;
            CryptoSettingsIdx++;

            AchContext->CryptoSettings[CryptoSettingsIdx].eAlgorithmUsage = TlsParametersCngAlgUsageDigest;
            AchContext->CryptoSettings[CryptoSettingsIdx].strCngAlgId = (UNICODE_STRING){
                sizeof(BCRYPT_SHA384_ALGORITHM),
                sizeof(BCRYPT_SHA384_ALGORITHM),
                BCRYPT_SHA384_ALGORITHM};
            CryptoSettingsIdx++;
        }
        if (DisallowedCipherSuites & QUIC_ALLOWED_CIPHER_SUITE_AES_128_GCM_SHA256) {
            AchContext->CryptoSettings[CryptoSettingsIdx].eAlgorithmUsage = TlsParametersCngAlgUsageCipher;
            AchContext->CryptoSettings[CryptoSettingsIdx].strCngAlgId = (UNICODE_STRING){
                sizeof(BCRYPT_AES_ALGORITHM),
                sizeof(BCRYPT_AES_ALGORITHM),
                BCRYPT_AES_ALGORITHM};
            AchContext->CryptoSettings[CryptoSettingsIdx].dwMaxBitLength = 256;
            AchContext->CryptoSettings[CryptoSettingsIdx].dwMinBitLength = 256;
            CryptoSettingsIdx++;

            AchContext->CryptoSettings[CryptoSettingsIdx].eAlgorithmUsage = TlsParametersCngAlgUsageDigest;
            AchContext->CryptoSettings[CryptoSettingsIdx].strCngAlgId = (UNICODE_STRING){
                sizeof(BCRYPT_SHA256_ALGORITHM),
                sizeof(BCRYPT_SHA256_ALGORITHM),
                BCRYPT_SHA256_ALGORITHM};
            CryptoSettingsIdx++;
        }
    }

    AchContext->TlsParameters.cDisabledCrypto = CryptoSettingsIdx;


#ifdef _KERNEL_MODE
    if (IsClient && CredConfig->Type == QUIC_CREDENTIAL_TYPE_NONE) {
        //
        // Plain client with no certificate.
        //

    } else if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH) {
        CXPLAT_DBG_ASSERT(CredConfig->CertificateHash != NULL);

        QUIC_CERTIFICATE_HASH* CertHash = CredConfig->CertificateHash;
        AchContext->CertHash.dwLength = sizeof(AchContext->CertHash);
        AchContext->CertHash.dwFlags |= SCH_MACHINE_CERT_HASH;
        AchContext->CertHash.hProv = 0;

        RtlCopyMemory(
            AchContext->CertHash.ShaHash,
            CertHash->ShaHash,
            sizeof(AchContext->CertHash.ShaHash));

        //
        // Assume the Machine MY store if unspecified.
        //
        RtlCopyMemory(AchContext->CertHash.pwszStoreName, L"MY", sizeof(L"MY"));

        Credentials->cCreds = 1;
        Credentials->paCred = (PVOID)&AchContext->CertHash;
        Credentials->dwCredFormat = SCH_CRED_FORMAT_CERT_HASH_STORE;
        Credentials->dwFlags |= SCH_MACHINE_CERT_HASH;

    } else if (CredConfig->Type == QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE) {
        CXPLAT_DBG_ASSERT(CredConfig->CertificateHashStore != NULL);

        QUIC_CERTIFICATE_HASH_STORE* CertHashStore = CredConfig->CertificateHashStore;
        AchContext->CertHash.dwLength = sizeof(AchContext->CertHash);
        if (CertHashStore->Flags & QUIC_CERTIFICATE_HASH_STORE_FLAG_MACHINE_STORE) {
            AchContext->CertHash.dwFlags |= SCH_MACHINE_CERT_HASH;
        }
        RtlCopyMemory(
            AchContext->CertHash.ShaHash,
            &(CertHashStore->ShaHash),
            sizeof(AchContext->CertHash.ShaHash));

#pragma warning(push)
#pragma warning(disable:6387) // Parameter 3 is allowed to be NULL when the value isn't wanted.
#pragma warning(disable:6385) // SAL ignores the annotations on strnlen_s because of the (ULONG) cast. Probably.
        Status =
            RtlUTF8ToUnicodeN(
                AchContext->CertHash.pwszStoreName,
                sizeof(AchContext->CertHash.pwszStoreName),
                NULL,
                CertHashStore->StoreName,
                (ULONG)strnlen_s(
                    CertHashStore->StoreName,
                    sizeof(CertHashStore->StoreName)));
#pragma warning(pop)
        if (!NT_SUCCESS(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "Convert cert store name to unicode");
            goto Error;
        }

        Credentials->cCreds = 1;
        Credentials->paCred = (PVOID)&AchContext->CertHash;
        Credentials->dwCredFormat = SCH_CRED_FORMAT_CERT_HASH_STORE;
        Credentials->dwFlags |= SCH_MACHINE_CERT_HASH;

    } else if (CredConfig->Principal != NULL) {
        //
        // No certificate hashes present, only use Principal.
        //

    } else {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Invalid flags passed in to CxPlatTlsSecConfigCreate");
        goto Error;
    }

    if (CredConfig->Principal != NULL) {

        Status = CxPlatTlsUtf8ToUnicodeString(CredConfig->Principal, &AchContext->Principal, QUIC_POOL_TLS_PRINCIPAL);
        if (!NT_SUCCESS(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "Convert principal to unicode");
            goto Error;
        }

        Credentials->dwFlags |= SCH_CRED_SNI_CREDENTIAL;
    }
#else

    if (CredConfig->Type != QUIC_CREDENTIAL_TYPE_NONE) {
        Status = CxPlatCertCreate(CredConfig, &CertContext);
        if (QUIC_FAILED(Status)) {
            QuicTraceEvent(
                LibraryErrorStatus,
                "[ lib] ERROR, %u, %s.",
                Status,
                "CxPlatCertCreate");
            goto Error;
        }

        Credentials->cCreds = 1;
        Credentials->paCred = &CertContext;

    } else {
        CXPLAT_DBG_ASSERT(IsClient);
        Credentials->cCreds = 0;
        Credentials->paCred = NULL;
    }
#endif

#ifdef _KERNEL_MODE

    //
    // Kernel-mode only code path.
    //

    AchContext->SspiContext = SspiCreateAsyncContext();
    if (AchContext->SspiContext == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "SspiCreateAsyncContext");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    SecStatus =
        SspiSetAsyncNotifyCallback(
            AchContext->SspiContext,
            CxPlatTlsSspiNotifyCallback,
            AchContext);
    if (SecStatus != SEC_E_OK) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SecStatus,
            "SspiSetAsyncNotifyCallback");
        Status = SecStatusToQuicStatus(SecStatus);
        goto Error;
    }

    CXPLAT_DBG_ASSERT(AchContext->SecConfig != NULL);
    AchContext->SecConfig->ImpersonationToken =
        PsReferenceImpersonationToken(
            PsGetCurrentThread(),
            &AchContext->SecConfig->CopyOnOpen,
            &AchContext->SecConfig->EffectiveOnly,
            &AchContext->SecConfig->ImpersonationLevel);

    if (AchContext->SecConfig->ImpersonationToken == NULL) {
        AchContext->SecConfig->ImpersonationToken =
            PsReferencePrimaryToken(
                PsGetCurrentProcess());
        AchContext->SecConfig->IsPrimaryToken = TRUE;
    }

    QuicTraceLogVerbose(
        SchannelAchWorkerStart,
        "[ tls] Starting ACH worker");

    TLS_WORKER_CONTEXT ThreadContext = { STATUS_SUCCESS, AchContext };
    CxPlatTlsAchHelper(&ThreadContext);

    Status = ThreadContext.CompletionStatus;
    AchContext = ThreadContext.AchContext;

#else // !_KERNEL_MODE

    QuicTraceLogVerbose(
        SchannelAch,
        "[ tls] Calling AcquireCredentialsHandleW");

    SecStatus =
        AcquireCredentialsHandleW(
            NULL,
            UNISP_NAME_W,
            IsClient ? SECPKG_CRED_OUTBOUND : SECPKG_CRED_INBOUND,
            NULL,
            Credentials,
            NULL,
            NULL,
            &AchContext->SecConfig->CredentialHandle,
            NULL);
    if (SecStatus != SEC_E_OK) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SecStatus,
            "AcquireCredentialsHandleW");
        Status = SecStatusToQuicStatus(SecStatus);
        goto Error;
    }

    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION) {
        Status = CxPlatTlsSetClientCertPolicy(AchContext->SecConfig);
    }

    QuicTraceLogVerbose(
        SchannelAchCompleteInline,
        "[ tls] Invoking security config completion callback inline, 0x%x",
        Status);

    CompletionHandler(
        CredConfig,
        Context,
        Status,
        AchContext->SecConfig);
    if (CredConfig->Flags & QUIC_CREDENTIAL_FLAG_LOAD_ASYNCHRONOUS) {
        Status = QUIC_STATUS_PENDING;
    } else {
        Status = QUIC_STATUS_SUCCESS;
    }
    AchContext->SecConfig = NULL;

#endif // _KERNEL_MODE

Error:

#ifndef _KERNEL_MODE
    if (CertContext != NULL && CertContext != CredConfig->CertificateContext) {
        CertFreeCertificateContext(CertContext);
    }
#endif

    if (AchContext != NULL) {
        CxPlatTlsFreeAchContext(AchContext);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatTlsSecConfigDelete(
    __drv_freesMem(ServerConfig) _Frees_ptr_ _In_ CXPLAT_SEC_CONFIG* ServerConfig
    )
{
    if (SecIsValidHandle(&ServerConfig->CredentialHandle)) {
        FreeCredentialsHandle(&ServerConfig->CredentialHandle);
    }

#ifdef _KERNEL_MODE
    if (ServerConfig->ImpersonationToken) {
        if (ServerConfig->IsPrimaryToken) {
            PsDereferencePrimaryToken(ServerConfig->ImpersonationToken);
        } else {
            PsDereferenceImpersonationToken(ServerConfig->ImpersonationToken);
        }
    }
#endif

    CXPLAT_FREE(ServerConfig, QUIC_POOL_TLS_SECCONF);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsSecConfigSetTicketKeys(
    _In_ CXPLAT_SEC_CONFIG* SecurityConfig,
    _In_reads_(KeyCount) QUIC_TICKET_KEY_CONFIG* KeyConfig,
    _In_ uint8_t KeyCount
    )
{
    if (KeyCount > QUIC_MAX_TICKET_KEY_COUNT) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    SecPkgCred_SessionTicketKey Key[QUIC_MAX_TICKET_KEY_COUNT];
    for (uint8_t i = 0; i < KeyCount; ++i) {
        if (KeyConfig[i].MaterialLength > sizeof(Key[i].KeyingMaterial)) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        Key[i].TicketInfoVersion = SESSION_TICKET_INFO_V0;
        Key[i].KeyingMaterialSize = KeyConfig[i].MaterialLength;
        CxPlatCopyMemory(Key[i].KeyingMaterial, KeyConfig[i].Material, KeyConfig[i].MaterialLength);
        CxPlatCopyMemory(Key[i].KeyId, KeyConfig[i].Id, sizeof(KeyConfig[i].Id));
    }

    SecPkgCred_SessionTicketKeys Keys;
    Keys.cSessionTicketKeys = KeyCount;
    Keys.pSessionTicketKeys = Key;
    SECURITY_STATUS SecStatus =
        SetCredentialsAttributesW(
            &SecurityConfig->CredentialHandle,
            SECPKG_ATTR_SESSION_TICKET_KEYS,
            &Keys,
            sizeof(Keys));
    if (SecStatus != SEC_E_OK) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SecStatus,
            "SetCredentialsAttributesW(SESSION_TICKET_KEYS)");
        return SecStatusToQuicStatus(SecStatus);
    }

    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsInitialize(
    _In_ const CXPLAT_TLS_CONFIG* Config,
    _Inout_ CXPLAT_TLS_PROCESS_STATE* State,
    _Out_ CXPLAT_TLS** NewTlsContext
    )
{
    UNREFERENCED_PARAMETER(Config->Connection);

    const ULONG AppProtocolsSize =
        (ULONG)(Config->AlpnBufferLength +
            FIELD_OFFSET(SEC_APPLICATION_PROTOCOLS, ProtocolLists) +
            FIELD_OFFSET(SEC_APPLICATION_PROTOCOL_LIST, ProtocolList));
    const size_t TlsSize = sizeof(CXPLAT_TLS) + (size_t)AppProtocolsSize;

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    CXPLAT_TLS* TlsContext = NULL;

    CXPLAT_DBG_ASSERT(Config->HkdfLabels);

    if (Config->IsServer != !(Config->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT)) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            Config->Connection,
            "Mismatched SEC_CONFIG IsServer state");
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    TlsContext = CXPLAT_ALLOC_NONPAGED(TlsSize, QUIC_POOL_TLS_CTX);
    if (TlsContext == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "CXPLAT_TLS",
            sizeof(CXPLAT_TLS));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    CXPLAT_ANALYSIS_ASSUME(sizeof(*TlsContext) < TlsSize); // This should not be necessary.
    RtlZeroMemory(TlsContext, sizeof(*TlsContext));
    SecInvalidateHandle(&TlsContext->SchannelContext);

    TlsContext->IsServer = Config->IsServer;
    TlsContext->Connection = Config->Connection;
    TlsContext->HkdfLabels = Config->HkdfLabels;
    TlsContext->QuicTpExtType = Config->TPType;
    TlsContext->SNI = Config->ServerName;
    TlsContext->SecConfig = Config->SecConfig;
    TlsContext->TlsSecrets = Config->TlsSecrets;

    QuicTraceLogConnVerbose(
        SchannelContextCreated,
        TlsContext->Connection,
        "TLS context Created");

    TlsContext->AppProtocolsSize = AppProtocolsSize;
    TlsContext->ApplicationProtocols = (SEC_APPLICATION_PROTOCOLS*)(TlsContext + 1);
    TlsContext->ApplicationProtocols->ProtocolListsSize =
        (ULONG)(FIELD_OFFSET(SEC_APPLICATION_PROTOCOL_LIST, ProtocolList) + Config->AlpnBufferLength);

    SEC_APPLICATION_PROTOCOL_LIST* AlpnList = &TlsContext->ApplicationProtocols->ProtocolLists[0];
    AlpnList->ProtoNegoExt = SecApplicationProtocolNegotiationExt_ALPN;
    AlpnList->ProtocolListSize = Config->AlpnBufferLength;
    memcpy(&AlpnList->ProtocolList, Config->AlpnBuffer, Config->AlpnBufferLength);

    TlsContext->TransportParams = (SEND_GENERIC_TLS_EXTENSION*)Config->LocalTPBuffer;
    TlsContext->TransportParams->ExtensionType = Config->TPType;
    TlsContext->TransportParams->HandshakeType =
        Config->IsServer ? TlsHandshake_EncryptedExtensions : TlsHandshake_ClientHello;
    TlsContext->TransportParams->Flags = 0;
    TlsContext->TransportParams->BufferSize =
        (uint16_t)(Config->LocalTPLength - FIELD_OFFSET(SEND_GENERIC_TLS_EXTENSION, Buffer));

    State->EarlyDataState = CXPLAT_TLS_EARLY_DATA_UNSUPPORTED; // 0-RTT not currently supported.
    if (Config->ResumptionTicketBuffer != NULL) {
        CXPLAT_FREE(Config->ResumptionTicketBuffer, QUIC_POOL_CRYPTO_RESUMPTION_TICKET);
    }

    Status = QUIC_STATUS_SUCCESS;
    *NewTlsContext = TlsContext;
    TlsContext = NULL;

Error:
    if (TlsContext) {
        CXPLAT_FREE(TlsContext, QUIC_POOL_TLS_CTX);
    }
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
inline
static
void
CxPlatTlsResetSchannel(
    _In_ CXPLAT_TLS* TlsContext
    )
{
    if (SecIsValidHandle(&TlsContext->SchannelContext)) {
#ifdef _KERNEL_MODE
        SspiAsyncContext* DscContext = SspiCreateAsyncContext();
        if (DscContext != NULL) {
            SspiDeleteSecurityContextAsync(DscContext, &TlsContext->SchannelContext);
            SecInvalidateHandle(&TlsContext->SchannelContext);

            //
            // No callback was registered, so free this immediately.
            //
            SspiFreeAsyncContext(DscContext);
            DscContext = NULL;
        }
#else
        DeleteSecurityContext(&TlsContext->SchannelContext);
#endif
        SecInvalidateHandle(&TlsContext->SchannelContext);
        CxPlatZeroMemory(&TlsContext->Workspace, sizeof(TlsContext->Workspace));
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatTlsUninitialize(
    _In_opt_ CXPLAT_TLS* TlsContext
    )
{
    if (TlsContext != NULL) {
        QuicTraceLogConnVerbose(
            SchannelContextCleaningUp,
            TlsContext->Connection,
            "Cleaning up");

        CxPlatTlsResetSchannel(TlsContext);
        if (TlsContext->TransportParams != NULL) {
            CXPLAT_FREE(TlsContext->TransportParams, QUIC_POOL_TLS_TRANSPARAMS);
        }
        if (TlsContext->PeerTransportParams) {
            CXPLAT_FREE(TlsContext->PeerTransportParams, QUIC_POOL_TLS_TMP_TP);
            TlsContext->PeerTransportParams = NULL;
            TlsContext->PeerTransportParamsLength = 0;
        }
        CXPLAT_FREE(TlsContext, QUIC_POOL_TLS_CTX);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CxPlatTlsUpdateHkdfLabels(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ const QUIC_HKDF_LABELS* const Labels
    )
{
    TlsContext->HkdfLabels = Labels;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_TLS_RESULT_FLAGS
CxPlatTlsIndicateCertificateReceived(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ CXPLAT_TLS_PROCESS_STATE* State,
    _In_ SecPkgContext_CertificateValidationResult* CertValidationResult,
#ifdef _KERNEL_MODE
    _In_ SecPkgContext_Certificates* PeerCert
#else
    _In_ PCCERT_CONTEXT PeerCert
#endif
    )
{
    CXPLAT_TLS_RESULT_FLAGS Result = 0;
    QUIC_CERTIFICATE* Certificate;
    QUIC_CERTIFICATE_CHAIN* CertificateChain;
#ifndef _KERNEL_MODE
    QUIC_PORTABLE_CERTIFICATE PortableCertificate = {0};
#endif

#ifdef _KERNEL_MODE
    Certificate = (QUIC_CERTIFICATE*)PeerCert;
    CertificateChain = (QUIC_CERTIFICATE_CHAIN*)PeerCert;
#else
    if (PeerCert == NULL) {
        Certificate = NULL;
        CertificateChain = NULL;
    } else if (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES) {
        QUIC_STATUS Status =
            CxPlatGetPortableCertificate(
                (QUIC_CERTIFICATE*)PeerCert,
                &PortableCertificate);
        if (QUIC_FAILED(Status)) {
            Result |= CXPLAT_TLS_RESULT_ERROR;
            State->AlertCode = CXPLAT_TLS_ALERT_CODE_INTERNAL_ERROR;
            goto Exit;
        }
        Certificate = (QUIC_CERTIFICATE*)&PortableCertificate.PortableCertificate;
        CertificateChain = (QUIC_CERTIFICATE_CHAIN*)&PortableCertificate.PortableChain;
    } else {
        Certificate = (QUIC_CERTIFICATE*)PeerCert;
        CertificateChain = (QUIC_CERTIFICATE_CHAIN*)(PeerCert->hCertStore);
    }
#endif

    if (!TlsContext->SecConfig->Callbacks.CertificateReceived(
            TlsContext->Connection,
            Certificate,
            CertificateChain,
            CertValidationResult->dwChainErrorStatus,
            (QUIC_STATUS)CertValidationResult->hrVerifyChainStatus)) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Indicate certificate received failed");
        Result |= CXPLAT_TLS_RESULT_ERROR;
        State->AlertCode = CXPLAT_TLS_ALERT_CODE_BAD_CERTIFICATE;
        goto Exit;
    }

Exit:

#ifndef _KERNEL_MODE
    CxPlatFreePortableCertificate(&PortableCertificate);
#endif

    return Result;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_TLS_RESULT_FLAGS
CxPlatTlsWriteDataToSchannel(
    _In_ CXPLAT_TLS* TlsContext,
    _In_reads_(*InBufferLength)
        const uint8_t* InBuffer,
    _Inout_ uint32_t* InBufferLength,
    _Inout_ CXPLAT_TLS_PROCESS_STATE* State
    )
{
#ifdef _KERNEL_MODE
    SECURITY_STRING ServerName = { 0 };
    PSECURITY_STRING TargetServerName = NULL;
#else
    SEC_WCHAR* TargetServerName = NULL;
#endif

    SecBuffer* InSecBuffers = TlsContext->Workspace.InSecBuffers;
    SecBuffer* OutSecBuffers = TlsContext->Workspace.OutSecBuffers;

    SecBufferDesc InSecBufferDesc;
    InSecBufferDesc.ulVersion = SECBUFFER_VERSION;
    InSecBufferDesc.pBuffers = InSecBuffers;
    InSecBufferDesc.cBuffers = 0;

    SecBufferDesc OutSecBufferDesc;
    OutSecBufferDesc.ulVersion = SECBUFFER_VERSION;
    OutSecBufferDesc.pBuffers = OutSecBuffers;
    OutSecBufferDesc.cBuffers = 0;

    uint8_t AlertBufferRaw[2];

    if (*InBufferLength == 0) {

        //
        // If the input length is zero, then we are initializing the client
        // side, and have a few special differences in this code path.
        //
        CXPLAT_DBG_ASSERT(TlsContext->IsServer == FALSE);

        if (TlsContext->SNI != NULL) {
#ifdef _KERNEL_MODE
            TargetServerName = &ServerName;
            QUIC_STATUS Status = CxPlatTlsUtf8ToUnicodeString(TlsContext->SNI, TargetServerName, QUIC_POOL_TLS_SNI);
#else
            QUIC_STATUS Status = CxPlatUtf8ToWideChar(TlsContext->SNI, QUIC_POOL_TLS_SNI, &TargetServerName);
#endif
            if (QUIC_FAILED(Status)) {
                QuicTraceEvent(
                    TlsErrorStatus,
                    "[ tls][%p] ERROR, %u, %s.",
                    TlsContext->Connection,
                    Status,
                    "Convert SNI to unicode");
                return CXPLAT_TLS_RESULT_ERROR;
            }
        }

        //
        // The first (input) secbuffer holds the ALPN for client initials.
        //
        InSecBuffers[InSecBufferDesc.cBuffers].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
        InSecBuffers[InSecBufferDesc.cBuffers].cbBuffer = TlsContext->AppProtocolsSize;
        InSecBuffers[InSecBufferDesc.cBuffers].pvBuffer = TlsContext->ApplicationProtocols;
        InSecBufferDesc.cBuffers++;

    } else {

        //
        // The first (input) secbuffer holds the received TLS data.
        //
        InSecBuffers[InSecBufferDesc.cBuffers].BufferType = SECBUFFER_TOKEN;
        InSecBuffers[InSecBufferDesc.cBuffers].cbBuffer = *InBufferLength;
        InSecBuffers[InSecBufferDesc.cBuffers].pvBuffer = (void*)InBuffer;
        InSecBufferDesc.cBuffers++;
    }

    //
    // More (input) secbuffers to allow Schannel to signal to if any data is
    // extra or missing.
    // N.B. These must always immediately follow the SECBUFFER_TOKEN. Nothing
    // is allowed to be before them.
    //
    InSecBuffers[InSecBufferDesc.cBuffers].BufferType = SECBUFFER_EMPTY;
    InSecBuffers[InSecBufferDesc.cBuffers].cbBuffer = 0;
    InSecBuffers[InSecBufferDesc.cBuffers].pvBuffer = NULL;
    InSecBufferDesc.cBuffers++;
    InSecBuffers[InSecBufferDesc.cBuffers].BufferType = SECBUFFER_EMPTY;
    InSecBuffers[InSecBufferDesc.cBuffers].cbBuffer = 0;
    InSecBuffers[InSecBufferDesc.cBuffers].pvBuffer = NULL;
    InSecBufferDesc.cBuffers++;

    //
    // Another (input) secbuffer to configure Schannel to use disable the TLS
    // record layer.
    //
    CXPLAT_STATIC_ASSERT(
        ISC_REQ_MESSAGES == ASC_REQ_MESSAGES,
        "To simplify the code, we use the same value for both ISC and ASC");
    TlsContext->Workspace.InSecFlags.Flags = ISC_REQ_MESSAGES;
    InSecBuffers[InSecBufferDesc.cBuffers].BufferType = SECBUFFER_FLAGS;
    InSecBuffers[InSecBufferDesc.cBuffers].cbBuffer = sizeof(TlsContext->Workspace.InSecFlags);
    InSecBuffers[InSecBufferDesc.cBuffers].pvBuffer = &TlsContext->Workspace.InSecFlags;
    InSecBufferDesc.cBuffers++;

    //
    // If this is the first server call to ASC, populate the ALPN extension.
    //
    if (TlsContext->IsServer && !TlsContext->GeneratedFirstPayload) {
        //
        // The last (input) secbuffer contains the ALPN on server.
        //
        InSecBuffers[InSecBufferDesc.cBuffers].BufferType = SECBUFFER_APPLICATION_PROTOCOLS;
        InSecBuffers[InSecBufferDesc.cBuffers].cbBuffer = TlsContext->AppProtocolsSize;
        InSecBuffers[InSecBufferDesc.cBuffers].pvBuffer = TlsContext->ApplicationProtocols;
        InSecBufferDesc.cBuffers++;
    }

    //
    // The first (output) secbuffer is the buffer for Schannel to write any
    // TLS payload to send back out.
    //
    OutSecBuffers[OutSecBufferDesc.cBuffers].BufferType = SECBUFFER_TOKEN;
    OutSecBuffers[OutSecBufferDesc.cBuffers].cbBuffer = State->BufferAllocLength - State->BufferLength;
    OutSecBuffers[OutSecBufferDesc.cBuffers].pvBuffer = State->Buffer + State->BufferLength;
    OutSecBufferDesc.cBuffers++;

    //
    // Another (output) secbuffer is for any TLS alerts.
    //
    OutSecBuffers[OutSecBufferDesc.cBuffers].BufferType = SECBUFFER_ALERT;
    OutSecBuffers[OutSecBufferDesc.cBuffers].cbBuffer = sizeof(AlertBufferRaw);
    OutSecBuffers[OutSecBufferDesc.cBuffers].pvBuffer = AlertBufferRaw;
    OutSecBufferDesc.cBuffers++;

    if (TlsContext->TransportParams != NULL) {
        //
        // If we still have transport parameters to write, we need to add them
        // to the input buffer.
        //
        InSecBuffers[InSecBufferDesc.cBuffers].BufferType = SECBUFFER_SEND_GENERIC_TLS_EXTENSION;
        InSecBuffers[InSecBufferDesc.cBuffers].cbBuffer =
            FIELD_OFFSET(SEND_GENERIC_TLS_EXTENSION, Buffer) +
            TlsContext->TransportParams->BufferSize;
        InSecBuffers[InSecBufferDesc.cBuffers].pvBuffer = TlsContext->TransportParams;
        InSecBufferDesc.cBuffers++;
    }

    SUBSCRIBE_GENERIC_TLS_EXTENSION SubscribeExt;
    if (*InBufferLength != 0 &&
        !TlsContext->IsServer &&
        !TlsContext->PeerTransportParamsReceived) {
        //
        // Subscribe to get the peer's transport parameters, if available.
        //
        SubscribeExt.Flags = 0;
        SubscribeExt.SubscriptionsCount = 1;
        SubscribeExt.Subscriptions[0].ExtensionType = TlsContext->QuicTpExtType;
        SubscribeExt.Subscriptions[0].HandshakeType =
            TlsContext->IsServer ? TlsHandshake_ClientHello : TlsHandshake_EncryptedExtensions;

        InSecBuffers[InSecBufferDesc.cBuffers].BufferType = SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION;
        InSecBuffers[InSecBufferDesc.cBuffers].cbBuffer = sizeof(SubscribeExt);
        InSecBuffers[InSecBufferDesc.cBuffers].pvBuffer = &SubscribeExt;
        InSecBufferDesc.cBuffers++;

        //
        // Another (output) secbuffer for the result of the subscription.
        //
        OutSecBuffers[OutSecBufferDesc.cBuffers].BufferType = SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION;
        if (TlsContext->PeerTransportParams != NULL) {
            OutSecBuffers[OutSecBufferDesc.cBuffers].cbBuffer = TlsContext->PeerTransportParamsLength;
            OutSecBuffers[OutSecBufferDesc.cBuffers].pvBuffer = (void*)TlsContext->PeerTransportParams;
        } else {
            OutSecBuffers[OutSecBufferDesc.cBuffers].cbBuffer = *InBufferLength;
            OutSecBuffers[OutSecBufferDesc.cBuffers].pvBuffer = (void*)InBuffer; // Overwrite the input buffer with the extension.
        }
        OutSecBufferDesc.cBuffers++;
    }

    //
    // Four more output secbuffers for any traffic secrets generated.
    //
    for (uint8_t i = 0; i < SEC_TRAFFIC_SECRETS_COUNT; ++i) {
        OutSecBuffers[OutSecBufferDesc.cBuffers].BufferType = SECBUFFER_TRAFFIC_SECRETS;
        OutSecBuffers[OutSecBufferDesc.cBuffers].cbBuffer = MAX_SEC_TRAFFIC_SECRETS_SIZE;
        OutSecBuffers[OutSecBufferDesc.cBuffers].pvBuffer =
            TlsContext->Workspace.OutTrafSecBuf + i * MAX_SEC_TRAFFIC_SECRETS_SIZE;
        OutSecBufferDesc.cBuffers++;
    }

    CXPLAT_STATIC_ASSERT(ISC_REQ_SEQUENCE_DETECT == ASC_REQ_SEQUENCE_DETECT, "These are assumed to match");
    CXPLAT_STATIC_ASSERT(ISC_REQ_CONFIDENTIALITY == ASC_REQ_CONFIDENTIALITY, "These are assumed to match");
    ULONG ContextReq = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONFIDENTIALITY;
    if (TlsContext->IsServer) {
        ContextReq |= ASC_REQ_EXTENDED_ERROR | ASC_REQ_STREAM |
            ASC_REQ_SESSION_TICKET; // Always use session tickets for resumption
        if (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION) {
            ContextReq |= ASC_REQ_MUTUAL_AUTH;
        }
    } else {
        ContextReq |= ISC_REQ_EXTENDED_ERROR | ISC_REQ_STREAM;
        if (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_USE_SUPPLIED_CREDENTIALS) {
            ContextReq |= ISC_REQ_USE_SUPPLIED_CREDS;
        }
    }
    ULONG ContextAttr;
    SECURITY_STATUS SecStatus;

#ifdef _KERNEL_MODE
    if (TlsContext->SecConfig->ImpersonationToken) {
        NTSTATUS Status;
        if (TlsContext->SecConfig->IsPrimaryToken) {
            Status =
                PsImpersonateClient(
                    PsGetCurrentThread(),
                    TlsContext->SecConfig->ImpersonationToken,
                    FALSE,
                    FALSE,
                    SecurityImpersonation);
        } else {
            Status =
                PsImpersonateClient(
                    PsGetCurrentThread(),
                    TlsContext->SecConfig->ImpersonationToken,
                    TlsContext->SecConfig->CopyOnOpen,
                    TlsContext->SecConfig->EffectiveOnly,
                    TlsContext->SecConfig->ImpersonationLevel);
        }
        if (!NT_SUCCESS(Status)) {
            QuicTraceEvent(
                TlsErrorStatus,
                "[ tls][%p] ERROR, %u, %s.",
                TlsContext->Connection,
                Status,
                "PsImpersonateClient failed");
        }
    }
#endif

    if (TlsContext->IsServer) {
        CXPLAT_DBG_ASSERT(!(TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT));

        SecStatus =
            AcceptSecurityContext(
                &TlsContext->SecConfig->CredentialHandle,
                SecIsValidHandle(&TlsContext->SchannelContext) ? &TlsContext->SchannelContext : NULL,
                &InSecBufferDesc,
                ContextReq,
                0,
                &(TlsContext->SchannelContext),
                &OutSecBufferDesc,
                &ContextAttr,
                NULL); // FYI, used for client authentication certificate.

    } else {
        CXPLAT_DBG_ASSERT(TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_CLIENT);

        SecStatus =
            InitializeSecurityContextW(
                &TlsContext->SecConfig->CredentialHandle,
                SecIsValidHandle(&TlsContext->SchannelContext) ? &TlsContext->SchannelContext : NULL,
                TargetServerName, // Only set to non-null on client initial.
                ContextReq,
                0,
                SECURITY_NATIVE_DREP,
                &InSecBufferDesc,
                0,
                &TlsContext->SchannelContext,
                &OutSecBufferDesc,
                &ContextAttr,
                NULL);
    }

#ifdef _KERNEL_MODE
    if (TlsContext->SecConfig->ImpersonationToken) {
        //
        // This must only be called on a worker thread.
        // Otherwise, this might ruin existing impersonation.
        //
        PsRevertToSelf();
    }
#endif

    CXPLAT_TLS_RESULT_FLAGS Result = 0;

    SecBuffer* ExtraBuffer = NULL;
    SecBuffer* MissingBuffer = NULL;
    for (uint32_t i = 0; i < InSecBufferDesc.cBuffers; ++i) {
        if (ExtraBuffer == NULL &&
            InSecBufferDesc.pBuffers[i].BufferType == SECBUFFER_EXTRA) {
            ExtraBuffer = &InSecBufferDesc.pBuffers[i];
        } else if (MissingBuffer == NULL &&
            InSecBufferDesc.pBuffers[i].BufferType == SECBUFFER_MISSING) {
            MissingBuffer = &InSecBufferDesc.pBuffers[i];
        }
    }

    SecBuffer* OutputTokenBuffer = NULL;
    SecBuffer* AlertBuffer = NULL;
    SecBuffer* TlsExtensionBuffer = NULL;
    SEC_TRAFFIC_SECRETS* NewPeerTrafficSecrets[2] = {0};
    SEC_TRAFFIC_SECRETS* NewOwnTrafficSecrets[2] = {0};
    uint8_t NewPeerTrafficSecretsCount = 0;
    uint8_t NewOwnTrafficSecretsCount = 0;

    for (uint32_t i = 0; i < OutSecBufferDesc.cBuffers; ++i) {
        if (OutputTokenBuffer == NULL &&
            OutSecBufferDesc.pBuffers[i].BufferType == SECBUFFER_TOKEN) {
            OutputTokenBuffer = &OutSecBufferDesc.pBuffers[i];
        } else if (AlertBuffer == NULL &&
            OutSecBufferDesc.pBuffers[i].BufferType == SECBUFFER_ALERT &&
            OutSecBufferDesc.pBuffers[i].cbBuffer > 0) {
            AlertBuffer = &OutSecBufferDesc.pBuffers[i];
        } else if (TlsExtensionBuffer == NULL &&
            OutSecBufferDesc.pBuffers[i].BufferType == SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION) {
            TlsExtensionBuffer = &OutSecBufferDesc.pBuffers[i];
        } else if (OutSecBufferDesc.pBuffers[i].BufferType == SECBUFFER_TRAFFIC_SECRETS) {
            SEC_TRAFFIC_SECRETS* TrafficSecret =
                (SEC_TRAFFIC_SECRETS*)OutSecBufferDesc.pBuffers[i].pvBuffer;
            if (TrafficSecret->TrafficSecretType == SecTrafficSecret_None) {
                continue;
            }
            QuicTraceLogConnVerbose(
                SchannelKeyReady,
                TlsContext->Connection,
                "Key Ready Type, %u [%hu to %hu]",
                (uint32_t)TrafficSecret->TrafficSecretType,
                TrafficSecret->MsgSequenceStart,
                TrafficSecret->MsgSequenceEnd);
            if (TlsContext->IsServer) {
                if (TrafficSecret->TrafficSecretType == SecTrafficSecret_Server) {
                    NewOwnTrafficSecrets[NewOwnTrafficSecretsCount++] = TrafficSecret;
                } else {
                    NewPeerTrafficSecrets[NewPeerTrafficSecretsCount++] = TrafficSecret;
                }
            } else {
                if (TrafficSecret->TrafficSecretType == SecTrafficSecret_Server) {
                    NewPeerTrafficSecrets[NewPeerTrafficSecretsCount++] = TrafficSecret;
                } else {
                    NewOwnTrafficSecrets[NewOwnTrafficSecretsCount++] = TrafficSecret;
                }
            }
        }
    }

    switch (SecStatus) {
    case SEC_E_OK:

        //
        // The handshake has completed. This may or may not result in more data
        // that needs to be sent back in response (depending on client/server).
        //
        if (!TlsContext->IsServer && !TlsContext->PeerTransportParamsReceived) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "No QUIC TP received");
            Result |= CXPLAT_TLS_RESULT_ERROR;
            break;
        }

        if (TlsContext->TransportParams != NULL) {
            //
            // Done with the transport parameters. Clear them out so we don't
            // try to send them again.
            //
            CXPLAT_FREE(TlsContext->TransportParams, QUIC_POOL_TLS_TRANSPARAMS);
            TlsContext->TransportParams = NULL;
        }

        if (!State->HandshakeComplete) {
            if (!TlsContext->IsServer) {
                SecPkgContext_ApplicationProtocol NegotiatedAlpn;
                SecStatus =
                    QueryContextAttributesW(
                        &TlsContext->SchannelContext,
                        SECPKG_ATTR_APPLICATION_PROTOCOL,
                        &NegotiatedAlpn);
                if (SecStatus != SEC_E_OK) {
                    QuicTraceEvent(
                        TlsErrorStatus,
                        "[ tls][%p] ERROR, %u, %s.",
                        TlsContext->Connection,
                        SecStatus,
                        "query negotiated ALPN");
                    Result |= CXPLAT_TLS_RESULT_ERROR;
                    break;
                }
                if (NegotiatedAlpn.ProtoNegoStatus != SecApplicationProtocolNegotiationStatus_Success) {
                    QuicTraceEvent(
                        TlsErrorStatus,
                        "[ tls][%p] ERROR, %u, %s.",
                        TlsContext->Connection,
                        NegotiatedAlpn.ProtoNegoStatus,
                        "ALPN negotiation status");
                    Result |= CXPLAT_TLS_RESULT_ERROR;
                    break;
                }
                const SEC_APPLICATION_PROTOCOL_LIST* AlpnList =
                    &TlsContext->ApplicationProtocols->ProtocolLists[0];
                State->NegotiatedAlpn =
                    CxPlatTlsAlpnFindInList(
                        AlpnList->ProtocolListSize,
                        AlpnList->ProtocolList,
                        NegotiatedAlpn.ProtocolIdSize,
                        NegotiatedAlpn.ProtocolId);
                if (State->NegotiatedAlpn == NULL) {
                    QuicTraceEvent(
                        TlsError,
                        "[ tls][%p] ERROR, %s.",
                        TlsContext->Connection,
                        "ALPN Mismatch");
                    Result |= CXPLAT_TLS_RESULT_ERROR;
                    break;
                }
            }
            SecPkgContext_CertificateValidationResult CertValidationResult = {0,0};

            SecPkgContext_SessionInfo SessionInfo;
            SecStatus =
                QueryContextAttributesW(
                    &TlsContext->SchannelContext,
                    SECPKG_ATTR_SESSION_INFO,
                    &SessionInfo);
            if (SecStatus != SEC_E_OK) {
                QuicTraceEvent(
                    TlsErrorStatus,
                    "[ tls][%p] ERROR, %u, %s.",
                    TlsContext->Connection,
                    SecStatus,
                    "query session info");
                Result |= CXPLAT_TLS_RESULT_ERROR;
                break;
            }
            if (SessionInfo.dwFlags & SSL_SESSION_RECONNECT) {
                State->SessionResumed = TRUE;
            }

        const BOOLEAN RequirePeerCert =
            !TlsContext->IsServer ||
            TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION;

#ifdef _KERNEL_MODE
            SecPkgContext_Certificates _PeerCert;
            CxPlatZeroMemory(&_PeerCert, sizeof(_PeerCert));
            SecPkgContext_Certificates* PeerCert = &_PeerCert;
            SecStatus =
                QueryContextAttributesW(
                    &TlsContext->SchannelContext,
                    SECPKG_ATTR_REMOTE_CERTIFICATES,
                    (PVOID)PeerCert);
#else
            PCCERT_CONTEXT PeerCert = NULL;
            SecStatus =
                QueryContextAttributesW(
                    &TlsContext->SchannelContext,
                    SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                    (PVOID)&PeerCert);
#endif
            if (SecStatus == SEC_E_NO_CREDENTIALS &&
                (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION)) {
                //
                // Ignore this case.
                //
                CertValidationResult.hrVerifyChainStatus = SecStatus;
            } else if (SecStatus == SEC_E_OK &&
                !(TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION) &&
                (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_REQUIRE_CLIENT_AUTHENTICATION ||
                TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION)) {
                //
                // Collect the client cert validation result
                //
                SecStatus =
                    QueryContextAttributesW(
                        &TlsContext->SchannelContext,
                        SECPKG_ATTR_CERT_CHECK_RESULT_INPROC,
                        &CertValidationResult);
                if (SecStatus == SEC_E_NO_CREDENTIALS) {
                    CertValidationResult.hrVerifyChainStatus = SecStatus;
                } else if (SecStatus != SEC_E_OK) {
                    QuicTraceEvent(
                        TlsErrorStatus,
                        "[ tls][%p] ERROR, %u, %s.",
                        TlsContext->Connection,
                        SecStatus,
                        "query cert validation result");
                    Result |= CXPLAT_TLS_RESULT_ERROR;
                    break;
                }
            } else if (SecStatus != SEC_E_OK && RequirePeerCert &&
                !(TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION)) {
                QuicTraceEvent(
                    TlsErrorStatus,
                    "[ tls][%p] ERROR, %u, %s.",
                    TlsContext->Connection,
                    SecStatus,
                    "Query peer cert");
                Result |= CXPLAT_TLS_RESULT_ERROR;
                State->AlertCode = CXPLAT_TLS_ALERT_CODE_INTERNAL_ERROR;
                break;
            }

            if (TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED) {
                Result |=
                     CxPlatTlsIndicateCertificateReceived(
                        TlsContext,
                        State,
                        &CertValidationResult,
                        PeerCert);
            }

#ifdef _KERNEL_MODE
            if (_PeerCert.pbCertificateChain != NULL) {
                FreeContextBuffer(_PeerCert.pbCertificateChain);
            }
#else
            if (PeerCert != NULL) {
                CertFreeCertificateContext(PeerCert);
            }
#endif

            if ((Result & CXPLAT_TLS_RESULT_ERROR) != 0) {
                break;
            }

            if (!(TlsContext->SecConfig->Flags & QUIC_CREDENTIAL_FLAG_DEFER_CERTIFICATE_VALIDATION) &&
                CertValidationResult.hrVerifyChainStatus != QUIC_STATUS_SUCCESS) {
                //
                // If the server has configured client authentication but not deferred validation,
                // fail the handshake if the client cert doesn't pass validation
                //
                QuicTraceEvent(
                    TlsErrorStatus,
                    "[ tls][%p] ERROR, %u, %s.",
                    TlsContext->Connection,
                    CertValidationResult.hrVerifyChainStatus,
                    "Certificate validation failed");
                Result |= CXPLAT_TLS_RESULT_ERROR;
                State->AlertCode = CXPLAT_TLS_ALERT_CODE_BAD_CERTIFICATE;
                break;
            }

            QuicTraceLogConnInfo(
                SchannelHandshakeComplete,
                TlsContext->Connection,
                "Handshake complete (resume=%hu)",
                State->SessionResumed);
            State->HandshakeComplete = TRUE;
            Result |= CXPLAT_TLS_RESULT_HANDSHAKE_COMPLETE;
        }

        __fallthrough;

    case SEC_I_CONTINUE_NEEDED:
    case SEC_I_CONTINUE_NEEDED_MESSAGE_OK:

        if (AlertBuffer != NULL) {
            if (AlertBuffer->cbBuffer < 2) {
                QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "TLS alert message received (invalid)");
            } else {
                State->AlertCode = ((uint8_t*)AlertBuffer->pvBuffer)[1];
                QuicTraceEvent(
                    TlsErrorStatus,
                    "[ tls][%p] ERROR, %u, %s.",
                    TlsContext->Connection,
                    State->AlertCode,
                    "TLS alert message received");
            }
            Result |= CXPLAT_TLS_RESULT_ERROR;
            break;
        }

        //
        // Some or all of the input data was processed. There may or may not be
        // corresponding output data to send in response.
        //

        if (ExtraBuffer != NULL && ExtraBuffer->cbBuffer > 0) {
            //
            // Not all the input buffer was consumed. There is some 'extra' left over.
            //
            CXPLAT_DBG_ASSERT(InSecBuffers[1].cbBuffer <= *InBufferLength);
            *InBufferLength -= InSecBuffers[1].cbBuffer;
        }

        QuicTraceLogConnInfo(
            SchannelConsumedBytes,
            TlsContext->Connection,
            "Consumed %u bytes",
            *InBufferLength);

        //
        // Update our "read" key state based on any new peer keys being available.
        //
        for (uint8_t i = 0; i < NewPeerTrafficSecretsCount; ++i) {
            Result |= CXPLAT_TLS_RESULT_READ_KEY_UPDATED;
            if (NewPeerTrafficSecrets[i]->TrafficSecretType == SecTrafficSecret_ClientEarlyData) {
                CXPLAT_FRE_ASSERT(FALSE); // TODO - Finish the 0-RTT logic.
            } else {
                if (State->ReadKey == QUIC_PACKET_KEY_INITIAL) {
                    if (!QuicPacketKeyCreate(
                            TlsContext,
                            QUIC_PACKET_KEY_HANDSHAKE,
                            "peer handshake traffic secret",
                            NewPeerTrafficSecrets[i],
                            &State->ReadKeys[QUIC_PACKET_KEY_HANDSHAKE])) {
                        Result |= CXPLAT_TLS_RESULT_ERROR;
                        break;
                    }
                    State->ReadKey = QUIC_PACKET_KEY_HANDSHAKE;
                    QuicTraceLogConnInfo(
                        SchannelReadHandshakeStart,
                        TlsContext->Connection,
                        "Reading Handshake data starts now");
                    if (TlsContext->TlsSecrets != NULL) {
                        TlsContext->TlsSecrets->SecretLength = (uint8_t)NewPeerTrafficSecrets[i]->TrafficSecretSize;
                        if (TlsContext->IsServer) {
                            memcpy(
                                TlsContext->TlsSecrets->ClientHandshakeTrafficSecret,
                                NewPeerTrafficSecrets[i]->TrafficSecret,
                                NewPeerTrafficSecrets[i]->TrafficSecretSize);
                            TlsContext->TlsSecrets->IsSet.ClientHandshakeTrafficSecret = TRUE;
                        } else {
                            memcpy(
                                TlsContext->TlsSecrets->ServerHandshakeTrafficSecret,
                                NewPeerTrafficSecrets[i]->TrafficSecret,
                                NewPeerTrafficSecrets[i]->TrafficSecretSize);
                            TlsContext->TlsSecrets->IsSet.ServerHandshakeTrafficSecret = TRUE;
                        }
                    }
                } else if (State->ReadKey == QUIC_PACKET_KEY_HANDSHAKE) {
                    if (!QuicPacketKeyCreate(
                            TlsContext,
                            QUIC_PACKET_KEY_1_RTT,
                            "peer application traffic secret",
                            NewPeerTrafficSecrets[i],
                            &State->ReadKeys[QUIC_PACKET_KEY_1_RTT])) {
                        Result |= CXPLAT_TLS_RESULT_ERROR;
                        break;
                    }
                    State->ReadKey = QUIC_PACKET_KEY_1_RTT;
                    QuicTraceLogConnInfo(
                        SchannelRead1RttStart,
                        TlsContext->Connection,
                        "Reading 1-RTT data starts now");
                    if (TlsContext->TlsSecrets != NULL) {
                        TlsContext->TlsSecrets->SecretLength = (uint8_t)NewPeerTrafficSecrets[i]->TrafficSecretSize;
                        if (TlsContext->IsServer) {
                            memcpy(
                                TlsContext->TlsSecrets->ClientTrafficSecret0,
                                NewPeerTrafficSecrets[i]->TrafficSecret,
                                NewPeerTrafficSecrets[i]->TrafficSecretSize);
                            TlsContext->TlsSecrets->IsSet.ClientTrafficSecret0 = TRUE;
                        } else {
                            memcpy(
                                TlsContext->TlsSecrets->ServerTrafficSecret0,
                                NewPeerTrafficSecrets[i]->TrafficSecret,
                                NewPeerTrafficSecrets[i]->TrafficSecretSize);
                            TlsContext->TlsSecrets->IsSet.ServerTrafficSecret0 = TRUE;
                        }
                    }
                }
            }
        }

        //
        // Update our "write" state based on any of our own keys being available
        //
        for (uint8_t i = 0; i < NewOwnTrafficSecretsCount; ++i) {
            Result |= CXPLAT_TLS_RESULT_WRITE_KEY_UPDATED;
            if (NewOwnTrafficSecrets[i]->TrafficSecretType == SecTrafficSecret_ClientEarlyData) {
                CXPLAT_FRE_ASSERT(FALSE); // TODO - Finish the 0-RTT logic.
                CXPLAT_FRE_ASSERT(!TlsContext->IsServer);
                if (TlsContext->TlsSecrets != NULL) {
                    TlsContext->TlsSecrets->SecretLength = (uint8_t)NewOwnTrafficSecrets[i]->TrafficSecretSize;
                    memcpy(
                        TlsContext->TlsSecrets->ClientEarlyTrafficSecret,
                        NewOwnTrafficSecrets[i]->TrafficSecret,
                        NewOwnTrafficSecrets[i]->TrafficSecretSize);
                    TlsContext->TlsSecrets->IsSet.ClientEarlyTrafficSecret = TRUE;
                }
            } else {
                if (State->WriteKey == QUIC_PACKET_KEY_INITIAL) {
                    if (!QuicPacketKeyCreate(
                            TlsContext,
                            QUIC_PACKET_KEY_HANDSHAKE,
                            "own handshake traffic secret",
                            NewOwnTrafficSecrets[i],
                            &State->WriteKeys[QUIC_PACKET_KEY_HANDSHAKE])) {
                        Result |= CXPLAT_TLS_RESULT_ERROR;
                        break;
                    }
                    State->BufferOffsetHandshake =
                        State->BufferTotalLength + NewOwnTrafficSecrets[i]->MsgSequenceStart;
                    State->BufferOffset1Rtt = // HACK - Currently Schannel has weird output for 1-RTT start
                        State->BufferTotalLength + NewOwnTrafficSecrets[i]->MsgSequenceEnd;
                    State->WriteKey = QUIC_PACKET_KEY_HANDSHAKE;
                    QuicTraceLogConnInfo(
                        SchannelWriteHandshakeStart,
                        TlsContext->Connection,
                        "Writing Handshake data starts at %u",
                        State->BufferOffsetHandshake);
                    if (TlsContext->TlsSecrets != NULL) {
                        TlsContext->TlsSecrets->SecretLength = (uint8_t)NewOwnTrafficSecrets[i]->TrafficSecretSize;
                        if (TlsContext->IsServer) {
                            memcpy(
                                TlsContext->TlsSecrets->ServerHandshakeTrafficSecret,
                                NewOwnTrafficSecrets[i]->TrafficSecret,
                                NewOwnTrafficSecrets[i]->TrafficSecretSize);
                            TlsContext->TlsSecrets->IsSet.ServerHandshakeTrafficSecret = TRUE;
                        } else {
                            memcpy(
                                TlsContext->TlsSecrets->ClientHandshakeTrafficSecret,
                                NewOwnTrafficSecrets[i]->TrafficSecret,
                                NewOwnTrafficSecrets[i]->TrafficSecretSize);
                            TlsContext->TlsSecrets->IsSet.ClientHandshakeTrafficSecret = TRUE;
                        }
                    }
                } else if (State->WriteKey == QUIC_PACKET_KEY_HANDSHAKE) {
                    if (!TlsContext->IsServer && State->BufferOffsetHandshake == State->BufferOffset1Rtt) {
                        State->BufferOffset1Rtt = // HACK - Currently Schannel has weird output for 1-RTT start
                            State->BufferTotalLength + NewOwnTrafficSecrets[i]->MsgSequenceEnd;
                    } else {
                        if (!QuicPacketKeyCreate(
                                TlsContext,
                                QUIC_PACKET_KEY_1_RTT,
                                "own application traffic secret",
                                NewOwnTrafficSecrets[i],
                                &State->WriteKeys[QUIC_PACKET_KEY_1_RTT])) {
                            Result |= CXPLAT_TLS_RESULT_ERROR;
                            break;
                        }
                        //State->BufferOffset1Rtt = // Currently have to get the offset from the Handshake "end"
                        //    State->BufferTotalLength + NewOwnTrafficSecrets[i]->MsgSequenceStart;
                        State->WriteKey = QUIC_PACKET_KEY_1_RTT;
                        QuicTraceLogConnInfo(
                            SchannelWrite1RttStart,
                            TlsContext->Connection,
                            "Writing 1-RTT data starts at %u",
                            State->BufferOffset1Rtt);
                        if (TlsContext->TlsSecrets != NULL) {
                            TlsContext->TlsSecrets->SecretLength = (uint8_t)NewOwnTrafficSecrets[i]->TrafficSecretSize;
                            if (TlsContext->IsServer) {
                                memcpy(
                                    TlsContext->TlsSecrets->ServerTrafficSecret0,
                                    NewOwnTrafficSecrets[i]->TrafficSecret,
                                    NewOwnTrafficSecrets[i]->TrafficSecretSize);
                                TlsContext->TlsSecrets->IsSet.ServerTrafficSecret0 = TRUE;
                            } else {
                                memcpy(
                                    TlsContext->TlsSecrets->ClientTrafficSecret0,
                                    NewOwnTrafficSecrets[i]->TrafficSecret,
                                    NewOwnTrafficSecrets[i]->TrafficSecretSize);
                                TlsContext->TlsSecrets->IsSet.ClientTrafficSecret0 = TRUE;
                            }
                        }
                    }
                }
            }
        }

        if (SecStatus == SEC_E_OK) {
            //
            // We're done with the TlsSecrets.
            //
            TlsContext->TlsSecrets = NULL;
        }

        if (OutputTokenBuffer != NULL && OutputTokenBuffer->cbBuffer > 0) {
            //
            // There is output data to send back.
            //
            Result |= CXPLAT_TLS_RESULT_DATA;
            TlsContext->GeneratedFirstPayload = TRUE;

            CXPLAT_FRE_ASSERT(OutputTokenBuffer->cbBuffer <= 0xFFFF);
            CXPLAT_DBG_ASSERT((uint16_t)OutputTokenBuffer->cbBuffer <= (State->BufferAllocLength - State->BufferLength));
            State->BufferLength += (uint16_t)OutputTokenBuffer->cbBuffer;
            State->BufferTotalLength += OutputTokenBuffer->cbBuffer;

            QuicTraceLogConnInfo(
                SchannelProducedData,
                TlsContext->Connection,
                "Produced %u bytes",
                OutputTokenBuffer->cbBuffer);
        }

        break;

    case SEC_I_GENERIC_EXTENSION_RECEIVED:

        if (TlsExtensionBuffer == NULL) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "QUIC TP wasn't present");
            Result |= CXPLAT_TLS_RESULT_ERROR;
            break;
        }

        //
        // We received the peer's transport parameters and need to decode
        // them.
        //
        if (!TlsContext->SecConfig->Callbacks.ReceiveTP(
                TlsContext->Connection,
                (uint16_t)(TlsExtensionBuffer->cbBuffer - 4),
                ((uint8_t*)TlsExtensionBuffer->pvBuffer) + 4)) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Process QUIC TP");
            Result |= CXPLAT_TLS_RESULT_ERROR;
            break;
        }

        TlsContext->PeerTransportParamsReceived = TRUE;
        Result |= CXPLAT_TLS_RESULT_CONTINUE;
        if (TlsContext->PeerTransportParams != NULL) {
            CXPLAT_FREE(TlsContext->PeerTransportParams, QUIC_POOL_TLS_TMP_TP);
            TlsContext->PeerTransportParams = NULL;
            TlsContext->PeerTransportParamsLength = 0;
        }

        break;

    case SEC_E_INCOMPLETE_MESSAGE:

        //
        // None of the input buffer was consumed. There wasn't a complete TLS
        // record for Schannel to process. Check to see if Schannel indicated
        // how much more data they expect.
        //
        *InBufferLength = 0;

        if (MissingBuffer != NULL && MissingBuffer->cbBuffer != 0) {
            QuicTraceLogConnInfo(
                SchannelMissingData,
                TlsContext->Connection,
                "TLS message missing %u bytes of data",
                MissingBuffer->cbBuffer);
        }

        break;

    case SEC_E_EXT_BUFFER_TOO_SMALL:
        if (*InBufferLength != 0 &&
            !TlsContext->IsServer &&
            !TlsContext->PeerTransportParamsReceived) {

            for (uint32_t i = 0; i < OutSecBufferDesc.cBuffers; ++i) {
                if (OutSecBufferDesc.pBuffers[i].BufferType == SECBUFFER_SUBSCRIBE_GENERIC_TLS_EXTENSION) {

                    CXPLAT_DBG_ASSERT(OutSecBufferDesc.pBuffers[i].cbBuffer > *InBufferLength);

                    QuicTraceLogConnInfo(
                        SchannelTransParamsBufferTooSmall,
                        TlsContext->Connection,
                        "Peer TP too large for available buffer (%u vs. %u)",
                        OutSecBufferDesc.pBuffers[i].cbBuffer,
                        (TlsContext->PeerTransportParams != NULL) ?
                            TlsContext->PeerTransportParamsLength :
                            *InBufferLength);

                    if (TlsContext->PeerTransportParams != NULL) {
                        CXPLAT_FREE(TlsContext->PeerTransportParams, QUIC_POOL_TLS_TMP_TP);
                    }

                    TlsContext->PeerTransportParams =
                        CXPLAT_ALLOC_NONPAGED(
                            OutSecBufferDesc.pBuffers[i].cbBuffer,
                            QUIC_POOL_TLS_TMP_TP);
                    if (TlsContext->PeerTransportParams == NULL) {
                        QuicTraceEvent(
                            AllocFailure,
                            "Allocation of '%s' failed. (%llu bytes)",
                            "Temporary Peer Transport Params",
                            OutSecBufferDesc.pBuffers[i].cbBuffer);
                        Result |= CXPLAT_TLS_RESULT_ERROR;
                        break;
                    }
                    TlsContext->PeerTransportParamsLength = OutSecBufferDesc.pBuffers[i].cbBuffer;
                    Result |= CXPLAT_TLS_RESULT_CONTINUE;
                    break;
                }
            }
            if (TlsContext->PeerTransportParams != NULL) {
                break;
            }
        }
        //
        // Fall through here in other cases when we don't expect this.
        //
        __fallthrough;

    default:
        //
        // Some other error occurred and we should indicate no data could be
        // processed successfully.
        //
        if (AlertBuffer != NULL) {
            if (AlertBuffer->cbBuffer < 2) {
                QuicTraceEvent(
                    TlsError,
                    "[ tls][%p] ERROR, %s.",
                    TlsContext->Connection,
                    "TLS alert message received (invalid)");
            } else {
                State->AlertCode = ((uint8_t*)AlertBuffer->pvBuffer)[1];
                QuicTraceEvent(
                    TlsErrorStatus,
                    "[ tls][%p] ERROR, %u, %s.",
                    TlsContext->Connection,
                    State->AlertCode,
                    "TLS alert message received");
            }
            Result |= CXPLAT_TLS_RESULT_ERROR;
        }
        if (SecStatus == SEC_I_INCOMPLETE_CREDENTIALS &&
            State->AlertCode == TLS1_ALERT_CLOSE_NOTIFY) {
            //
            // Work-around for Schannel sending the wrong TLS alert.
            //
            State->AlertCode = TLS1_ALERT_CERTIFICATE_REQUIRED;
        }
        *InBufferLength = 0;
        QuicTraceEvent(
            TlsErrorStatus,
            "[ tls][%p] ERROR, %u, %s.",
            TlsContext->Connection,
            SecStatus,
            "Accept/InitializeSecurityContext");
        Result |= CXPLAT_TLS_RESULT_ERROR;
        break;
    }

#ifdef _KERNEL_MODE
    if (ServerName.Buffer != NULL) {
        CXPLAT_FREE(ServerName.Buffer, QUIC_POOL_TLS_SNI);
    }
#else
    if (TargetServerName != NULL) {
        CXPLAT_FREE(TargetServerName, QUIC_POOL_TLS_SNI);
    }
#endif

    return Result;
}


_IRQL_requires_max_(PASSIVE_LEVEL)
CXPLAT_TLS_RESULT_FLAGS
CxPlatTlsProcessData(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ CXPLAT_TLS_DATA_TYPE DataType,
    _In_reads_bytes_(*BufferLength)
        const uint8_t * Buffer,
    _Inout_ uint32_t * BufferLength,
    _Inout_ CXPLAT_TLS_PROCESS_STATE* State
    )
{
    CXPLAT_TLS_RESULT_FLAGS Result = 0;
    if (DataType == CXPLAT_TLS_TICKET_DATA) {
        Result = CXPLAT_TLS_RESULT_ERROR;

        QuicTraceLogConnVerbose(
            SchannelIgnoringTicket,
            TlsContext->Connection,
            "Ignoring %u ticket bytes",
            *BufferLength);
        goto Error;
    }

    if (!TlsContext->IsServer && State->BufferOffset1Rtt > 0 &&
        State->HandshakeComplete) {
        //
        // Schannel currently sends the NST after receiving client finished.
        // We need to wait for the handshake to be complete before setting
        // the flag, since we don't know if we've received the ticket yet.
        //
        (void)TlsContext->SecConfig->Callbacks.ReceiveTicket(
            TlsContext->Connection,
            0,
            NULL);
    }

    QuicTraceLogConnVerbose(
        SchannelProcessingData,
        TlsContext->Connection,
        "Processing %u received bytes",
        *BufferLength);

    Result =
        CxPlatTlsWriteDataToSchannel(
            TlsContext,
            Buffer,
            BufferLength,
            State);
    if ((Result & CXPLAT_TLS_RESULT_ERROR) != 0) {
        goto Error;
    }

    while (Result & CXPLAT_TLS_RESULT_CONTINUE) {
        Result &= ~CXPLAT_TLS_RESULT_CONTINUE;
        Result |=
            CxPlatTlsWriteDataToSchannel(
                TlsContext,
                Buffer,
                BufferLength,
                State);
        if ((Result & CXPLAT_TLS_RESULT_ERROR) != 0) {
            goto Error;
        }
    }

Error:

    return Result;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSecConfigParamSet(
    _In_ CXPLAT_SEC_CONFIG* SecConfig,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    QUIC_STATUS Status;

    switch (Param) {
    case QUIC_PARAM_CONFIGURATION_SCHANNEL_CREDENTIAL_ATTRIBUTE_W: {
        if (Buffer == NULL ||
            BufferLength != sizeof(QUIC_SCHANNEL_CREDENTIAL_ATTRIBUTE_W)) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            break;
        }

        if (SecConfig == NULL || !SecIsValidHandle(&SecConfig->CredentialHandle)) {
            Status = QUIC_STATUS_INVALID_STATE;
            break;
        }

        QUIC_SCHANNEL_CREDENTIAL_ATTRIBUTE_W *CredentialAttribute =
            (QUIC_SCHANNEL_CREDENTIAL_ATTRIBUTE_W*)Buffer;

        Status =
            SecStatusToQuicStatus(
            SetCredentialsAttributesW(
                &SecConfig->CredentialHandle,
                CredentialAttribute->Attribute,
                CredentialAttribute->Buffer,
                CredentialAttribute->BufferLength));
        break;
    }
    default:
        Status = QUIC_STATUS_NOT_SUPPORTED;
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatSecConfigParamGet(
    _In_ CXPLAT_SEC_CONFIG* SecConfig,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Inout_updates_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    UNREFERENCED_PARAMETER(SecConfig);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsParamSet(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ uint32_t Param,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const void* Buffer
    )
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(Param);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
CxPlatTlsParamGet(
    _In_ CXPLAT_TLS* TlsContext,
    _In_ uint32_t Param,
    _Inout_ uint32_t* BufferLength,
    _Inout_updates_bytes_opt_(*BufferLength)
        void* Buffer
    )
{
    QUIC_STATUS Status;

    switch (Param) {

        case QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_W: {
            if (*BufferLength < sizeof(QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_W)) {
                *BufferLength = sizeof(QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_W);
                Status = QUIC_STATUS_BUFFER_TOO_SMALL;
                break;
            }

            if (Buffer == NULL) {
                Status = QUIC_STATUS_INVALID_PARAMETER;
                break;
            }

            QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_W *ContextAttribute =
                (QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_W*)Buffer;

            Status =
                SecStatusToQuicStatus(
                QueryContextAttributesW(
                    &TlsContext->SchannelContext,
                    ContextAttribute->Attribute,
                    ContextAttribute->Buffer));
            break;
        }

        case QUIC_PARAM_TLS_SCHANNEL_CONTEXT_ATTRIBUTE_EX_W: {
            if (*BufferLength < sizeof(QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_EX_W)) {
                *BufferLength = sizeof(QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_EX_W);
                Status = QUIC_STATUS_BUFFER_TOO_SMALL;
                break;
            }

            if (Buffer == NULL) {
                Status = QUIC_STATUS_INVALID_PARAMETER;
                break;
            }

            QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_EX_W *ContextAttribute =
                (QUIC_SCHANNEL_CONTEXT_ATTRIBUTE_EX_W*)Buffer;

            Status =
                SecStatusToQuicStatus(
                QueryContextAttributesExW(
                    &TlsContext->SchannelContext,
                    ContextAttribute->Attribute,
                    ContextAttribute->Buffer,
                    ContextAttribute->BufferLength));
            break;
        }

        case QUIC_PARAM_TLS_SCHANNEL_SECURITY_CONTEXT_TOKEN:
            if (*BufferLength < sizeof(void*)) {
                *BufferLength = sizeof(void*);
                Status = QUIC_STATUS_BUFFER_TOO_SMALL;
                break;
            }

            if (Buffer == NULL) {
                Status = QUIC_STATUS_INVALID_PARAMETER;
                break;
            }

            Status =
                SecStatusToQuicStatus(
                QuerySecurityContextToken(
                    &TlsContext->SchannelContext,
                    Buffer));
            break;

        case QUIC_PARAM_TLS_HANDSHAKE_INFO: {
            if (*BufferLength < sizeof(QUIC_HANDSHAKE_INFO)) {
                *BufferLength = sizeof(QUIC_HANDSHAKE_INFO);
                Status = QUIC_STATUS_BUFFER_TOO_SMALL;
                break;
            }

            if (Buffer == NULL) {
                Status = QUIC_STATUS_INVALID_PARAMETER;
                break;
            }

            SecPkgContext_ConnectionInfo ConnInfo;
            CxPlatZeroMemory(&ConnInfo, sizeof(ConnInfo));

            Status =
                SecStatusToQuicStatus(
                    QueryContextAttributesW(
                        &TlsContext->SchannelContext,
                        SECPKG_ATTR_CONNECTION_INFO,
                        &ConnInfo));
            if (QUIC_FAILED(Status)) {
                QuicTraceEvent(
                    TlsErrorStatus,
                    "[ tls][%p] ERROR, %u, %s.",
                    TlsContext->Connection,
                    Status,
                    "Query Connection Info");
                break;
            }

            SecPkgContext_CipherInfo CipherInfo;
            CxPlatZeroMemory(&CipherInfo, sizeof(CipherInfo));

            Status =
                SecStatusToQuicStatus(
                    QueryContextAttributesW(
                        &TlsContext->SchannelContext,
                        SECPKG_ATTR_CIPHER_INFO,
                        &CipherInfo));
            if (QUIC_FAILED(Status)) {
                QuicTraceEvent(
                    TlsErrorStatus,
                    "[ tls][%p] ERROR, %u, %s.",
                    TlsContext->Connection,
                    Status,
                    "Query Cipher Info");
                break;
            }

            QUIC_HANDSHAKE_INFO* HandshakeInfo = (QUIC_HANDSHAKE_INFO*)Buffer;
            if ((ConnInfo.dwProtocol & SP_PROT_TLS1_3) != 0) {
                HandshakeInfo->TlsProtocolVersion = QUIC_TLS_PROTOCOL_1_3;
            } else {
                HandshakeInfo->TlsProtocolVersion = QUIC_TLS_PROTOCOL_UNKNOWN;
            }

            HandshakeInfo->CipherAlgorithm = ConnInfo.aiCipher;
            HandshakeInfo->CipherStrength = ConnInfo.dwCipherStrength;
            HandshakeInfo->Hash = ConnInfo.aiHash;
            HandshakeInfo->HashStrength = ConnInfo.dwHashStrength;
            HandshakeInfo->KeyExchangeAlgorithm = ConnInfo.aiExch;
            HandshakeInfo->KeyExchangeStrength = ConnInfo.dwExchStrength;
            HandshakeInfo->CipherSuite = CipherInfo.dwCipherSuite;
            break;
        }

        default:
            Status = QUIC_STATUS_NOT_SUPPORTED;
            break;

        case QUIC_PARAM_TLS_NEGOTIATED_ALPN: {
            if (Buffer == NULL) {
                Status = QUIC_STATUS_INVALID_PARAMETER;
                break;
            }

            SecPkgContext_ApplicationProtocol NegotiatedAlpn;
            CxPlatZeroMemory(&NegotiatedAlpn, sizeof(NegotiatedAlpn));

            Status =
                SecStatusToQuicStatus(
                    QueryContextAttributesW(
                        &TlsContext->SchannelContext,
                        SECPKG_ATTR_APPLICATION_PROTOCOL,
                        &NegotiatedAlpn));
            if (QUIC_FAILED(Status)) {
                QuicTraceEvent(
                    TlsErrorStatus,
                    "[ tls][%p] ERROR, %u, %s.",
                    TlsContext->Connection,
                    Status,
                    "Query Application Protocol");
                break;
            }
            if (NegotiatedAlpn.ProtoNegoStatus != SecApplicationProtocolNegotiationStatus_Success) {
                QuicTraceEvent(
                    TlsErrorStatus,
                    "[ tls][%p] ERROR, %u, %s.",
                    TlsContext->Connection,
                    NegotiatedAlpn.ProtoNegoStatus,
                    "ALPN negotiation status");
                Status = QUIC_STATUS_INVALID_STATE;
                break;
            }
            if (*BufferLength < NegotiatedAlpn.ProtocolIdSize) {
                *BufferLength = NegotiatedAlpn.ProtocolIdSize;
                Status = QUIC_STATUS_BUFFER_TOO_SMALL;
                break;
            }
            *BufferLength = NegotiatedAlpn.ProtocolIdSize;
            CxPlatCopyMemory(Buffer, NegotiatedAlpn.ProtocolId, NegotiatedAlpn.ProtocolIdSize);
            break;
        }
    }

    return Status;
}

_Success_(return != FALSE)
BOOLEAN
CxPlatParseTrafficSecrets(
    _In_ const CXPLAT_TLS* TlsContext,
    _In_ const SEC_TRAFFIC_SECRETS* TrafficSecrets,
    _Out_ CXPLAT_SECRET* Secret
    )
{
    UNREFERENCED_PARAMETER(TlsContext);

    if (wcscmp(TrafficSecrets->SymmetricAlgId, BCRYPT_AES_ALGORITHM) == 0) {
        if (wcscmp(TrafficSecrets->ChainingMode, BCRYPT_CHAIN_MODE_GCM) != 0) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Unsupported chaining mode");
            return FALSE;
        }
        switch (TrafficSecrets->KeySize) {
        case 16:
            Secret->Aead = CXPLAT_AEAD_AES_128_GCM;
            break;
        case 32:
            Secret->Aead = CXPLAT_AEAD_AES_256_GCM;
            break;
        default:
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Unsupported AES key size");
            return FALSE;
        }
    } else if (wcscmp(TrafficSecrets->SymmetricAlgId, BCRYPT_CHACHA20_POLY1305_ALGORITHM) == 0) {
        if (CXPLAT_CHACHA20_POLY1305_ALG_HANDLE == NULL) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Algorithm unsupported by TLS: ChaCha20-Poly1305");
            return FALSE;
        }
        switch (TrafficSecrets->KeySize) {
        case 32:
            Secret->Aead = CXPLAT_AEAD_CHACHA20_POLY1305;
            break;
        default:
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Unsupported ChaCha key size");
            return FALSE;
        }
    } else {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Unsupported symmetric algorithm");
        return FALSE;
    }

    if (wcscmp(TrafficSecrets->HashAlgId, BCRYPT_SHA256_ALGORITHM) == 0) {
        Secret->Hash = CXPLAT_HASH_SHA256;
    } else if (wcscmp(TrafficSecrets->HashAlgId, BCRYPT_SHA384_ALGORITHM) == 0) {
        Secret->Hash = CXPLAT_HASH_SHA384;
    } else if (wcscmp(TrafficSecrets->HashAlgId, BCRYPT_SHA512_ALGORITHM) == 0) {
        Secret->Hash = CXPLAT_HASH_SHA512;
    } else {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Unsupported hash algorithm");
        return FALSE;
    }

    CXPLAT_DBG_ASSERT(TrafficSecrets->TrafficSecretSize <= sizeof(Secret->Secret));
    CXPLAT_DBG_ASSERT(TrafficSecrets->IvSize == CXPLAT_IV_LENGTH);

    memcpy(Secret->Secret, TrafficSecrets->TrafficSecret, TrafficSecrets->TrafficSecretSize);

    return TRUE;
}

_Success_(return==TRUE)
BOOLEAN
QuicPacketKeyCreate(
    _Inout_ CXPLAT_TLS* TlsContext,
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _In_z_ const char* const SecretName,
    _In_ const SEC_TRAFFIC_SECRETS* TrafficSecrets,
    _Out_ QUIC_PACKET_KEY** Key
    )
{
    QUIC_STATUS Status;
    CXPLAT_SECRET Secret;

    if (!CxPlatParseTrafficSecrets(TlsContext, TrafficSecrets, &Secret)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    Status =
        QuicPacketKeyDerive(
            KeyType,
            TlsContext->HkdfLabels,
            &Secret,
            SecretName,
            TRUE,
            Key);
    if (!QUIC_SUCCEEDED(Status)) {
        QuicTraceEvent(
            TlsErrorStatus,
            "[ tls][%p] ERROR, %u, %s.",
            TlsContext->Connection,
            Status,
            "QuicPacketKeyDerive");
        goto Error;
    }

Error:

    return QUIC_SUCCEEDED(Status);
}
