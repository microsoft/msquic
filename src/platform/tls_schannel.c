/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    SCHANNEL TLS Implementation for QUIC

Environment:

    Windows user mode or kernel mode

--*/

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

typedef struct _SEND_GENERIC_TLS_EXTENSION
{
    WORD  ExtensionType;            // Code point of extension.
    WORD  HandshakeType;            // Message type used to transport extension.
    DWORD Flags;                    // Flags used to modify behavior. Must be zero.
    WORD  BufferSize;               // Size in bytes of the extension data.
    UCHAR Buffer[ANYSIZE_ARRAY];    // Extension data.
} SEND_GENERIC_TLS_EXTENSION, * PSEND_GENERIC_TLS_EXTENSION;

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

#else

#define SCHANNEL_USE_BLACKLISTS
#include <schannel.h>

#endif

uint16_t QuicTlsTPHeaderSize = FIELD_OFFSET(SEND_GENERIC_TLS_EXTENSION, Buffer);

#define SecTrafficSecret_ClientEarlyData (SecTrafficSecret_Server + 1) // Hack to have my layer support 0-RTT

#define SEC_TRAFFIC_SECRETS_COUNT       4
#define MAX_SEC_TRAFFIC_SECRET_SIZE     0x40 // Fits all known current and future algorithms

#define MAX_SEC_TRAFFIC_SECRETS_SIZE \
    (sizeof(SEC_TRAFFIC_SECRETS) + MAX_SEC_TRAFFIC_SECRET_SIZE)

const WORD TlsHandshake_ClientHello = 0x01;
const WORD TlsHandshake_EncryptedExtensions = 0x08;

typedef struct QUIC_SEC_CONFIG {
    BOOLEAN IsServer : 1;
    LONG RefCount;
} QUIC_SEC_CONFIG;

typedef struct QUIC_SERVER_SEC_CONFIG {
    QUIC_SEC_CONFIG;
    QUIC_RUNDOWN_REF* CleanupRundown;
#ifdef _KERNEL_MODE
    //
    // Async call context.
    //
    SspiAsyncContext* SspiContext;
#endif
    //
    // Acquired credential handle.
    //
    CredHandle CertificateHandle;
} QUIC_SERVER_SEC_CONFIG;

// allocate this internally and cast to the sec_config type
typedef struct QUIC_CLIENT_SEC_CONFIG {
    QUIC_SEC_CONFIG;

    //
    // Credential handle as obtained from AcquireCredentialsHandle.
    //
    CredHandle SchannelHandle;
} QUIC_CLIENT_SEC_CONFIG;

#ifdef _KERNEL_MODE
typedef struct QUIC_ACHA_CONTEXT {
    //
    // Context for the completion callback.
    //
    void* CompletionContext;

    //
    // Caller-registered callback to signal credential acquisition is complete.
    //
    QUIC_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionCallback;

    //
    // Principal string, stored here to ensure it's alive as long as the async
    // call needs it.
    //
    UNICODE_STRING Principal;

    //
    // Certificate hash used to find the server certificate.
    //
    SCHANNEL_CERT_HASH_STORE CertHash;

    //
    // Security config to pass back to the caller.
    //
    QUIC_SERVER_SEC_CONFIG* SecConfig;

    //
    // Holds the credentials configuration for the lifetime of the async call.
    //
    SCH_CREDENTIALS Credentials;

    //
    // Holds TLS configuration for the lifetime of the async call.
    //
    TLS_PARAMETERS TlsParameters;

} QUIC_ACHA_CONTEXT;
#endif

typedef struct QUIC_TLS_SESSION {

    uint32_t Reserved;

} QUIC_TLS_SESSION;

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

typedef struct QUIC_TLS {

    BOOLEAN IsServer : 1;
    BOOLEAN GeneratedFirstPayload : 1;
    BOOLEAN PeerTransportParamsReceived : 1;
    BOOLEAN HandshakeKeyRead : 1;
    BOOLEAN ApplicationKeyRead : 1;

    QUIC_TLS_SESSION* TlsSession;

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
    QUIC_SEC_CONFIG* SecConfig;

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
    QUIC_TLS_RECEIVE_TP_CALLBACK_HANDLER ReceiveTPCallback;

    //
    // Workspace for sec buffers pass into ISC/ASC.
    //
    SEC_BUFFER_WORKSPACE Workspace;

} QUIC_TLS;

_Success_(return==TRUE)
BOOLEAN
QuicPacketKeyCreate(
    _Inout_ QUIC_TLS* TlsContext,
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _In_z_ const char* const SecretName,
    _In_ const SEC_TRAFFIC_SECRETS* TrafficSecrets,
    _Out_ QUIC_PACKET_KEY** Key
    );

#define SecStatusToQuicStatus(x) (QUIC_STATUS)(x)

#ifdef _KERNEL_MODE
#define NtStatusToQuicStatus(x) (x)
#else
#define NtStatusToQuicStatus(x) HRESULT_FROM_WIN32(RtlNtStatusToDosError(x))
#endif

#ifdef _KERNEL_MODE
BCRYPT_ALG_HANDLE QUIC_HMAC_SHA256_ALG_HANDLE;
BCRYPT_ALG_HANDLE QUIC_HMAC_SHA384_ALG_HANDLE;
BCRYPT_ALG_HANDLE QUIC_HMAC_SHA512_ALG_HANDLE;
BCRYPT_ALG_HANDLE QUIC_AES_ECB_ALG_HANDLE;
BCRYPT_ALG_HANDLE QUIC_AES_GCM_ALG_HANDLE;
#else
BCRYPT_ALG_HANDLE QUIC_HMAC_SHA256_ALG_HANDLE = BCRYPT_HMAC_SHA256_ALG_HANDLE;
BCRYPT_ALG_HANDLE QUIC_HMAC_SHA384_ALG_HANDLE = BCRYPT_HMAC_SHA384_ALG_HANDLE;
BCRYPT_ALG_HANDLE QUIC_HMAC_SHA512_ALG_HANDLE = BCRYPT_HMAC_SHA512_ALG_HANDLE;
BCRYPT_ALG_HANDLE QUIC_AES_ECB_ALG_HANDLE = BCRYPT_AES_ECB_ALG_HANDLE;
BCRYPT_ALG_HANDLE QUIC_AES_GCM_ALG_HANDLE = BCRYPT_AES_GCM_ALG_HANDLE;
#endif

QUIC_STATUS
QuicTlsLibraryInitialize(
    void
    )
{
#ifdef _KERNEL_MODE
    ULONG Flags = BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_PROV_DISPATCH;
    NTSTATUS Status =
        BCryptOpenAlgorithmProvider(
            &QUIC_HMAC_SHA256_ALG_HANDLE,
            BCRYPT_SHA256_ALGORITHM,
            MS_PRIMITIVE_PROVIDER,
            Flags);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Open HMAC_SHA256 algorithm");
        goto Error;
    }

    Status =
        BCryptOpenAlgorithmProvider(
            &QUIC_HMAC_SHA384_ALG_HANDLE,
            BCRYPT_SHA384_ALGORITHM,
            MS_PRIMITIVE_PROVIDER,
            Flags);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Open HMAC_SHA384 algorithm");
        goto Error;
    }

    Status =
        BCryptOpenAlgorithmProvider(
            &QUIC_HMAC_SHA512_ALG_HANDLE,
            BCRYPT_SHA512_ALGORITHM,
            MS_PRIMITIVE_PROVIDER,
            Flags);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Open HMAC_SHA512 algorithm");
        goto Error;
    }

    Status =
        BCryptOpenAlgorithmProvider(
            &QUIC_AES_ECB_ALG_HANDLE,
            BCRYPT_AES_ALGORITHM,
            MS_PRIMITIVE_PROVIDER,
            BCRYPT_PROV_DISPATCH);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Open AES algorithm");
        goto Error;
    }

    Status =
        BCryptSetProperty(
            QUIC_AES_ECB_ALG_HANDLE,
            BCRYPT_CHAINING_MODE,
            (PBYTE)BCRYPT_CHAIN_MODE_ECB,
            sizeof(BCRYPT_CHAIN_MODE_ECB),
            0);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Set ECB chaining mode");
        goto Error;
    }

    Status =
        BCryptOpenAlgorithmProvider(
            &QUIC_AES_GCM_ALG_HANDLE,
            BCRYPT_AES_ALGORITHM,
            MS_PRIMITIVE_PROVIDER,
            BCRYPT_PROV_DISPATCH);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Open AES algorithm");
        goto Error;
    }

    Status =
        BCryptSetProperty(
            QUIC_AES_GCM_ALG_HANDLE,
            BCRYPT_CHAINING_MODE,
            (PBYTE)BCRYPT_CHAIN_MODE_GCM,
            sizeof(BCRYPT_CHAIN_MODE_GCM),
            0);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Set GCM chaining mode");
        goto Error;
    }

    QuicTraceLogVerbose(
        SchannelInitialized,
        "[ tls] Library initialized");

Error:

    if (!NT_SUCCESS(Status)) {
        if (QUIC_HMAC_SHA256_ALG_HANDLE) {
            BCryptCloseAlgorithmProvider(QUIC_HMAC_SHA256_ALG_HANDLE, 0);
            QUIC_HMAC_SHA256_ALG_HANDLE = NULL;
        }
        if (QUIC_HMAC_SHA384_ALG_HANDLE) {
            BCryptCloseAlgorithmProvider(QUIC_HMAC_SHA384_ALG_HANDLE, 0);
            QUIC_HMAC_SHA384_ALG_HANDLE = NULL;
        }
        if (QUIC_HMAC_SHA512_ALG_HANDLE) {
            BCryptCloseAlgorithmProvider(QUIC_HMAC_SHA512_ALG_HANDLE, 0);
            QUIC_HMAC_SHA512_ALG_HANDLE = NULL;
        }
        if (QUIC_AES_ECB_ALG_HANDLE) {
            BCryptCloseAlgorithmProvider(QUIC_AES_ECB_ALG_HANDLE, 0);
            QUIC_AES_ECB_ALG_HANDLE = NULL;
        }
        if (QUIC_AES_GCM_ALG_HANDLE) {
            BCryptCloseAlgorithmProvider(QUIC_AES_GCM_ALG_HANDLE, 0);
            QUIC_AES_GCM_ALG_HANDLE = NULL;
        }
    }

    return NtStatusToQuicStatus(Status);
#else
    QuicTraceLogVerbose(
        SchannelInitialized,
        "[ tls] Library initialized");
    return QUIC_STATUS_SUCCESS;
#endif
}

void
QuicTlsLibraryUninitialize(
    void
    )
{
#ifdef _KERNEL_MODE
    BCryptCloseAlgorithmProvider(QUIC_HMAC_SHA256_ALG_HANDLE, 0);
    BCryptCloseAlgorithmProvider(QUIC_HMAC_SHA384_ALG_HANDLE, 0);
    BCryptCloseAlgorithmProvider(QUIC_HMAC_SHA512_ALG_HANDLE, 0);
    BCryptCloseAlgorithmProvider(QUIC_AES_ECB_ALG_HANDLE, 0);
    BCryptCloseAlgorithmProvider(QUIC_AES_GCM_ALG_HANDLE, 0);
    QUIC_HMAC_SHA256_ALG_HANDLE = NULL;
    QUIC_HMAC_SHA384_ALG_HANDLE = NULL;
    QUIC_HMAC_SHA512_ALG_HANDLE = NULL;
    QUIC_AES_ECB_ALG_HANDLE = NULL;
    QUIC_AES_GCM_ALG_HANDLE = NULL;
#endif
    QuicTraceLogVerbose(
        SchannelUninitialized,
        "[ tls] Library uninitialized");
}

#ifndef _KERNEL_MODE
QUIC_STATUS
QuicTlsUtf8ToWideChar(
    _In_z_ const char* const Input,
    _Outptr_result_z_ PWSTR* Output
    )
{
    QUIC_DBG_ASSERT(Input != NULL);
    QUIC_DBG_ASSERT(Output != NULL);

    DWORD Error = NO_ERROR;
    PWSTR Buffer = NULL;
    int Size =
        MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            Input,
            -1,
            NULL,
            0);
    if (Size == 0) {
        Error = GetLastError();
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Error,
            "Get wchar string size");
        goto Error;
    }

    Buffer = QUIC_ALLOC_NONPAGED(sizeof(WCHAR) * Size);
    if (Buffer == NULL) {
        Error = ERROR_NOT_ENOUGH_MEMORY;
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "wchar string",
            sizeof(WCHAR) * Size);
        goto Error;
    }

    Size =
        MultiByteToWideChar(
            CP_UTF8,
            MB_ERR_INVALID_CHARS,
            Input,
            -1,
            Buffer,
            Size);
    if (Size == 0) {
        Error = GetLastError();
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Error,
            "Convert string to wchar");
        goto Error;
    }

    *Output = Buffer;
    Buffer = NULL;

Error:

    if (Buffer != NULL) {
        QUIC_FREE(Buffer);
    }

    return HRESULT_FROM_WIN32(Error);
}
#endif

#ifdef _KERNEL_MODE

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsUtf8ToUnicodeString(
    _In_z_ const char* Input,
    _Inout_ PUNICODE_STRING Output
    )
{
    QUIC_DBG_ASSERT(Input != NULL);
    QUIC_DBG_ASSERT(Output != NULL);

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

    UnicodeString = QUIC_ALLOC_NONPAGED(RequiredSize);
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

    QUIC_DBG_ASSERT(Output->Buffer == NULL);
    Output->Buffer = UnicodeString;
    UnicodeString = NULL;

    Output->MaximumLength = (USHORT)RequiredSize;
    Output->Length = Output->MaximumLength - sizeof(WCHAR);

Error:
    if (UnicodeString != NULL) {
        QUIC_FREE(UnicodeString);
        UnicodeString = NULL;
    }
    return Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicTlsAllocateAchaContext(
    _In_ void* Context,
    _In_ QUIC_SEC_CONFIG_CREATE_COMPLETE_HANDLER Callback,
    _In_ QUIC_SERVER_SEC_CONFIG* Config,
    _Out_ QUIC_ACHA_CONTEXT** AchaContext
    )
{
    QUIC_DBG_ASSERT(AchaContext != NULL);

    QUIC_ACHA_CONTEXT* NewAchaContext = QUIC_ALLOC_NONPAGED(sizeof(QUIC_ACHA_CONTEXT));
    if (NewAchaContext == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_ACHA_CONTEXT",
            sizeof(QUIC_ACHA_CONTEXT));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    RtlZeroMemory(NewAchaContext, sizeof(*NewAchaContext));
    NewAchaContext->CompletionContext = Context;
    NewAchaContext->CompletionCallback = Callback;
    NewAchaContext->SecConfig = Config;
    *AchaContext = NewAchaContext;

    return QUIC_STATUS_SUCCESS;
}

void
QuicTlsFreeAchaContext(
    _In_ QUIC_ACHA_CONTEXT* AchaContext
    )
{
    if (AchaContext->Principal.Buffer != NULL) {
        QUIC_FREE(AchaContext->Principal.Buffer);
        RtlZeroMemory(&AchaContext->Principal, sizeof(AchaContext->Principal));
    }
    QUIC_FREE(AchaContext);
}

void
QuicTlsSspiNotifyCallback(
    _In_     SspiAsyncContext* Handle,
    _In_opt_ void*  CallbackData
    )
{
    if (CallbackData == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "NULL CallbackData to QuicTlsSspiNotifyCallback");
        return;
    }
    QUIC_ACHA_CONTEXT* Context = CallbackData;
    QUIC_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionCallback = Context->CompletionCallback;
    void* CompletionContext = Context->CompletionContext;
    QUIC_SEC_CONFIG* SecConfig = (QUIC_SEC_CONFIG*)Context->SecConfig;
    SECURITY_STATUS Status = SspiGetAsyncCallStatus(Handle);
    QuicTlsFreeAchaContext(Context);
    if (Status != SEC_E_OK) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "Completion for SspiAcquireCredentialsHandleAsyncW");
        CompletionCallback(CompletionContext, SecStatusToQuicStatus(Status), NULL);
        QuicTlsSecConfigRelease(SecConfig); // *MUST* be last call to prevent crash in platform cleanup.
    } else {
        CompletionCallback(CompletionContext, QUIC_STATUS_SUCCESS, SecConfig);
    }
}

//
// Used by QuicTlsServerSecConfigCreate and QuicTlsInitialize
//
const static UNICODE_STRING QuicTlsPackageName = RTL_CONSTANT_STRING(L"Schannel");

#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsServerSecConfigDelete(
    __drv_freesMem(ServerConfig) _Frees_ptr_ _In_ QUIC_SERVER_SEC_CONFIG* ServerConfig
    )
{
    QUIC_DBG_ASSERT(ServerConfig->IsServer == TRUE);
#ifdef _KERNEL_MODE
    if (ServerConfig->SspiContext != NULL) {
        SspiFreeAsyncContext(ServerConfig->SspiContext);
    }
    if (SecIsValidHandle(&ServerConfig->CertificateHandle)) {
        FreeCredentialsHandle(&ServerConfig->CertificateHandle);
    }
#endif

    QUIC_RUNDOWN_REF* Rundown = ServerConfig->CleanupRundown;
    QUIC_DBG_ASSERT(Rundown != NULL);
    QUIC_FREE(ServerConfig);
    QuicRundownRelease(Rundown);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsServerSecConfigCreate(
    _Inout_ QUIC_RUNDOWN_REF* Rundown,
    _In_ QUIC_SEC_CONFIG_FLAGS Flags,
    _When_(Flags & QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH, _In_)
    _When_(Flags & QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH_STORE, _In_)
    _When_(Flags & QUIC_SEC_CONFIG_FLAG_CERTIFICATE_CONTEXT, _In_)
    _When_(Flags & QUIC_SEC_CONFIG_FLAG_CERTIFICATE_NONE, _In_opt_)
        void* Certificate,
    _When_(Flags& QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH, _In_opt_z_)
    _When_(Flags& QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH_STORE, _In_opt_z_)
    _When_(Flags& QUIC_SEC_CONFIG_FLAG_CERTIFICATE_CONTEXT, _In_opt_z_)
    _When_(Flags & QUIC_SEC_CONFIG_FLAG_CERTIFICATE_NONE, _In_z_)
        const char* Principal,
    _In_opt_ void* Context,
    _In_ QUIC_SEC_CONFIG_CREATE_COMPLETE_HANDLER CompletionHandler
    )
{
    SECURITY_STATUS SecStatus;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (CompletionHandler == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (Flags & QUIC_SEC_CONFIG_FLAG_CERTIFICATE_CONTEXT) {
        if (Certificate == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    } else if ((Flags & (QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH | QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH_STORE)) == 0) {
        if (Principal == NULL) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
    }

    if (Flags & QUIC_SEC_CONFIG_FLAG_CERTIFICATE_FILE) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    if (Certificate == NULL && Principal == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    QUIC_DBG_ASSERT(Rundown != NULL);
    if (!QuicRundownAcquire(Rundown)) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Acquire SecConfig rundown");
        return QUIC_STATUS_INVALID_STATE;
    }

#pragma prefast(suppress: __WARNING_6014, "Memory is correctly freed (QuicTlsSecConfigDelete)")
    QUIC_SERVER_SEC_CONFIG* Config = QUIC_ALLOC_NONPAGED(sizeof(QUIC_SERVER_SEC_CONFIG));
    if (Config == NULL) {
        QuicRundownRelease(Rundown);
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_SERVER_SEC_CONFIG",
            sizeof(QUIC_SERVER_SEC_CONFIG));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    RtlZeroMemory(Config, sizeof(QUIC_SERVER_SEC_CONFIG));
    SecInvalidateHandle(&Config->CertificateHandle);
    Config->CleanupRundown = Rundown;
    Config->RefCount = 1;
    Config->IsServer = TRUE;

#ifdef _KERNEL_MODE
    QUIC_ACHA_CONTEXT* AchaContext = NULL;
    Status = QuicTlsAllocateAchaContext(Context, CompletionHandler, Config, &AchaContext);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    PSCH_CREDENTIALS Credentials = &AchaContext->Credentials;
    Credentials->pTlsParameters = &AchaContext->TlsParameters;
    Credentials->cTlsParameters = 1;
#else
    SCH_CREDENTIALS LocalCredentials = { 0 };
    TLS_PARAMETERS LocalTlsParameters = { 0 };
    PSCH_CREDENTIALS Credentials = &LocalCredentials;
    Credentials->pTlsParameters = &LocalTlsParameters;
    Credentials->cTlsParameters = 1;
#endif

    //
    // Initialize user/kernel-common configuration.
    //
    Credentials->dwVersion = SCH_CREDENTIALS_VERSION;
    Credentials->pTlsParameters->grbitDisabledProtocols = (DWORD) ~SP_PROT_TLS1_3_SERVER;
    Credentials->pTlsParameters->cAlpnIds = 0;
    Credentials->pTlsParameters->rgstrAlpnIds = NULL; // QUIC manages all the ALPN matching.
    Credentials->pTlsParameters->cDisabledCrypto = 0;
    //
    // TODO: Disallow AES_CCM_8 algorithm, which are undefined in the QUIC-TLS spec.
    //
    Credentials->pTlsParameters->pDisabledCrypto = NULL;
    Credentials->dwFlags |= SCH_CRED_NO_SYSTEM_MAPPER;

    //
    // This flag disables known-weak crypto algorithms.
    //
    Credentials->dwFlags |= SCH_USE_STRONG_CRYPTO;

    if (Flags & QUIC_SEC_CONFIG_FLAG_ENABLE_OCSP) {
        Credentials->dwFlags |= SCH_CRED_SNI_ENABLE_OCSP;
    }

    //
    // Kernel mode-only APIs and configuration.
    //
#ifdef _KERNEL_MODE

    Config->SspiContext = SspiCreateAsyncContext();
    if (Config->SspiContext == NULL) {
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "SspiCreateAsyncContext");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    SecStatus =
        SspiSetAsyncNotifyCallback(
            Config->SspiContext,
            QuicTlsSspiNotifyCallback,
            AchaContext);
    if (SecStatus != SEC_E_OK) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SecStatus,
            "SspiSetAsyncNotifyCallback");
        Status = SecStatusToQuicStatus(SecStatus);
        goto Error;
    }

    //
    // Set the parameters and then call ACHA.
    //
    if (Flags & QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH) {
        if (Certificate == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Error;
        }
        QUIC_CERTIFICATE_HASH* CertHash = Certificate;
        AchaContext->CertHash.dwLength = sizeof(AchaContext->CertHash);
        AchaContext->CertHash.dwFlags |= SCH_MACHINE_CERT_HASH;
        AchaContext->CertHash.hProv = 0;

        RtlCopyMemory(
            AchaContext->CertHash.ShaHash,
            CertHash->ShaHash,
            sizeof(AchaContext->CertHash.ShaHash));

        //
        // Assume the Machine MY store if unspecified.
        //
        RtlCopyMemory(AchaContext->CertHash.pwszStoreName, L"MY", sizeof(L"MY"));

        Credentials->cCreds = 1;
        Credentials->paCred = (PVOID)&AchaContext->CertHash;
        Credentials->dwCredFormat = SCH_CRED_FORMAT_CERT_HASH_STORE;
        Credentials->dwFlags |= SCH_MACHINE_CERT_HASH;

    } else if (Flags & QUIC_SEC_CONFIG_FLAG_CERTIFICATE_HASH_STORE) {
        if (Certificate == NULL) {
            Status = QUIC_STATUS_INVALID_PARAMETER;
            goto Error;
        }
        QUIC_CERTIFICATE_HASH_STORE* CertHashStore = Certificate;

        AchaContext->CertHash.dwLength = sizeof(AchaContext->CertHash);
        AchaContext->CertHash.dwFlags |= CertHashStore->Flags;
        AchaContext->CertHash.hProv = 0;

        RtlCopyMemory(
            AchaContext->CertHash.ShaHash,
            &(CertHashStore->ShaHash),
            sizeof(AchaContext->CertHash.ShaHash));

#pragma warning(push)
#pragma warning(disable:6387) // Parameter 3 is allowed to be NULL when the value isn't wanted.
#pragma warning(disable:6385) // SAL ignores the annotations on strnlen_s because of the (ULONG) cast. Probably.
        Status =
            RtlUTF8ToUnicodeN(
                AchaContext->CertHash.pwszStoreName,
                sizeof(AchaContext->CertHash.pwszStoreName),
                NULL,
                CertHashStore->StoreName,
                (ULONG) strnlen_s(
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
        Credentials->paCred = (PVOID)&AchaContext->CertHash;
        Credentials->dwCredFormat = SCH_CRED_FORMAT_CERT_HASH_STORE;
        Credentials->dwFlags |= SCH_MACHINE_CERT_HASH;

    } else if (Principal != NULL) {
        //
        // No certificate hashes present, only use Principal.
        //
        Credentials->cCreds = 0;
        Credentials->paCred = NULL;
    } else {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        QuicTraceEvent(
            LibraryError,
            "[ lib] ERROR, %s.",
            "Invalid flags passed in to QuicTlsSecConfigCreate");
        goto Error;
    }

    if (Principal != NULL) {

        Status = QuicTlsUtf8ToUnicodeString(Principal, &AchaContext->Principal);
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

    SecStatus =
        SspiAcquireCredentialsHandleAsyncW(
            Config->SspiContext,
            &AchaContext->Principal,
            (PUNICODE_STRING) &QuicTlsPackageName,
            SECPKG_CRED_INBOUND,
            NULL,
            &AchaContext->Credentials,
            NULL,
            NULL,
            &Config->CertificateHandle,
            NULL);
    if (SecStatus != SEC_E_OK) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SecStatus,
            "SspiAcquireCredentialsHandleAsyncW");
        Status = SecStatusToQuicStatus(SecStatus);
        goto Error;
    }

    Status = QUIC_STATUS_PENDING;
    AchaContext = NULL;
#else
    //
    // User mode-only APIs and configuration.
    //

    TimeStamp CredExpiration;
    PCERT_CONTEXT CertContext = NULL;

    Status =
        QuicCertCreate(
            Flags,
            Certificate,
            Principal,
            &CertContext);
    if (QUIC_FAILED(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "QuicCertCreate");
        goto Error;
    }

    Credentials->cCreds = 1;
    Credentials->paCred = &CertContext;

    QuicTraceLogVerbose(
        SchannelAch,
        "[ tls] Calling ACH to create server security config");

    SecStatus =
        AcquireCredentialsHandleW(
            NULL,
            UNISP_NAME_W,
            SECPKG_CRED_INBOUND,
            NULL,
            Credentials,
            NULL,
            NULL,
            &Config->CertificateHandle,
            &CredExpiration);
    if (SecStatus != SEC_E_OK) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SecStatus,
            "AcquireCredentialsHandleW");
        Status = SecStatusToQuicStatus(SecStatus);
        goto Error;
    }

    //
    // In user mode, call the completion in-line.
    //
    QuicTraceLogVerbose(
        SchannelAchCompleteInline,
        "[ tls] Invoking security config completion callback, 0x%x",
        SecStatus);
    CompletionHandler(Context, SecStatusToQuicStatus(SecStatus), (QUIC_SEC_CONFIG*)Config);
    Status = QUIC_STATUS_PENDING;
#endif

    //
    // The completion handler will return the context to caller, so we can clear it here.
    //
    Config = NULL;

Error:

    if (Config != NULL) {
        QuicTlsServerSecConfigDelete(Config);
        Config = NULL;
    }

#ifdef _KERNEL_MODE
    if (AchaContext != NULL) {
        QuicTlsFreeAchaContext(AchaContext);
    }
#else
    if (CertContext != NULL && CertContext != Certificate) {
         CertFreeCertificateContext(CertContext);
    }
#endif

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsClientSecConfigDelete(
    __drv_freesMem(ClientConfig) _Frees_ptr_ _In_ QUIC_CLIENT_SEC_CONFIG* ClientConfig
    )
{
    QUIC_DBG_ASSERT(ClientConfig->IsServer == FALSE);

    if (SecIsValidHandle(&ClientConfig->SchannelHandle)) {
        FreeCredentialsHandle(&ClientConfig->SchannelHandle);
        SecInvalidateHandle(&ClientConfig->SchannelHandle);
    }

    QUIC_FREE(ClientConfig);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsClientSecConfigCreate(
    _In_ uint32_t Flags,
    _Outptr_ QUIC_SEC_CONFIG** ClientConfig
    )
{
    TimeStamp CredExpiration;
    TLS_PARAMETERS TlsParameters = { 0 };
    SCH_CREDENTIALS SchannelCred = { 0 };
    SECURITY_STATUS SecStatus;
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (ClientConfig == NULL) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }

    QUIC_CLIENT_SEC_CONFIG* Config = QUIC_ALLOC_PAGED(sizeof(QUIC_CLIENT_SEC_CONFIG));
    if (Config == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_CLIENT_SEC_CONFIG", sizeof(QUIC_CLIENT_SEC_CONFIG));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }

    SecInvalidateHandle(&Config->SchannelHandle);
    Config->IsServer = FALSE;
    Config->RefCount = 1;

    SchannelCred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS;
    SchannelCred.dwFlags |= SCH_USE_STRONG_CRYPTO;
    if (Flags & QUIC_CERTIFICATE_FLAG_DISABLE_CERT_VALIDATION) {
        SchannelCred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
    } else if (Flags != 0) {
        //
        // TODO - Schannel support for direct passthrough for certificate ignore
        // flags (Flags variable).
        //
        SchannelCred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
    }

    TlsParameters.grbitDisabledProtocols = (DWORD) ~SP_PROT_TLS1_3_CLIENT;
    TlsParameters.cAlpnIds = 0;
    TlsParameters.rgstrAlpnIds = NULL; // Only used on server.
    TlsParameters.cDisabledCrypto = 0;
    //
    // TODO: Disallow AES_CCM_8 algorithm, which are undefined in the QUIC-TLS spec.
    //
    TlsParameters.pDisabledCrypto = NULL;
    SchannelCred.cTlsParameters = 1;
    SchannelCred.pTlsParameters = &TlsParameters;
    SchannelCred.dwVersion = SCH_CREDENTIALS_VERSION;
#ifdef _KERNEL_MODE
    PSECURITY_STRING PackageName = (PSECURITY_STRING) &QuicTlsPackageName;
#else
    WCHAR* PackageName = UNISP_NAME_W;
#endif
    SecStatus =
        AcquireCredentialsHandleW(
            NULL,
            PackageName,
            SECPKG_CRED_OUTBOUND,
            NULL,
            &SchannelCred,
            NULL,
            NULL,
            &Config->SchannelHandle,
            &CredExpiration);
    if (SecStatus != SEC_E_OK) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            SecStatus,
            "AcquireCredentialsHandleW");
        Status = SecStatusToQuicStatus(SecStatus);
        QUIC_DBG_ASSERT(QUIC_FAILED(Status));
        goto Error;
    }

    *ClientConfig = (QUIC_SEC_CONFIG*)Config;
    Config = NULL;
    Status = QUIC_STATUS_SUCCESS;

Error:
    if (Config != NULL) {
        QuicTlsClientSecConfigDelete(Config);
    }

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_SEC_CONFIG*
QuicTlsSecConfigAddRef(
    _In_ QUIC_SEC_CONFIG* SecurityConfig
    )
{
    InterlockedIncrement(&SecurityConfig->RefCount);
    return SecurityConfig;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QUIC_API
QuicTlsSecConfigRelease(
    _In_ QUIC_SEC_CONFIG* SecurityConfig
    )
{
    if (InterlockedDecrement(&SecurityConfig->RefCount) == 0) {

        if (SecurityConfig->IsServer) {
            QuicTlsServerSecConfigDelete((QUIC_SERVER_SEC_CONFIG*)SecurityConfig);
        } else {
            QuicTlsClientSecConfigDelete((QUIC_CLIENT_SEC_CONFIG*)SecurityConfig);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsSessionInitialize(
    _Out_ QUIC_TLS_SESSION** NewTlsSession
    )
{
    *NewTlsSession = QUIC_ALLOC_NONPAGED(sizeof(QUIC_TLS_SESSION));
    if (*NewTlsSession == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_TLS_SESSION",
            sizeof(QUIC_TLS_SESSION));
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    return QUIC_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsSessionUninitialize(
    _In_opt_ QUIC_TLS_SESSION* TlsSession
    )
{
    if (TlsSession != NULL) {
        QUIC_FREE(TlsSession);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsSessionSetTicketKey(
    _In_ QUIC_TLS_SESSION* TlsSession,
    _In_reads_bytes_(44)
        const void* Buffer
    )
{
    UNREFERENCED_PARAMETER(TlsSession);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsSessionAddTicket(
    _In_ QUIC_TLS_SESSION* TlsSession,
    _In_ uint32_t BufferLength,
    _In_reads_bytes_(BufferLength)
        const uint8_t * const Buffer
    )
{
    UNREFERENCED_PARAMETER(TlsSession);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsInitialize(
    _In_ const QUIC_TLS_CONFIG* Config,
    _Inout_ QUIC_TLS_PROCESS_STATE* State,
    _Out_ QUIC_TLS** NewTlsContext
    )
{
    UNREFERENCED_PARAMETER(Config->Connection);

    const ULONG AppProtocolsSize =
        (ULONG)(Config->AlpnBufferLength +
            FIELD_OFFSET(SEC_APPLICATION_PROTOCOLS, ProtocolLists) +
            FIELD_OFFSET(SEC_APPLICATION_PROTOCOL_LIST, ProtocolList));
    const size_t TlsSize = sizeof(QUIC_TLS) + (size_t)AppProtocolsSize;

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    QUIC_TLS* TlsContext = QUIC_ALLOC_NONPAGED(TlsSize);
    if (TlsContext == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_TLS",
            sizeof(QUIC_TLS));
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }

    QUIC_ANALYSIS_ASSUME(sizeof(*TlsContext) < TlsSize); // This should not be necessary.
    RtlZeroMemory(TlsContext, sizeof(*TlsContext));
    SecInvalidateHandle(&TlsContext->SchannelContext);

    TlsContext->IsServer = Config->IsServer;
    TlsContext->TlsSession = Config->TlsSession;

    QuicTraceLogConnVerbose(
        SchannelContextCreated,
        TlsContext->Connection,
        "Created");

    TlsContext->AppProtocolsSize = AppProtocolsSize;
    TlsContext->ApplicationProtocols = (SEC_APPLICATION_PROTOCOLS*)(TlsContext + 1);
    TlsContext->ApplicationProtocols->ProtocolListsSize =
        (ULONG)(FIELD_OFFSET(SEC_APPLICATION_PROTOCOL_LIST, ProtocolList) + Config->AlpnBufferLength);

    SEC_APPLICATION_PROTOCOL_LIST* AlpnList = &TlsContext->ApplicationProtocols->ProtocolLists[0];
    AlpnList->ProtoNegoExt = SecApplicationProtocolNegotiationExt_ALPN;
    AlpnList->ProtocolListSize = Config->AlpnBufferLength;
    memcpy(&AlpnList->ProtocolList, Config->AlpnBuffer, Config->AlpnBufferLength);

    TlsContext->TransportParams = (SEND_GENERIC_TLS_EXTENSION*)Config->LocalTPBuffer;
    TlsContext->TransportParams->ExtensionType = TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS;
    TlsContext->TransportParams->HandshakeType =
        Config->IsServer ? TlsHandshake_EncryptedExtensions : TlsHandshake_ClientHello;
    TlsContext->TransportParams->Flags = 0;
    TlsContext->TransportParams->BufferSize =
        (uint16_t)(Config->LocalTPLength - FIELD_OFFSET(SEND_GENERIC_TLS_EXTENSION, Buffer));

    //
    // Associate the existing security config with this TLS context.
    //
    TlsContext->SecConfig = QuicTlsSecConfigAddRef(Config->SecConfig);
    TlsContext->Connection = Config->Connection;
    TlsContext->ReceiveTPCallback = Config->ReceiveTPCallback;
    TlsContext->SNI = Config->ServerName;

    State->EarlyDataState = QUIC_TLS_EARLY_DATA_UNSUPPORTED; // 0-RTT not currently supported.

    Status = QUIC_STATUS_SUCCESS;
    *NewTlsContext = TlsContext;
    TlsContext = NULL;

Error:
    if (TlsContext) {
        if (TlsContext->SecConfig != NULL) {
            QuicTlsSecConfigRelease(TlsContext->SecConfig);
        }
        QUIC_FREE(TlsContext);
    }
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
inline
static
void
QuicTlsResetSchannel(
    _In_ QUIC_TLS* TlsContext
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
        QuicZeroMemory(&TlsContext->Workspace, sizeof(TlsContext->Workspace));
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsUninitialize(
    _In_opt_ QUIC_TLS* TlsContext
    )
{
    if (TlsContext != NULL) {
        QuicTraceLogConnVerbose(
            SchannelContextCleaningUp,
            TlsContext->Connection,
            "Cleaning up");

        QuicTlsResetSchannel(TlsContext);
        if (TlsContext->SecConfig != NULL) {
            QuicTlsSecConfigRelease(TlsContext->SecConfig);
        }
        if (TlsContext->TransportParams != NULL) {
            QUIC_FREE(TlsContext->TransportParams);
        }
        QUIC_FREE(TlsContext);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicTlsReset(
    _In_ QUIC_TLS* TlsContext
    )
{
    QuicTraceLogConnInfo(
        SchannelContextReset,
        TlsContext->Connection,
        "Resetting TLS state");

    //
    // Clean up and then re-create Schannel state.
    //
    QuicTlsResetSchannel(TlsContext);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_SEC_CONFIG*
QuicTlsGetSecConfig(
    _In_ QUIC_TLS* TlsContext
    )
{
    return QuicTlsSecConfigAddRef(TlsContext->SecConfig);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_TLS_RESULT_FLAGS
QuicTlsWriteDataToSchannel(
    _In_ QUIC_TLS* TlsContext,
    _In_reads_(*InBufferLength)
        const uint8_t* InBuffer,
    _Inout_ uint32_t* InBufferLength,
    _Inout_ QUIC_TLS_PROCESS_STATE* State
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
        QUIC_DBG_ASSERT(TlsContext->IsServer == FALSE);

        if (TlsContext->SNI != NULL) {
#ifdef _KERNEL_MODE
            TargetServerName = &ServerName;
            QUIC_STATUS Status = QuicTlsUtf8ToUnicodeString(TlsContext->SNI, TargetServerName);
#else
            QUIC_STATUS Status = QuicTlsUtf8ToWideChar(TlsContext->SNI, &TargetServerName);
#endif
            if (QUIC_FAILED(Status)) {
                QuicTraceEvent(
                    TlsErrorStatus,
                    "[ tls][%p] ERROR, %u, %s.",
                    TlsContext->Connection,
                    Status,
                    "Convert SNI to unicode");
                return QUIC_TLS_RESULT_ERROR;
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
    static_assert(
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
    OutSecBuffers[OutSecBufferDesc.cBuffers].BufferType = SECBUFFER_EMPTY;
    OutSecBuffers[OutSecBufferDesc.cBuffers].cbBuffer = sizeof(AlertBufferRaw);
    OutSecBuffers[OutSecBufferDesc.cBuffers].pvBuffer = &AlertBufferRaw;
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
    if (*InBufferLength != 0 && !TlsContext->PeerTransportParamsReceived) {
        //
        // Subscribe to get the peer's transport parameters, if available.
        //
        SubscribeExt.Flags = 0;
        SubscribeExt.SubscriptionsCount = 1;
        SubscribeExt.Subscriptions[0].ExtensionType =
            TLS_EXTENSION_TYPE_QUIC_TRANSPORT_PARAMETERS;
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
        OutSecBuffers[OutSecBufferDesc.cBuffers].cbBuffer = *InBufferLength;
        OutSecBuffers[OutSecBufferDesc.cBuffers].pvBuffer = (void*)InBuffer; // Overwrite the input buffer with the extension.
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

    ULONG ContextReq =
        ISC_REQ_SEQUENCE_DETECT |
        ISC_REQ_CONFIDENTIALITY |
        ISC_RET_EXTENDED_ERROR |
        ISC_REQ_STREAM;
    ULONG ContextAttr;
    SECURITY_STATUS SecStatus;

    if (TlsContext->IsServer) {
        QUIC_SERVER_SEC_CONFIG* SecConfig = (QUIC_SERVER_SEC_CONFIG*)TlsContext->SecConfig;
        QUIC_DBG_ASSERT(SecConfig->IsServer == TRUE);

        SecStatus =
            AcceptSecurityContext(
                &SecConfig->CertificateHandle,
                SecIsValidHandle(&TlsContext->SchannelContext) ? &TlsContext->SchannelContext : NULL,
                &InSecBufferDesc,
                ContextReq,
                0,
                &(TlsContext->SchannelContext),
                &OutSecBufferDesc,
                &ContextAttr,
                NULL); // FYI, used for client authentication certificate.

    } else {
        QUIC_CLIENT_SEC_CONFIG* SecConfig = (QUIC_CLIENT_SEC_CONFIG*)TlsContext->SecConfig;
        QUIC_DBG_ASSERT(SecConfig->IsServer == FALSE);

        SecStatus =
            InitializeSecurityContextW(
                &SecConfig->SchannelHandle,
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

    QUIC_TLS_RESULT_FLAGS Result = 0;

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
            OutSecBufferDesc.pBuffers[i].BufferType == SECBUFFER_ALERT) {
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
                TrafficSecret->TrafficSecretType,
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
        if (!TlsContext->PeerTransportParamsReceived) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "No QUIC TP received");
            Result |= QUIC_TLS_RESULT_ERROR;
            break;
        }

        if (TlsContext->TransportParams != NULL) {
            //
            // Done with the transport parameters. Clear them out so we don't
            // try to send them again.
            //
            QUIC_FREE(TlsContext->TransportParams);
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
                    Result |= QUIC_TLS_RESULT_ERROR;
                    break;
                }
                if (NegotiatedAlpn.ProtoNegoStatus != SecApplicationProtocolNegotiationStatus_Success) {
                    QuicTraceEvent(
                        TlsErrorStatus,
                        "[ tls][%p] ERROR, %u, %s.",
                        TlsContext->Connection,
                        NegotiatedAlpn.ProtoNegoStatus,
                        "ALPN negotiation status");
                    Result |= QUIC_TLS_RESULT_ERROR;
                    break;
                }
                const SEC_APPLICATION_PROTOCOL_LIST* AlpnList =
                    &TlsContext->ApplicationProtocols->ProtocolLists[0];
                State->NegotiatedAlpn =
                    QuicTlsAlpnFindInList(
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
                    Result |= QUIC_TLS_RESULT_ERROR;
                    break;
                }
            }

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
                Result |= QUIC_TLS_RESULT_ERROR;
                break;
            }
            if (SessionInfo.dwFlags & SSL_SESSION_RECONNECT) {
                State->SessionResumed = TRUE;
            }

            QuicTraceLogConnInfo(
                SchannelHandshakeComplete,
                TlsContext->Connection,
                "Handshake complete (resume=%hu)",
                State->SessionResumed);
            State->HandshakeComplete = TRUE;
            Result |= QUIC_TLS_RESULT_COMPLETE;
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
            Result |= QUIC_TLS_RESULT_ERROR;
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
            QUIC_DBG_ASSERT(InSecBuffers[1].cbBuffer <= *InBufferLength);
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
            Result |= QUIC_TLS_RESULT_READ_KEY_UPDATED;
            if (NewPeerTrafficSecrets[i]->TrafficSecretType == SecTrafficSecret_ClientEarlyData) {
                QUIC_FRE_ASSERT(FALSE); // TODO - Finish the 0-RTT logic.
            } else {
                if (State->ReadKey == QUIC_PACKET_KEY_INITIAL) {
                    if (!QuicPacketKeyCreate(
                            TlsContext,
                            QUIC_PACKET_KEY_HANDSHAKE,
                            "peer handshake traffic secret",
                            NewPeerTrafficSecrets[i],
                            &State->ReadKeys[QUIC_PACKET_KEY_HANDSHAKE])) {
                        Result |= QUIC_TLS_RESULT_ERROR;
                        break;
                    }
                    State->ReadKey = QUIC_PACKET_KEY_HANDSHAKE;
                    QuicTraceLogConnInfo(
                        SchannelReadHandshakeStart,
                        TlsContext->Connection,
                        "Reading Handshake data starts now");
                } else if (State->ReadKey == QUIC_PACKET_KEY_HANDSHAKE) {
                    if (!QuicPacketKeyCreate(
                            TlsContext,
                            QUIC_PACKET_KEY_1_RTT,
                            "peer application traffic secret",
                            NewPeerTrafficSecrets[i],
                            &State->ReadKeys[QUIC_PACKET_KEY_1_RTT])) {
                        Result |= QUIC_TLS_RESULT_ERROR;
                        break;
                    }
                    State->ReadKey = QUIC_PACKET_KEY_1_RTT;
                    QuicTraceLogConnInfo(
                        SchannelRead1RttStart,
                        TlsContext->Connection,
                        "Reading 1-RTT data starts now");
                }
            }
        }

        //
        // Update our "write" state based on any of our own keys being available
        //
        for (uint8_t i = 0; i < NewOwnTrafficSecretsCount; ++i) {
            Result |= QUIC_TLS_RESULT_WRITE_KEY_UPDATED;
            if (NewOwnTrafficSecrets[i]->TrafficSecretType == SecTrafficSecret_ClientEarlyData) {
                QUIC_FRE_ASSERT(FALSE); // TODO - Finish the 0-RTT logic.
            } else {
                if (State->WriteKey == QUIC_PACKET_KEY_INITIAL) {
                    if (!QuicPacketKeyCreate(
                            TlsContext,
                            QUIC_PACKET_KEY_HANDSHAKE,
                            "own handshake traffic secret",
                            NewOwnTrafficSecrets[i],
                            &State->WriteKeys[QUIC_PACKET_KEY_HANDSHAKE])) {
                        Result |= QUIC_TLS_RESULT_ERROR;
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
                            Result |= QUIC_TLS_RESULT_ERROR;
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
                    }
                }
            }
        }

        if (OutputTokenBuffer != NULL && OutputTokenBuffer->cbBuffer > 0) {
            //
            // There is output data to send back.
            //
            Result |= QUIC_TLS_RESULT_DATA;
            TlsContext->GeneratedFirstPayload = TRUE;

            QUIC_FRE_ASSERT(OutputTokenBuffer->cbBuffer <= 0xFFFF);
            QUIC_DBG_ASSERT((uint16_t)OutputTokenBuffer->cbBuffer <= (State->BufferAllocLength - State->BufferLength));
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
            Result |= QUIC_TLS_RESULT_ERROR;
            break;
        }

        //
        // We received the peer's transport parameters and need to decode
        // them.
        //
        if (!TlsContext->ReceiveTPCallback(
                TlsContext->Connection,
                (uint16_t)(TlsExtensionBuffer->cbBuffer - 4),
                ((uint8_t*)TlsExtensionBuffer->pvBuffer) + 4)) {
            QuicTraceEvent(
                TlsError,
                "[ tls][%p] ERROR, %s.",
                TlsContext->Connection,
                "Process QUIC TP");
            Result |= QUIC_TLS_RESULT_ERROR;
            break;
        }

        TlsContext->PeerTransportParamsReceived = TRUE;
        Result |= QUIC_TLS_RESULT_CONTINUE;

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

    default:
        //
        // Some other error occurred and we should indicate no data could be
        // processed successfully.
        //
        *InBufferLength = 0;
        QuicTraceEvent(
            TlsErrorStatus,
            "[ tls][%p] ERROR, %u, %s.",
            TlsContext->Connection,
            SecStatus,
            "Accept/InitializeSecurityContext");
        Result |= QUIC_TLS_RESULT_ERROR;
        break;
    }

#ifdef _KERNEL_MODE
    if (ServerName.Buffer != NULL) {
        QUIC_FREE(ServerName.Buffer);
    }
#else
    if (TargetServerName != NULL) {
        QUIC_FREE(TargetServerName);
    }
#endif

    return Result;
}


_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_TLS_RESULT_FLAGS
QuicTlsProcessData(
    _In_ QUIC_TLS* TlsContext,
    _In_ QUIC_TLS_DATA_TYPE DataType,
    _In_reads_bytes_(*BufferLength)
        const uint8_t * Buffer,
    _Inout_ uint32_t * BufferLength,
    _Inout_ QUIC_TLS_PROCESS_STATE* State
    )
{
    QUIC_TLS_RESULT_FLAGS Result = 0;
    if (DataType == QUIC_TLS_TICKET_DATA) {
        Result = QUIC_TLS_RESULT_ERROR;

        QuicTraceLogConnVerbose(
            SchannelProcessingData,
            TlsContext->Connection,
            "Ignoring %u ticket bytes",
            *BufferLength);
        goto Error;
    }

    QuicTraceLogConnVerbose(
        SchannelProcessingData,
        TlsContext->Connection,
        "Processing %u received bytes",
        *BufferLength);

    Result =
        QuicTlsWriteDataToSchannel(
            TlsContext,
            Buffer,
            BufferLength,
            State);
    if ((Result & QUIC_TLS_RESULT_ERROR) != 0) {
        goto Error;
    }

    if (Result & QUIC_TLS_RESULT_CONTINUE) {
        Result &= ~QUIC_TLS_RESULT_CONTINUE;
        Result |=
            QuicTlsWriteDataToSchannel(
                TlsContext,
                Buffer,
                BufferLength,
                State);
        if ((Result & QUIC_TLS_RESULT_ERROR) != 0) {
            goto Error;
        }
    }

Error:

    return Result;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_TLS_RESULT_FLAGS
QuicTlsProcessDataComplete(
    _In_ QUIC_TLS* TlsContext,
    _Out_ uint32_t * BufferConsumed
    )
{
    UNREFERENCED_PARAMETER(TlsContext);
    *BufferConsumed = 0;
    return QUIC_TLS_RESULT_ERROR;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsReadTicket(
    _In_ QUIC_TLS* TlsContext,
    _Inout_ uint32_t* BufferLength,
    _Out_writes_bytes_opt_(*BufferLength)
        uint8_t* Buffer
    )
{
    UNREFERENCED_PARAMETER(TlsContext);
    UNREFERENCED_PARAMETER(BufferLength);
    UNREFERENCED_PARAMETER(Buffer);
    return QUIC_STATUS_INVALID_STATE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsParamSet(
    _In_ QUIC_TLS* TlsContext,
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
QuicTlsParamGet(
    _In_ QUIC_TLS* TlsContext,
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

        default:
            Status = QUIC_STATUS_NOT_SUPPORTED;
            break;
    }

    return Status;
}

//
// Key Encryption Functions
//

#ifdef DEBUG
void
QuicTlsLogSecret(
    _In_z_ const char* const Prefix,
    _In_reads_(Length)
        const uint8_t* const Secret,
    _In_ uint32_t Length
    )
{
    #define HEX_TO_CHAR(x) ((x) > 9 ? ('a' + ((x) - 10)) : '0' + (x))
    char SecretStr[256 + 1] = {0};
    QUIC_DBG_ASSERT(Length * 2 < sizeof(SecretStr));
    for (uint8_t i = 0; i < Length; i++) {
        SecretStr[i*2]     = HEX_TO_CHAR(Secret[i] >> 4);
        SecretStr[i*2 + 1] = HEX_TO_CHAR(Secret[i] & 0xf);
    }
    QuicTraceLogVerbose(
        SchannelLogSecret,
        "[ tls] %s[%u]: %s",
        Prefix,
        Length,
        SecretStr);
}
#else
#define QuicTlsLogSecret(Prefix, Secret, Length) UNREFERENCED_PARAMETER(Prefix);
#endif

_IRQL_requires_max_(PASSIVE_LEVEL)
void
QuicHkdfFormatLabel(
    _In_z_ const char* const Label,
    _In_ uint16_t HashLength,
    _Out_writes_all_(5 + QUIC_HKDF_PREFIX_LEN + strlen(Label))
        uint8_t* const Data,
    _Inout_ uint32_t* const DataLength
    )
{
    QUIC_DBG_ASSERT(strlen(Label) <= UINT8_MAX - QUIC_HKDF_PREFIX_LEN);
    uint8_t LabelLength = (uint8_t)strlen(Label);

    Data[0] = HashLength >> 8;
    Data[1] = HashLength & 0xff;
    Data[2] = QUIC_HKDF_PREFIX_LEN + LabelLength;
    memcpy(Data + 3, QUIC_HKDF_PREFIX, QUIC_HKDF_PREFIX_LEN);
    memcpy(Data + 3 + QUIC_HKDF_PREFIX_LEN, Label, LabelLength);
    Data[3 + QUIC_HKDF_PREFIX_LEN + LabelLength] = 0;
    *DataLength = 3 + QUIC_HKDF_PREFIX_LEN + LabelLength + 1;

    Data[*DataLength] = 0x1;
    *DataLength += 1;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicHkdfExpandLabel(
    _In_ QUIC_HASH* Hash,
    _In_z_ const char* const Label,
    _In_ uint16_t KeyLength,
    _In_ uint32_t OutputLength, // Writes QuicHashLength(HashType) bytes.
    _Out_writes_all_(OutputLength)
        uint8_t* const Output
    )
{
    uint8_t LabelBuffer[64];
    uint32_t LabelLength = sizeof(LabelBuffer);

    _Analysis_assume_(strlen(Label) <= 23);
    QuicHkdfFormatLabel(Label, KeyLength, LabelBuffer, &LabelLength);

    return
        QuicHashCompute(
            Hash,
            LabelBuffer,
            LabelLength,
            OutputLength,
            Output);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicTlsDeriveInitialSecrets(
    _In_reads_(QUIC_VERSION_SALT_LENGTH)
        const uint8_t* const Salt,
    _In_reads_(CIDLength)
        const uint8_t* const CID,
    _In_ uint8_t CIDLength,
    _Out_ QUIC_SECRET *ClientInitial,
    _Out_ QUIC_SECRET *ServerInitial
    )
{
    QUIC_STATUS Status;
    QUIC_HASH* InitialHash = NULL;
    QUIC_HASH* DerivedHash = NULL;
    uint8_t InitialSecret[QUIC_HASH_SHA256_SIZE];

    QuicTlsLogSecret("init cid", CID, CIDLength);

    Status =
        QuicHashCreate(
            QUIC_HASH_SHA256,
            Salt,
            QUIC_VERSION_SALT_LENGTH,
            &InitialHash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    //
    // Extract secret for client and server secret expansion.
    //
    Status =
        QuicHashCompute(
            InitialHash,
            CID,
            CIDLength,
            sizeof(InitialSecret),
            InitialSecret);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    QuicTlsLogSecret("init secret", InitialSecret, sizeof(InitialSecret));

    //
    // Create hash for client and server secret expansion.
    //
    Status =
        QuicHashCreate(
            QUIC_HASH_SHA256,
            InitialSecret,
            sizeof(InitialSecret),
            &DerivedHash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    //
    // Expand client secret.
    //
    ClientInitial->Hash = QUIC_HASH_SHA256;
    ClientInitial->Aead = QUIC_AEAD_AES_128_GCM;
    Status =
        QuicHkdfExpandLabel(
            DerivedHash,
            "client in",
            sizeof(InitialSecret),
            QUIC_HASH_SHA256_SIZE,
            ClientInitial->Secret);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    //
    // Expand server secret.
    //
    ServerInitial->Hash = QUIC_HASH_SHA256;
    ServerInitial->Aead = QUIC_AEAD_AES_128_GCM;
    Status =
        QuicHkdfExpandLabel(
            DerivedHash,
            "server in",
            sizeof(InitialSecret),
            QUIC_HASH_SHA256_SIZE,
            ServerInitial->Secret);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

Error:

    QuicHashFree(InitialHash);
    QuicHashFree(DerivedHash);

    RtlSecureZeroMemory(InitialSecret, sizeof(InitialSecret));

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicPacketKeyDerive(
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _In_ const QUIC_SECRET* const Secret,
    _In_z_ const char* const SecretName,
    _In_ BOOLEAN CreateHpKey,
    _Out_ QUIC_PACKET_KEY **NewKey
    )
{
    const uint16_t SecretLength = QuicHashLength(Secret->Hash);
    const uint16_t KeyLength = QuicKeyLength(Secret->Aead);

    QUIC_DBG_ASSERT(SecretLength >= KeyLength);
    QUIC_DBG_ASSERT(SecretLength >= QUIC_IV_LENGTH);
    QUIC_DBG_ASSERT(SecretLength <= QUIC_HASH_MAX_SIZE);

    QuicTlsLogSecret(SecretName, Secret->Secret, SecretLength);

    const uint16_t PacketKeyLength =
        sizeof(QUIC_PACKET_KEY) +
        (KeyType == QUIC_PACKET_KEY_1_RTT ? sizeof(QUIC_SECRET) : 0);
    QUIC_PACKET_KEY *Key = QUIC_ALLOC_NONPAGED(PacketKeyLength);
    if (Key == NULL) {
        QuicTraceEvent(
            AllocFailure,
            "Allocation of '%s' failed. (%llu bytes)",
            "QUIC_PACKET_KEY",
            PacketKeyLength);
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    QuicZeroMemory(Key, sizeof(QUIC_PACKET_KEY));
    Key->Type = KeyType;

    QUIC_HASH* Hash = NULL;
    uint8_t Temp[QUIC_HASH_MAX_SIZE];

    QUIC_STATUS Status =
        QuicHashCreate(
            Secret->Hash,
            Secret->Secret,
            SecretLength,
            &Hash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status =
        QuicHkdfExpandLabel(
            Hash,
            "quic iv",
            QUIC_IV_LENGTH,
            SecretLength,
            Temp);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    memcpy(Key->Iv, Temp, QUIC_IV_LENGTH);
    QuicTlsLogSecret("static iv", Key->Iv, QUIC_IV_LENGTH);

    Status =
        QuicHkdfExpandLabel(
            Hash,
            "quic key",
            KeyLength,
            SecretLength,
            Temp);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    QuicTlsLogSecret("key", Temp, KeyLength);

    Status =
        QuicKeyCreate(
            Secret->Aead,
            Temp,
            &Key->PacketKey);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    if (CreateHpKey) {
        Status =
            QuicHkdfExpandLabel(
                Hash,
                "quic hp",
                KeyLength,
                SecretLength,
                Temp);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }

        QuicTlsLogSecret("hp", Temp, KeyLength);

        Status =
            QuicHpKeyCreate(
                Secret->Aead,
                Temp,
                &Key->HeaderKey);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    if (KeyType == QUIC_PACKET_KEY_1_RTT) {
        QuicCopyMemory(Key->TrafficSecret, Secret, sizeof(QUIC_SECRET));
    }

    *NewKey = Key;
    Key = NULL;

Error:

    QuicPacketKeyFree(Key);
    QuicHashFree(Hash);

    RtlSecureZeroMemory(Temp, sizeof(Temp));

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_When_(NewReadKey != NULL, _At_(*NewReadKey, __drv_allocatesMem(Mem)))
_When_(NewWriteKey != NULL, _At_(*NewWriteKey, __drv_allocatesMem(Mem)))
QUIC_STATUS
QuicPacketKeyCreateInitial(
    _In_ BOOLEAN IsServer,
    _In_reads_(QUIC_VERSION_SALT_LENGTH)
        const uint8_t* const Salt,  // Version Specific
    _In_ uint8_t CIDLength,
    _In_reads_(CIDLength)
        const uint8_t* const CID,
    _Out_opt_ QUIC_PACKET_KEY** NewReadKey,
    _Out_opt_ QUIC_PACKET_KEY** NewWriteKey
    )
{
    QUIC_STATUS Status;
    QUIC_SECRET ClientInitial, ServerInitial;
    QUIC_PACKET_KEY* ReadKey = NULL, *WriteKey = NULL;

    Status =
        QuicTlsDeriveInitialSecrets(
            Salt,
            CID,
            CIDLength,
            &ClientInitial,
            &ServerInitial);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    if (NewWriteKey != NULL) {
        Status =
            QuicPacketKeyDerive(
                QUIC_PACKET_KEY_INITIAL,
                IsServer ? &ServerInitial : &ClientInitial,
                IsServer ? "srv secret" : "cli secret",
                TRUE,
                &WriteKey);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    if (NewReadKey != NULL) {
        Status =
            QuicPacketKeyDerive(
                QUIC_PACKET_KEY_INITIAL,
                IsServer ? &ClientInitial : &ServerInitial,
                IsServer ? "cli secret" : "srv secret",
                TRUE,
                &ReadKey);
        if (QUIC_FAILED(Status)) {
            goto Error;
        }
    }

    if (NewWriteKey != NULL) {
        *NewWriteKey = WriteKey;
        WriteKey = NULL;
    }

    if (NewReadKey != NULL) {
        *NewReadKey = ReadKey;
        ReadKey = NULL;
    }

Error:

    QuicPacketKeyFree(ReadKey);
    QuicPacketKeyFree(WriteKey);

    RtlSecureZeroMemory(ClientInitial.Secret, sizeof(ClientInitial.Secret));
    RtlSecureZeroMemory(ServerInitial.Secret, sizeof(ServerInitial.Secret));

    return Status;
}

_Success_(return != FALSE)
BOOLEAN
QuicParseTrafficSecrets(
    _In_ const QUIC_TLS* TlsContext,
    _In_ const SEC_TRAFFIC_SECRETS* TrafficSecrets,
    _Out_ QUIC_SECRET* Secret
    )
{
    UNREFERENCED_PARAMETER(TlsContext);

    if (wcscmp(TrafficSecrets->SymmetricAlgId, BCRYPT_AES_ALGORITHM) != 0) {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Unsupported symmetric algorithm");
        return FALSE;
    }

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
        Secret->Aead = QUIC_AEAD_AES_128_GCM;
        break;
    case 32:
        Secret->Aead = QUIC_AEAD_AES_256_GCM;
        break;
    default:
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Unsupported key size");
        return FALSE;
    }

    if (wcscmp(TrafficSecrets->HashAlgId, BCRYPT_SHA256_ALGORITHM) == 0) {
        Secret->Hash = QUIC_HASH_SHA256;
    } else if (wcscmp(TrafficSecrets->HashAlgId, BCRYPT_SHA384_ALGORITHM) == 0) {
        Secret->Hash = QUIC_HASH_SHA384;
    } else if (wcscmp(TrafficSecrets->HashAlgId, BCRYPT_SHA512_ALGORITHM) == 0) {
        Secret->Hash = QUIC_HASH_SHA512;
    } else {
        QuicTraceEvent(
            TlsError,
            "[ tls][%p] ERROR, %s.",
            TlsContext->Connection,
            "Unsupported hash algorithm");
        return FALSE;
    }

    QUIC_DBG_ASSERT(TrafficSecrets->TrafficSecretSize <= sizeof(Secret->Secret));
    QUIC_DBG_ASSERT(TrafficSecrets->IvSize == QUIC_IV_LENGTH);

    memcpy(Secret->Secret, TrafficSecrets->TrafficSecret, TrafficSecrets->TrafficSecretSize);

    return TRUE;
}

_Success_(return==TRUE)
BOOLEAN
QuicPacketKeyCreate(
    _Inout_ QUIC_TLS* TlsContext,
    _In_ QUIC_PACKET_KEY_TYPE KeyType,
    _In_z_ const char* const SecretName,
    _In_ const SEC_TRAFFIC_SECRETS* TrafficSecrets,
    _Out_ QUIC_PACKET_KEY** Key
    )
{
    NTSTATUS Status;
    QUIC_SECRET Secret;

    if (!QuicParseTrafficSecrets(TlsContext, TrafficSecrets, &Secret)) {
        Status = QUIC_STATUS_INVALID_PARAMETER;
        goto Error;
    }

    Status =
        QuicPacketKeyDerive(
            KeyType,
            &Secret,
            SecretName,
            TRUE,
            Key);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            TlsErrorStatus,
            "[ tls][%p] ERROR, %u, %s.",
            TlsContext->Connection,
            Status,
            "QuicPacketKeyDerive");
        goto Error;
    }

Error:

    return NT_SUCCESS(Status);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicPacketKeyFree(
    _In_opt_ __drv_freesMem(Mem) QUIC_PACKET_KEY* Key
    )
{
    if (Key != NULL) {
        QuicKeyFree(Key->PacketKey);
        QuicHpKeyFree(Key->HeaderKey);
        if (Key->Type >= QUIC_PACKET_KEY_1_RTT) {
            RtlSecureZeroMemory(Key->TrafficSecret, sizeof(QUIC_SECRET));
        }
        QUIC_FREE(Key);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_At_(*NewKey, __drv_allocatesMem(Mem))
QUIC_STATUS
QuicPacketKeyUpdate(
    _In_ QUIC_PACKET_KEY* OldKey,
    _Out_ QUIC_PACKET_KEY** NewKey
    )
{
    if (OldKey->Type != QUIC_PACKET_KEY_1_RTT) {
        return QUIC_STATUS_INVALID_STATE;
    }

    QUIC_HASH* Hash = NULL;
    QUIC_SECRET NewTrafficSecret;
    const uint16_t SecretLength = QuicHashLength(OldKey->TrafficSecret->Hash);

    QUIC_STATUS Status =
        QuicHashCreate(
            OldKey->TrafficSecret->Hash,
            OldKey->TrafficSecret->Secret,
            SecretLength,
            &Hash);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    Status =
        QuicHkdfExpandLabel(
            Hash,
            "quic ku",
            SecretLength,
            SecretLength,
            NewTrafficSecret.Secret);
    if (QUIC_FAILED(Status)) {
        goto Error;
    }

    NewTrafficSecret.Hash = OldKey->TrafficSecret->Hash;
    NewTrafficSecret.Aead = OldKey->TrafficSecret->Aead;

    Status =
        QuicPacketKeyDerive(
            QUIC_PACKET_KEY_1_RTT,
            &NewTrafficSecret,
            "update traffic secret",
            FALSE,
            NewKey);

    RtlSecureZeroMemory(&NewTrafficSecret, sizeof(QUIC_SECRET));
    RtlSecureZeroMemory(OldKey->TrafficSecret, sizeof(QUIC_SECRET));

Error:

    QuicHashFree(Hash);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicKeyCreate(
    _In_ QUIC_AEAD_TYPE AeadType,
    _When_(AeadType == QUIC_AEAD_AES_128_GCM, _In_reads_(16))
    _When_(AeadType == QUIC_AEAD_AES_256_GCM, _In_reads_(32))
    _When_(AeadType == QUIC_AEAD_CHACHA20_POLY1305, _In_reads_(32))
        const uint8_t* const RawKey,
    _Out_ QUIC_KEY** NewKey
    )
{
    uint8_t KeyLength;
    BCRYPT_ALG_HANDLE KeyAlgHandle;

    switch (AeadType) {
    case QUIC_AEAD_AES_128_GCM:
        KeyLength = 16;
        KeyAlgHandle = QUIC_AES_GCM_ALG_HANDLE;
        break;
    case QUIC_AEAD_AES_256_GCM:
        KeyLength = 32;
        KeyAlgHandle = QUIC_AES_GCM_ALG_HANDLE;
        break;
    case QUIC_AEAD_CHACHA20_POLY1305:
    default:
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    NTSTATUS Status =
        BCryptGenerateSymmetricKey(
            KeyAlgHandle,
            (BCRYPT_KEY_HANDLE*)NewKey,
            NULL, // Let BCrypt manage the memory for this key.
            0,
            (uint8_t*)RawKey,
            KeyLength,
            0);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "BCryptGenerateSymmetricKey");
        goto Error;
    }

Error:

    return NtStatusToQuicStatus(Status);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicKeyFree(
    _In_opt_ QUIC_KEY* Key
    )
{
    if (Key) {
        BCryptDestroyKey((BCRYPT_KEY_HANDLE)Key);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicEncrypt(
    _In_ QUIC_KEY* _Key,
    _In_reads_bytes_(QUIC_IV_LENGTH)
        const uint8_t* const Iv,
    _In_ uint16_t AuthDataLength,
    _In_reads_bytes_opt_(AuthDataLength)
        const uint8_t* const AuthData,
    _In_ uint16_t BufferLength,
    _When_(BufferLength > QUIC_ENCRYPTION_OVERHEAD, _Inout_updates_bytes_(BufferLength))
    _When_(BufferLength <= QUIC_ENCRYPTION_OVERHEAD, _Out_writes_bytes_(BufferLength))
        uint8_t* Buffer
    )
{
    NTSTATUS Status;
    ULONG CipherTextSize;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO Info;
    BCRYPT_KEY_HANDLE Key = (BCRYPT_KEY_HANDLE)_Key;

    QUIC_DBG_ASSERT(QUIC_ENCRYPTION_OVERHEAD <= BufferLength);

#ifdef QUIC_FUZZER
    if (MsQuicFuzzerContext.EncryptCallback) {
#pragma prefast(suppress: __WARNING_26000, "Auth Data and Buffer are always contiguous")
        MsQuicFuzzerContext.EncryptCallback(
            MsQuicFuzzerContext.CallbackContext,
            (uint8_t*)AuthData,
            AuthDataLength + BufferLength
        );
    }
#endif

    BCRYPT_INIT_AUTH_MODE_INFO(Info);
    Info.pbAuthData = (uint8_t*)AuthData;
    Info.cbAuthData = AuthDataLength;
    Info.pbTag = Buffer + (BufferLength - QUIC_ENCRYPTION_OVERHEAD);
    Info.cbTag = QUIC_ENCRYPTION_OVERHEAD;
    Info.pbNonce = (uint8_t*)Iv;
    Info.cbNonce = QUIC_IV_LENGTH;

    Status =
        BCryptEncrypt(
            Key,
            Buffer,
            BufferLength - QUIC_ENCRYPTION_OVERHEAD,
            &Info,
            (uint8_t*)Iv,
            QUIC_IV_LENGTH,
            Buffer,
            BufferLength,
            &CipherTextSize,
            0);

    QUIC_DBG_ASSERT(CipherTextSize == (ULONG)(BufferLength - QUIC_ENCRYPTION_OVERHEAD));

    return NtStatusToQuicStatus(Status);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicDecrypt(
    _In_ QUIC_KEY* _Key,
    _In_reads_bytes_(QUIC_IV_LENGTH)
        const uint8_t* const Iv,
    _In_ uint16_t AuthDataLength,
    _In_reads_bytes_opt_(AuthDataLength)
        const uint8_t* const AuthData,
    _In_ uint16_t BufferLength,
    _Inout_updates_bytes_(BufferLength)
        uint8_t* Buffer
    )
{
    NTSTATUS Status;
    ULONG PlainTextSize;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO Info;
    BCRYPT_KEY_HANDLE Key = (BCRYPT_KEY_HANDLE)_Key;

    QUIC_DBG_ASSERT(QUIC_ENCRYPTION_OVERHEAD <= BufferLength);

    BCRYPT_INIT_AUTH_MODE_INFO(Info);
    Info.pbAuthData = (uint8_t*)AuthData;
    Info.cbAuthData = AuthDataLength;
    Info.pbTag = Buffer + (BufferLength - QUIC_ENCRYPTION_OVERHEAD);
    Info.cbTag = QUIC_ENCRYPTION_OVERHEAD;
    Info.pbNonce = (uint8_t*)Iv;
    Info.cbNonce = QUIC_IV_LENGTH;

    Status =
        BCryptDecrypt(
            Key,
            Buffer,
            BufferLength - QUIC_ENCRYPTION_OVERHEAD,
            &Info,
            (uint8_t*)Iv,
            QUIC_IV_LENGTH,
            Buffer,
            BufferLength - QUIC_ENCRYPTION_OVERHEAD,
            &PlainTextSize,
            0);

    QUIC_DBG_ASSERT(PlainTextSize == (ULONG)(BufferLength - QUIC_ENCRYPTION_OVERHEAD));

    return NtStatusToQuicStatus(Status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicHpKeyCreate(
    _In_ QUIC_AEAD_TYPE AeadType,
    _When_(AeadType == QUIC_AEAD_AES_128_GCM, _In_reads_(16))
    _When_(AeadType == QUIC_AEAD_AES_256_GCM, _In_reads_(32))
    _When_(AeadType == QUIC_AEAD_CHACHA20_POLY1305, _In_reads_(32))
        const uint8_t* const RawKey,
    _Out_ QUIC_HP_KEY** NewKey
    )
{
    uint8_t KeyLength;

    switch (AeadType) {
    case QUIC_AEAD_AES_128_GCM:
        KeyLength = 16;
        break;
    case QUIC_AEAD_AES_256_GCM:
        KeyLength = 32;
        break;
    case QUIC_AEAD_CHACHA20_POLY1305:
    default:
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    NTSTATUS Status =
        BCryptGenerateSymmetricKey(
            QUIC_AES_ECB_ALG_HANDLE,
            (BCRYPT_KEY_HANDLE*)NewKey,
            NULL, // Let BCrypt manage the memory for this key.
            0,
            (uint8_t*)RawKey,
            KeyLength,
            0);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "BCryptGenerateSymmetricKey (ECB)");
        goto Error;
    }

Error:

    return NtStatusToQuicStatus(Status);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicHpKeyFree(
    _In_opt_ QUIC_HP_KEY* Key
    )
{
    if (Key) {
        BCryptDestroyKey((BCRYPT_KEY_HANDLE)Key);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicHpComputeMask(
    _In_ QUIC_HP_KEY* Key,
    _In_ uint8_t BatchSize,
    _In_reads_bytes_(QUIC_HP_SAMPLE_LENGTH * BatchSize)
        const uint8_t* const Cipher,
    _Out_writes_bytes_(QUIC_HP_SAMPLE_LENGTH * BatchSize)
        uint8_t* Mask
    )
{
    ULONG TempSize = 0;
    QUIC_STATUS Status =
        NtStatusToQuicStatus(
        BCryptEncrypt(
            (BCRYPT_KEY_HANDLE)Key,
            (uint8_t*)Cipher,
            QUIC_HP_SAMPLE_LENGTH * BatchSize,
            NULL,
            NULL,
            0,
            Mask,
            QUIC_HP_SAMPLE_LENGTH * BatchSize,
            &TempSize,
            0));
    QuicTlsLogSecret("Cipher", Cipher, QUIC_HP_SAMPLE_LENGTH * BatchSize);
    QuicTlsLogSecret("HpMask", Mask, QUIC_HP_SAMPLE_LENGTH * BatchSize);
    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_STATUS
QuicHashCreate(
    _In_ QUIC_HASH_TYPE HashType,
    _In_reads_(SaltLength)
        const uint8_t* const Salt,
    _In_ uint32_t SaltLength,
    _Out_ QUIC_HASH** Hash
    )
{
    BCRYPT_ALG_HANDLE HashAlgHandle;

    switch (HashType) {
    case QUIC_HASH_SHA256:
        HashAlgHandle = QUIC_HMAC_SHA256_ALG_HANDLE;
        break;
    case QUIC_HASH_SHA384:
        HashAlgHandle = QUIC_HMAC_SHA384_ALG_HANDLE;
        break;
    case QUIC_HASH_SHA512:
        HashAlgHandle = QUIC_HMAC_SHA512_ALG_HANDLE;
        break;
    default:
        return QUIC_STATUS_NOT_SUPPORTED;
    }

    NTSTATUS Status =
        BCryptCreateHash(
            HashAlgHandle,
            (BCRYPT_HASH_HANDLE*)Hash,
            NULL, // Let BCrypt manage the memory for this hash object.
            0,
            (uint8_t*)Salt,
            (ULONG)SaltLength,
            BCRYPT_HASH_REUSABLE_FLAG);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "BCryptCreateHash");
        goto Error;
    }

Error:

    return NtStatusToQuicStatus(Status);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void
QuicHashFree(
    _In_opt_ QUIC_HASH* Hash
    )
{
    if (Hash) {
        BCryptDestroyHash((BCRYPT_HASH_HANDLE)Hash);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
QUIC_STATUS
QuicHashCompute(
    _In_ QUIC_HASH* Hash,
    _In_reads_(InputLength)
        const uint8_t* const Input,
    _In_ uint32_t InputLength,
    _In_ uint32_t OutputLength,
    _Out_writes_all_(OutputLength)
        uint8_t* const Output
    )
{
    BCRYPT_HASH_HANDLE HashHandle = (BCRYPT_HASH_HANDLE)Hash;

    NTSTATUS Status =
        BCryptHashData(
            HashHandle,
            (uint8_t*)Input,
            InputLength,
            0);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "BCryptHashData");
        goto Error;
    }

    Status =
        BCryptFinishHash(
            HashHandle,
            Output,
            OutputLength,
            0);
    if (!NT_SUCCESS(Status)) {
        QuicTraceEvent(
            LibraryErrorStatus,
            "[ lib] ERROR, %u, %s.",
            Status,
            "BCryptFinishHash");
        goto Error;
    }

Error:

    return NtStatusToQuicStatus(Status);
}
